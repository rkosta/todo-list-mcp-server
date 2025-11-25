import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ListPromptsRequestSchema,
    ListResourcesRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { neon } from '@neondatabase/serverless';
import jwt, { Algorithm } from 'jsonwebtoken';
// @ts-ignore
import JwksClient from 'jwks-client';
import { createKindeServerClient, GrantType, SessionManager } from '@kinde-oss/kinde-typescript-sdk';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { JwksKey, KindeJwtPayload, BillingStatus, ValidationResult, SessionData, SessionValue } from './types/index.js';
import { config } from './config.js';
import {
    validateToolArgs,
    SaveTokenArgsSchema,
    GetTodoArgsSchema,
    DeleteTodoArgsSchema,
    CreateTodoArgsSchema,
    UpdateTodoArgsSchema,
    GetSubscriptionStatusArgsSchema,
    UpgradeSubscriptionArgsSchema
} from './validation/index.js';

// Token storage functions
const TOKEN_FILE = join(process.cwd(), config.TOKEN_FILE_PATH);

function saveToken(token: string) {
    writeFileSync(TOKEN_FILE, token, { mode: 0o600 });
}

function getStoredToken(): string | null {
    if (existsSync(TOKEN_FILE)) {
        return readFileSync(TOKEN_FILE, 'utf8').trim();
    }
    return null;
}

// Initialize Neon PostgreSQL
const sql = neon(config.DATABASE_URL);

// Initialize JWKS client for Kinde token verification
const client = JwksClient({
    jwksUri: config.KINDE_JWKS_URI,
    cache: true,
    cacheMaxAge: config.JWKS_CACHE_MAX_AGE,
});

// Create Kinde client for authentication
const kindeClient = createKindeServerClient(GrantType.AUTHORIZATION_CODE, {
    authDomain: config.KINDE_ISSUER_URL,
    clientId: config.KINDE_CLIENT_ID,
    clientSecret: config.KINDE_CLIENT_SECRET,
    redirectURL: config.KINDE_REDIRECT_URL,
    logoutRedirectURL: config.KINDE_LOGOUT_REDIRECT_URL,
});

// Simple session manager for Kinde - use a shared session store
const sessionStore: Record<string, SessionData> = {};

const createSessionManager = (): SessionManager => ({
    getSessionItem: async (key: string) => {
        return sessionStore[key] || null;
    },
    setSessionItem: async (key: string, value: unknown) => {
        sessionStore[key] = value as SessionData;
    },
    removeSessionItem: async (key: string) => {
        delete sessionStore[key];
    },
    destroySession: async () => {
        Object.keys(sessionStore).forEach(key => delete sessionStore[key]);
    }
});

// Create MCP server
const server = new Server(
    {
        name: 'todo-mcp-server',
        version: '1.0.0',
    },
    {
        capabilities: {
            tools: {},
            prompts: {},
            resources: {},
        },
    }
);

// Helper function to verify JWT token from Kinde
async function verifyToken(token: string): Promise<{ userId: string; email: string } | null> {
    try {
        // First decode to get the key ID (kid) from the header
        const decodedUnverified = jwt.decode(token, { complete: true });

        if (!decodedUnverified || typeof decodedUnverified === 'string') {
            console.error('Invalid token format');
            return null;
        }

        // Get the signing key from JWKS endpoint using the key ID
        const kid = decodedUnverified.header.kid;
        if (!kid) {
            console.error('Token missing key ID (kid)');
            return null;
        }

        try {
            // Try to get and verify with JWKS signing key
            // jwks-client uses callbacks, so wrap it in a Promise
            const key = await new Promise<JwksKey>((resolve, reject) => {
                client.getSigningKey(kid, (err: Error | null, key: JwksKey) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(key);
                    }
                });
            });

            // The jwks-client returns an object with publicKey property
            const signingKey: string = (key.publicKey || key.getPublicKey?.() || '') as string;

            if (!signingKey) {
                throw new Error('Unable to get public key from JWKS');
            }

            // Verify the token signature and claims
            const decoded = jwt.verify(token, signingKey, {
                issuer: config.KINDE_ISSUER_URL,
                algorithms: [config.JWT_ALGORITHM as Algorithm]
            }) as jwt.JwtPayload;

            if (!decoded.sub) {
                console.error('Token missing subject (sub)');
                return null;
            }

            // Token signature verified successfully
            return {
                userId: decoded.sub,
                email: (decoded.email as string) || 'user@example.com',
            };
        } catch (verifyError) {
            // If JWKS verification fails, fall back to decode-only with validation
            console.warn('JWKS verification failed, falling back to decode-only:', verifyError);

            const decoded = decodedUnverified.payload as jwt.JwtPayload;

            // Validate issuer
            if (decoded.iss !== config.KINDE_ISSUER_URL) {
                console.error('Token issuer mismatch');
                return null;
            }

            // Validate expiration
            if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
                console.error('Token expired');
                return null;
            }

            if (!decoded.sub) {
                console.error('Token missing subject (sub)');
                return null;
            }

            console.error('WARNING: Using unverified token - signature not checked!');
            return {
                userId: decoded.sub,
                email: (decoded.email as string) || 'user@example.com',
            };
        }
    } catch (error) {
        console.error('Token verification failed:', error);
        return null;
    }
}

// Helper function to get Kinde billing status
async function getKindeBillingStatus(userId: string, accessToken: string): Promise<BillingStatus> {
    try {
        // Decode JWT token to get user information
        const decoded = jwt.decode(accessToken) as KindeJwtPayload | null;

        if (!decoded || !decoded.sub) {
            return {
                plan: 'free',
                features: { maxTodos: config.FREE_TIER_TODO_LIMIT },
                canCreate: false,
                reason: 'Invalid token'
            };
        }
        // JWT Token decoded for user

        // Check local database for free tier usage only
        const subscription = await sql`
      SELECT * FROM users 
      WHERE user_id = ${userId}
    `;

        // If user doesn't exist, create them with details from JWT
        if (subscription.length === 0) {
            await sql`
        INSERT INTO users (user_id, name, email, subscription_status, plan, free_todos_used)
        VALUES (${userId}, ${decoded.given_name || decoded.name || 'User'}, ${decoded.email || 'user@example.com'}, 'free', 'free', 0)
      `;
            // New user created in database
        }

        // Check if user has used all free todos
        const freeTodosUsed = subscription.length > 0 ? subscription[0].free_todos_used : 0;

        if (freeTodosUsed < config.FREE_TIER_TODO_LIMIT) {
            return {
                plan: 'free',
                features: { maxTodos: config.FREE_TIER_TODO_LIMIT, used: freeTodosUsed },
                canCreate: true,
                reason: `Free tier - ${config.FREE_TIER_TODO_LIMIT - freeTodosUsed} todo(s) remaining`
            };
        }

        return {
            plan: 'free',
            features: { maxTodos: config.FREE_TIER_TODO_LIMIT, used: freeTodosUsed },
            canCreate: false,
            reason: `You have used all ${config.FREE_TIER_TODO_LIMIT} free todos. Please upgrade your plan at https://${config.KINDE_PORTAL_URL}/portal to create more todos.`
        };
    } catch (error) {
        console.error('Error checking Kinde billing:', error);
        return {
            plan: 'free',
            features: { maxTodos: config.FREE_TIER_TODO_LIMIT },
            canCreate: false,
            reason: 'Error checking billing status'
        };
    }
}

// Helper function to check if user can create more todos
async function canCreateTodo(userId: string, accessToken?: string): Promise<{ canCreate: boolean; reason?: string }> {
    try {
        if (accessToken) {
            const billingStatus = await getKindeBillingStatus(userId, accessToken);
            return {
                canCreate: billingStatus.canCreate,
                reason: billingStatus.reason
            };
        }

        // Fallback to local database check
        const subscription = await sql`
      SELECT * FROM users 
      WHERE user_id = ${userId}
    `;

        if (subscription.length === 0) {
            return { canCreate: true };
        }

        const userSub = subscription[0];

        if (userSub.subscription_status === 'active') {
            return { canCreate: true };
        }

        if (userSub.free_todos_used < config.FREE_TIER_TODO_LIMIT) {
            return { canCreate: true };
        }

        return {
            canCreate: false,
            reason: `You have used all ${config.FREE_TIER_TODO_LIMIT} free todos. Please upgrade to create more todos.`
        };
    } catch (error) {
        console.error('Error checking subscription:', error);
        return { canCreate: false, reason: 'Error checking subscription status' };
    }
}

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: 'login',
                description: 'Login with Kinde to get authentication token',
                inputSchema: {
                    type: 'object',
                    properties: {},
                },
            },
            {
                name: 'save_token',
                description: 'Save your Kinde authentication token for future use',
                inputSchema: {
                    type: 'object',
                    properties: {
                        token: {
                            type: 'string',
                            description: 'Your Kinde JWT token',
                        },
                    },
                    required: ['token'],
                },
            },
            {
                name: 'list_todos',
                description: 'List all todos for the authenticated user',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                    },
                },
            },
            {
                name: 'get_todo',
                description: 'Get detailed information for a specific todo by ID',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                        todoId: {
                            type: 'integer',
                            description: 'ID of the todo item to retrieve',
                        },
                    },
                    required: ['todoId'],
                },
            },
            {
                name: 'get_subscription_status',
                description: 'Get the user\'s subscription status and todo usage',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde',
                        },
                    },
                    required: ['authToken'],
                },
            },
            {
                name: 'upgrade_subscription',
                description: 'Upgrade user subscription to paid plan',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde',
                        },
                    },
                    required: ['authToken'],
                },
            },
            {
                name: 'create_todo',
                description: 'Create a new todo item with interactive prompts',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                        title: {
                            type: 'string',
                            description: 'Title of the todo item',
                        },
                        description: {
                            type: 'string',
                            description: 'Optional description of the todo item',
                        },
                        completed: {
                            type: 'boolean',
                            description: 'Completion status of the todo',
                        },
                    },
                },
            },
            {
                name: 'update_todo',
                description: 'Update an existing todo item with interactive prompts',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                        todoId: {
                            type: 'integer',
                            description: 'Optional id of the todo item',
                        },
                        title: {
                            type: 'string',
                            description: 'Optional title of the todo item',
                        },
                        description: {
                            type: 'string',
                            description: 'Optional description of the todo item',
                        },
                        completed: {
                            type: 'boolean',
                            description: 'Optional completion status of the todo',
                        },
                    },
                },
            },
            {
                name: 'delete_todo',
                description: 'Delete a todo item with interactive prompts',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                        todoId: {
                            type: 'integer',
                            description: 'Optional id of the todo item to delete',
                        },
                    },
                },
            },
            {
                name: 'logout',
                description: 'Logout and clear stored authentication token',
                inputSchema: {
                    type: 'object',
                    properties: {},
                },
            },
            {
                name: 'get_kinde_billing',
                description: 'Get Kinde billing information and subscription status',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                    },
                },
            },
            {
                name: 'refresh_billing_status',
                description: 'Force refresh billing status from Kinde (useful after plan changes)',
                inputSchema: {
                    type: 'object',
                    properties: {
                        authToken: {
                            type: 'string',
                            description: 'Authentication token from Kinde (optional if saved)',
                        },
                    },
                },
            },
            {
                name: 'logout',
                description: 'Logout and clear stored authentication token',
                inputSchema: {
                    type: 'object',
                    properties: {},
                },
            },
        ],
    };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        switch (name) {
            case 'login': {
                return {
                    content: [{
                        type: 'text',
                        text: JSON.stringify({
                            success: true,
                            message: 'Please visit the authentication server to login',
                            url: config.AUTH_SERVER_URL,
                            steps: [
                                'Click "Login with Kinde" on the page',
                                'Complete the login process',
                                'Copy your JWT token from the success page',
                                'Use "save_token" command with your token'
                            ]
                        }, null, 2)
                    }],
                };
            }

            case 'save_token': {
                try {
                    const validatedArgs = validateToolArgs(SaveTokenArgsSchema, args);
                    saveToken(validatedArgs.token);

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                message: 'Token saved successfully! You can now use commands like "list todos" and "create todo" without providing the token each time.'
                            }, null, 2)
                        }],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'list_todos': {
                try {
                    // Try to get token from args or stored token
                    let token = args?.authToken as string;
                    if (!token) {
                        token = getStoredToken() || '';
                    }

                    if (!token) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'No authentication token found',
                                    steps: [
                                        'Type "login" to get the authentication URL',
                                        `Complete login at ${config.AUTH_SERVER_URL}`,
                                        'Copy your token and use "save_token" to store it',
                                        'Then try "list todos" again'
                                    ]
                                }, null, 2)
                            }],
                        };
                    }

                    const user = await verifyToken(token);
                    if (!user) {
                        return {
                            content: [{
                                type: 'text', text: JSON.stringify({
                                    success: false,
                                    error: 'Invalid authentication token',
                                    message: 'Please login again to get a fresh token'
                                }, null, 2)
                            }],
                        };
                    }

                    const todos = await sql`
              SELECT * FROM todos
              WHERE user_id = ${user.userId}
              ORDER BY created_at DESC
            `;

                    return {
                        content: [{ type: 'text', text: JSON.stringify({ success: true, todos }, null, 2) }],
                    };
                } catch (error) {
                    console.error('Error in list_todos:', error);
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: 'Failed to list todos',
                                details: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'get_todo': {
                try {
                    // Validate arguments with Zod
                    const validatedArgs = validateToolArgs(GetTodoArgsSchema, args);

                    // Try to get token from args or stored token
                    let token = validatedArgs.authToken;
                    if (!token) {
                        token = getStoredToken() || '';
                    }

                    if (!token) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'No authentication token found',
                                    steps: [
                                        'Type "login" to get the authentication URL',
                                        `Complete login at ${config.AUTH_SERVER_URL}`,
                                        'Copy your token and use "save_token" to store it',
                                        'Then try "get todo" again'
                                    ]
                                }, null, 2)
                            }],
                        };
                    }

                    const user = await verifyToken(token);
                    if (!user) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'Invalid authentication token'
                                }, null, 2)
                            }],
                        };
                    }

                    // Query todo with ownership validation
                    const todo = await sql`
                        SELECT * FROM todos
                        WHERE id = ${validatedArgs.todoId} AND user_id = ${user.userId}
                    `;

                    if (todo.length === 0) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'Todo not found or access denied',
                                    message: 'The todo does not exist or you do not have permission to view it'
                                }, null, 2)
                            }]
                        };
                    }

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                todo: todo[0]
                            }, null, 2)
                        }]
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'get_subscription_status': {
                try {
                    const validatedArgs = validateToolArgs(GetSubscriptionStatusArgsSchema, args);

                    const user = await verifyToken(validatedArgs.authToken);
                    if (!user) {
                        return {
                            content: [{
                                type: 'text', text: JSON.stringify({
                                    success: false,
                                    error: 'Invalid authentication token'
                                }, null, 2)
                            }],
                        };
                    }

                    const subscription = await sql`
                        SELECT * FROM users
                        WHERE user_id = ${user.userId}
                    `;

                    // If no subscription exists, create one
                    if (subscription.length === 0) {
                        await sql`
                            INSERT INTO users (user_id, subscription_status, free_todos_used)
                            VALUES (${user.userId}, 'free', 0)
                        `;
                    }

                    const userSub = subscription[0] || { subscription_status: 'free', free_todos_used: 0 };

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                subscription: {
                                    status: userSub.subscription_status || 'free',
                                    freeTodosUsed: userSub.free_todos_used || 0,
                                    totalTodosCreated: userSub.total_todos_created || 0,
                                    freeTodosRemaining: Math.max(0, config.FREE_TIER_TODO_LIMIT - (userSub.free_todos_used || 0)),
                                }
                            }, null, 2)
                        }],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'upgrade_subscription': {
                try {
                    // TESTING ONLY - Not for production use
                    // TODO: Integrate with real payment provider (Stripe, Kinde billing, etc.)
                    const validatedArgs = validateToolArgs(UpgradeSubscriptionArgsSchema, args);

                    const user = await verifyToken(validatedArgs.authToken);
                    if (!user) {
                        return {
                            content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                        };
                    }

                    // In a real implementation, you would integrate with a payment processor
                    // For now, we'll simulate the upgrade
                    await sql`
                        INSERT INTO users (user_id, subscription_status, plan)
                        VALUES (${user.userId}, 'active', 'premium')
                        ON CONFLICT (user_id)
                        DO UPDATE SET
                            subscription_status = 'active',
                            plan = 'premium'
                    `;

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                message: 'Subscription upgraded successfully! You can now create unlimited todos.',
                                subscriptionStatus: 'active'
                            }, null, 2)
                        }],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'create_todo': {
                try {
                    // Validate arguments with Zod
                    const validatedArgs = validateToolArgs(CreateTodoArgsSchema, args);

                    // Try to get token from args or stored token
                    let token = validatedArgs.authToken;
                    if (!token) {
                        token = getStoredToken() || '';
                    }

                    if (!token) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'No authentication token found',
                                    steps: [
                                        'Type "login" to get the authentication URL',
                                        `Complete login at ${config.AUTH_SERVER_URL}`,
                                        'Copy your token and use "save_token" to store it',
                                        'Then try "create todo" again'
                                    ]
                                }, null, 2)
                            }],
                        };
                    }

                    const user = await verifyToken(token);
                    if (!user) {
                        return {
                            content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                        };
                    }

                    // If title is provided, create the todo
                    if (validatedArgs.title) {
                        // Check if user can create more todos
                        const { canCreate } = await canCreateTodo(user.userId);
                        if (!canCreate) {
                            return {
                                content: [{
                                    type: 'text',
                                    text: `🚫 You have used up all your free todos.\n\n💳 Upgrade your plan to create more todos:\n🔗 https://${config.KINDE_PORTAL_URL}/portal`
                                }],
                            };
                        }

                        const todoId = await sql`
                            INSERT INTO todos (user_id, title, description, completed)
                            VALUES (
                                ${user.userId},
                                ${validatedArgs.title},
                                ${validatedArgs.description || null},
                                ${validatedArgs.completed || false}
                            )
                            RETURNING id
                        `;

                        // Update user's todo count
                        await sql`
                            INSERT INTO users (user_id, free_todos_used)
                            VALUES (${user.userId}, 1)
                            ON CONFLICT (user_id)
                            DO UPDATE SET
                                free_todos_used = users.free_todos_used + 1
                        `;

                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: true,
                                    todoId: todoId[0].id,
                                    message: 'Todo created successfully',
                                    title: validatedArgs.title,
                                    description: validatedArgs.description,
                                    completed: validatedArgs.completed || false
                                }, null, 2)
                            }],
                        };
                    }

                    // If no title provided, ask for details (interactive mode)
                    return {
                        content: [
                            {
                                type: 'text',
                                text: `📝 **Create New Todo**\n\nPlease provide the following details:\n\n1. **Title**: What is the title of your todo?\n2. **Description**: (Optional) What is the description?\n3. **Completed**: (Optional) Is it completed? (true/false)\n\nPlease respond with your answers in this format:\n\`\`\`\ntitle: Your todo title\ndescription: Your description (optional)\ncompleted: false (optional)\n\`\`\``,
                            },
                        ],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'update_todo': {
                try {
                    // Validate arguments with Zod
                    const validatedArgs = validateToolArgs(UpdateTodoArgsSchema, args);

                    // Try to get token from args or stored token
                    let token = validatedArgs.authToken;
                    if (!token) {
                        token = getStoredToken() || '';
                    }

                    if (!token) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        success: false,
                                        error: 'No authentication token found',
                                        steps: [
                                            'Type "login" to get the authentication URL',
                                            `Complete login at ${config.AUTH_SERVER_URL}`,
                                            'Copy your token and use "save_token" to store it',
                                            'Then try "update todo" again'
                                        ]
                                    }, null, 2),
                                },
                            ],
                        };
                    }

                    const user = await verifyToken(token);
                    if (!user) {
                        return {
                            content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                        };
                    }

                    if (!validatedArgs.todoId) {
                        // If no todoId provided, ask user to select one (interactive mode)
                        const todos = await sql`
                            SELECT * FROM todos
                            WHERE user_id = ${user.userId}
                            ORDER BY created_at DESC
                        `;

                        if (todos.length === 0) {
                            return {
                                content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'No todos found', message: 'Create a todo first!' }, null, 2) }],
                            };
                        }

                        let todoList = '📋 **Your Todos:**\n\n';
                        todos.forEach((todo, index) => {
                            todoList += `${index + 1}. **ID: ${todo.id}** - ${todo.title}\n`;
                            if (todo.description) todoList += `   Description: ${todo.description}\n`;
                            todoList += `   Status: ${todo.completed ? '✅ Completed' : '⏳ Pending'}\n\n`;
                        });

                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `${todoList}**Which todo would you like to update?**\n\nPlease respond with the todo ID and new details in this format:\n\`\`\`\ntodoId: 1\ntitle: New title (optional)\ndescription: New description (optional)\ncompleted: true (optional)\n\`\`\``,
                                },
                            ],
                        };
                    }

                    // Update the specified todo
                    // First verify the todo exists and belongs to the user
                    const existingTodo = await sql`
                        SELECT * FROM todos
                        WHERE id = ${validatedArgs.todoId} AND user_id = ${user.userId}
                    `;

                    if (existingTodo.length === 0) {
                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'Todo not found or access denied'
                                }, null, 2)
                            }]
                        };
                    }

                    // Build the update using conditional values
                    const updatedTodo = await sql`
                        UPDATE todos
                        SET
                            title = ${validatedArgs.title !== undefined ? validatedArgs.title : existingTodo[0].title},
                            description = ${validatedArgs.description !== undefined ? validatedArgs.description : existingTodo[0].description},
                            completed = ${validatedArgs.completed !== undefined ? validatedArgs.completed : existingTodo[0].completed}
                        WHERE id = ${validatedArgs.todoId} AND user_id = ${user.userId}
                        RETURNING *
                    `;

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                message: 'Todo updated successfully',
                                todo: updatedTodo[0]
                            }, null, 2)
                        }]
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'delete_todo': {
                try {
                    // Validate arguments with Zod
                    const validatedArgs = validateToolArgs(DeleteTodoArgsSchema, args);

                    // Try to get token from args or stored token
                    let token = validatedArgs.authToken;
                    if (!token) {
                        token = getStoredToken() || '';
                    }

                    if (!token) {
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: JSON.stringify({
                                        success: false,
                                        error: 'No authentication token found',
                                        steps: [
                                            'Type "login" to get the authentication URL',
                                            `Complete login at ${config.AUTH_SERVER_URL}`,
                                            'Copy your token and use "save_token" to store it',
                                            'Then try "delete todo" again'
                                        ]
                                    }, null, 2),
                                },
                            ],
                        };
                    }

                    const user = await verifyToken(token);
                    if (!user) {
                        return {
                            content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                        };
                    }

                    // If todoId is provided, delete the todo
                    if (validatedArgs.todoId !== undefined) {
                        // Check if todo exists and belongs to user
                        const existingTodo = await sql`
                            SELECT * FROM todos
                            WHERE id = ${validatedArgs.todoId} AND user_id = ${user.userId}
                        `;

                        if (existingTodo.length === 0) {
                            return {
                                content: [{
                                    type: 'text',
                                    text: JSON.stringify({
                                        success: false,
                                        error: 'Todo not found or access denied',
                                        message: 'The todo does not exist or you do not have permission to delete it'
                                    }, null, 2)
                                }]
                            };
                        }

                        // Delete the todo
                        await sql`
                            DELETE FROM todos
                            WHERE id = ${validatedArgs.todoId} AND user_id = ${user.userId}
                        `;

                        // Update user's todo count (decrement to free up a slot)
                        await sql`
                            UPDATE users
                            SET free_todos_used = GREATEST(free_todos_used - 1, 0)
                            WHERE user_id = ${user.userId}
                        `;

                        return {
                            content: [{
                                type: 'text',
                                text: JSON.stringify({
                                    success: true,
                                    message: 'Todo deleted successfully',
                                    deletedTodo: {
                                        id: existingTodo[0].id,
                                        title: existingTodo[0].title
                                    }
                                }, null, 2)
                            }]
                        };
                    }

                    // Get user's todos to show them (interactive mode)
                    const todos = await sql`
                        SELECT * FROM todos
                        WHERE user_id = ${user.userId}
                        ORDER BY created_at DESC
                    `;

                    if (todos.length === 0) {
                        return {
                            content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'No todos found', message: 'Create a todo first!' }, null, 2) }],
                        };
                    }

                    let todoList = '📋 **Your Todos:**\n\n';
                    todos.forEach((todo, index) => {
                        todoList += `${index + 1}. **ID: ${todo.id}** - ${todo.title}\n`;
                        if (todo.description) todoList += `   Description: ${todo.description}\n`;
                        todoList += `   Status: ${todo.completed ? '✅ Completed' : '⏳ Pending'}\n\n`;
                    });

                    return {
                        content: [
                            {
                                type: 'text',
                                text: `${todoList}**Which todo would you like to delete?**\n\nPlease respond with the todo ID:\n\`\`\`\ntodoId: 1\n\`\`\``,
                            },
                        ],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: error instanceof Error ? error.message : 'Validation failed'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'logout': {
                // Clear the stored token
                if (existsSync(TOKEN_FILE)) {
                    const fs = await import('fs');
                    fs.unlinkSync(TOKEN_FILE);
                }

                return {
                    content: [{
                        type: 'text',
                        text: JSON.stringify({
                            success: true,
                            message: 'Logged out successfully! Your authentication token has been cleared.',
                            note: 'To login again, use the "login" command.'
                        }, null, 2)
                    }],
                };
            }

            case 'get_kinde_billing': {
                // Try to get token from args or stored token
                let token = args?.authToken as string;
                if (!token) {
                    token = getStoredToken() || '';
                }

                if (!token) {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'No authentication token found',
                                    steps: [
                                        'Type "login" to get the authentication URL',
                                        `Complete login at ${config.AUTH_SERVER_URL}`,
                                        'Copy your token and use "save_token" to store it',
                                        'Then try "get kinde billing" again'
                                    ]
                                }, null, 2),
                            },
                        ],
                    };
                }

                const user = await verifyToken(token);
                if (!user) {
                    return {
                        content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                    };
                }

                try {
                    const billingStatus = await getKindeBillingStatus(user.userId, token);

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                kindeBilling: {
                                    plan: billingStatus.plan,
                                    features: billingStatus.features,
                                    canCreate: billingStatus.canCreate,
                                    reason: billingStatus.reason,
                                    upgradeUrl: `https://${config.KINDE_PORTAL_URL}/portal`,
                                    selfServicePortal: `https://${config.KINDE_PORTAL_URL}/portal`
                                }
                            }, null, 2)
                        }],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: 'Failed to fetch Kinde billing information',
                                details: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                    };
                }
            }

            case 'refresh_billing_status': {
                // Try to get token from args or stored token
                let token = args?.authToken as string;
                if (!token) {
                    token = getStoredToken() || '';
                }

                if (!token) {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: JSON.stringify({
                                    success: false,
                                    error: 'No authentication token found',
                                    steps: [
                                        'Type "login" to get the authentication URL',
                                        `Complete login at ${config.AUTH_SERVER_URL}`,
                                        'Copy your token and use "save_token" to store it',
                                        'Then try "refresh billing status" again'
                                    ]
                                }, null, 2),
                            },
                        ],
                    };
                }

                const user = await verifyToken(token);
                if (!user) {
                    return {
                        content: [{ type: 'text', text: JSON.stringify({ success: false, error: 'Invalid authentication token' }, null, 2) }],
                    };
                }

                try {
                    // Force refreshing billing status
                    const billingStatus = await getKindeBillingStatus(user.userId, token);

                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: true,
                                message: 'Billing status refreshed successfully!',
                                kindeBilling: {
                                    plan: billingStatus.plan,
                                    features: billingStatus.features,
                                    canCreate: billingStatus.canCreate,
                                    reason: billingStatus.reason,
                                    upgradeUrl: `https://${config.KINDE_PORTAL_URL}/portal`,
                                    selfServicePortal: `https://${config.KINDE_PORTAL_URL}/portal`,
                                    lastChecked: new Date().toISOString()
                                }
                            }, null, 2)
                        }],
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: 'text',
                            text: JSON.stringify({
                                success: false,
                                error: 'Failed to refresh billing information',
                                details: error instanceof Error ? error.message : 'Unknown error'
                            }, null, 2)
                        }],
                    };
                }
            }


            default:
                return {
                    content: [{ type: 'text', text: JSON.stringify({ success: false, error: `Unknown tool: ${name}` }, null, 2) }],
                };
        }
    } catch (error) {
        console.error('Error handling tool call:', error);
        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    success: false,
                    error: 'Internal server error'
                }, null, 2)
            }],
        };
    }
});

// Handle prompts list (return empty list - we don't have prompts yet)
server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return {
        prompts: []
    };
});

// Handle resources list (return empty list - we don't have resources yet)
server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: []
    };
});

// Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    console.error('Server will continue running...');
    // Don't exit - keep server alive
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    console.error('Server will continue running...');
    // Don't exit - keep server alive
});

// Start the server
async function main() {
    try {
        const transport = new StdioServerTransport();
        await server.connect(transport);
        console.error('Todo MCP server running on stdio');
    } catch (error) {
        console.error('Error starting server:', error);
        console.error('Attempting to continue...');
        // Don't exit immediately - give it a chance to recover
    }
}

main().catch((error) => {
    console.error('Fatal error in main():', error);
    console.error('Server initialization failed, but process will stay alive');
    // Remove process.exit(1) to prevent container from stopping
});