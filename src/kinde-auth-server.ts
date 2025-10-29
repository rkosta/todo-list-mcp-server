import express from 'express';
import session from 'express-session';
import { createKindeServerClient, GrantType, SessionManager } from '@kinde-oss/kinde-typescript-sdk';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { neon } from '@neondatabase/serverless'



dotenv.config();

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
    throw new Error('DATABASE_URL is not defined in environment variables');
}

const sessionSecret = process.env.JWT_SECRET;
if (!sessionSecret) {
    throw new Error('JWT_SECRET is not defined in environment variables');
}

const kindeIssuerUrl = process.env.KINDE_ISSUER_URL;
if (!kindeIssuerUrl) {
    throw new Error('KINDE_ISSUER_URL is not defined in environment variables');
}

const kindeClientId = process.env.KINDE_CLIENT_ID;
if (!kindeClientId) {
    throw new Error('KINDE_CLIENT_ID is not defined in environment variables');
}

const kindeClientSecret = process.env.KINDE_CLIENT_SECRET;
if (!kindeClientSecret) {
    throw new Error('KINDE_CLIENT_SECRET is not defined in environment variables');
}

const sql = neon(databaseUrl);

declare module 'express-session' {
    interface SessionData {
        accessToken?: string;
        idToken?: string;
        userInfo?: any;
        userName?: string;
        userEmail?: string;
    }
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        httpOnly: true,
        sameSite: 'strict'
    }
}));

const createSessionManager = (req: any, res: express.Response): SessionManager => ({
    getSessionItem: async (key: string) => {
        return req.session?.[key];
    },
    setSessionItem: async (key: string, value: any) => {
        if (req.session) {
            req.session[key] = value;
        }
    },
    removeSessionItem: async (key: string) => {
        if (req.session) {
            delete req.session[key];
        }
    },
    destroySession: async () => {
        req.session = {}
    }

});

const kindleClient = createKindeServerClient(GrantType.AUTHORIZATION_CODE, {
    authDomain: kindeIssuerUrl,
    clientId: kindeClientId,
    clientSecret: kindeClientSecret,
    redirectURL: 'http://localhost:3000/callback',
    logoutRedirectURL: 'http://localhost:3000',
});

// Home page with login button
app.get('/', (req, res) => {
    const token = req.session?.accessToken;
    const userInfo = req.session?.userInfo;

    if (token) {
        // Use stored user info from session
        const userEmail = req.session?.userEmail || 'user@example.com';
        const userName = req.session?.userName || 'User';
        console.log('👤 Displaying user:', { userName, userEmail });

        res.send(`
      <html>
        <head>
          <title>Kinde Auth Test</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 600px; margin: 0 auto; }
            .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .token-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .btn { display: inline-block; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; }
            .btn-primary { background: #007bff; color: white; }
            .btn-success { background: #28a745; color: white; }
            .btn-danger { background: #dc3545; color: white; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🎉 Already Authenticated!</h1>
            <div class="success">
              <strong>Welcome back, ${userName}!</strong><br>
              Email: ${userEmail}<br>
              Session persists across page refreshes.
            </div>
            
            <h2>🔑 Your Access Token:</h2>
            <div class="token-box">
              <textarea id="accessToken" style="width: 100%; height: 100px; font-family: monospace; border: none; background: transparent;" readonly>${token}</textarea>
              <button onclick="copyAccessToken()" style="margin-top: 10px; padding: 5px 10px;">Copy Access Token</button>
            </div>
            
            <h2>🆔 Your ID Token (Use this with MCP server):</h2>
            <div class="token-box">
              <textarea id="idToken" style="width: 100%; height: 100px; font-family: monospace; border: none; background: transparent;" readonly>${req.session.idToken || 'No ID token available'}</textarea>
              <button onclick="copyIdToken()" style="margin-top: 10px; padding: 5px 10px;">Copy ID Token</button>
            </div>
            
            <h2>💳 Billing Management:</h2>
            <p><a href="https://learnflowai.kinde.com/portal" target="_blank" class="btn btn-success">🔗 Manage Billing</a></p>
            
            <p>
              <a href="/logout" class="btn btn-danger">Logout</a>
              <a href="/" class="btn btn-primary">Refresh Page</a>
            </p>
          </div>
          
          <script>
            function copyAccessToken() {
              document.getElementById('accessToken').select();
              document.execCommand('copy');
              alert('Access Token copied to clipboard!');
            }
            
            function copyIdToken() {
              document.getElementById('idToken').select();
              document.execCommand('copy');
              alert('ID Token copied to clipboard! Use this with the MCP server.');
            }
          </script>
        </body>
      </html>
    `);
    } else {
        res.send(`
      <html>
        <head>
          <title>Kinde Auth Test</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 600px; margin: 0 auto; }
            .btn { display: inline-block; padding: 10px 20px; text-decoration: none; border-radius: 5px; background: #007bff; color: white; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Kinde Authentication Test</h1>
            <p>Click the button below to login with Kinde:</p>
            <a href="/login" class="btn">Login with Kinde</a>
          </div>
        </body>
      </html>
    `);
    }
});

app.get('/login', async (req, res) => {
    try {
        const sessionManager = createSessionManager(req, res);
        const loginUrl = await kindleClient.login(sessionManager);
        res.redirect(loginUrl.toString());
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Login failed');
    }
});

app.get('/callback', async (req, res) => {
    try {
        const fullUrl = `http://${req.headers.host}${req.url}`;
        const url = new URL(fullUrl);
        const code = url.searchParams.get('code');

        if (!code) {
            return res.status(400).send('No authorization code received');
        }

        const tokenResponse = await fetch(`${kindeIssuerUrl}/oauth2/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: process.env.KINDE_CLIENT_ID!,
                client_secret: process.env.KINDE_CLIENT_SECRET!,
                code: code,
                redirect_uri: 'http://localhost:3000/callback',
            }),
        });

        const tokenData = await tokenResponse.json();
        console.log('Token response:', tokenData);

        if (tokenData.access_token) {

            // Store tokens in session for persistence
            req.session.accessToken = tokenData.access_token;
            req.session.idToken = tokenData.id_token;
            req.session.userInfo = tokenData;

            // Decode the ID token to get user info
            const idToken = tokenData.id_token;
            const user = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
            console.log('👤 User info from ID token:', user);

            // Store user info in session for easy access
            req.session.userName = user.given_name || user.name || 'User';
            req.session.userEmail = user.email || 'user@example.com';

            // Automatically create user in database
            try {
                const userId = user.sub;
                const userName = user.given_name || user.name || 'User';
                const userEmail = user.email || 'user@example.com';

                // Check if user already exists
                const existingUser = await sql`
                    SELECT * FROM users WHERE user_id = ${userId}
                `;

                if (existingUser.length === 0) {
                    // Create new user
                    await sql`
                                INSERT INTO users (user_id, name, email, subscription_status, plan, free_todos_used)
                                VALUES (${userId}, ${userName}, ${userEmail}, 'free', 'free', 0)
                            `;
                    console.log('✅ User automatically created in database:', userName, userEmail);
                } else {
                    // Update existing user info
                    await sql`
                                UPDATE users 
                                SET name = ${userName}, email = ${userEmail}
                                WHERE user_id = ${userId}
                            `;
                    console.log('✅ User info updated in database:', userName, userEmail);
                }
            } catch (error) {
                console.log('⚠️ Could not auto-create user in database:', error);
            }

            // Redirect to home page after successful authentication
            res.redirect('/');

        } else {
            console.log('No access token received');
            res.status(400).send('Authentication failed - no access token received');
        }

    }
    catch (error) {
        console.error('Callback error:', error);
        res.status(500).send(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
});

// Logout route
app.get('/logout', async (req, res) => {
  try {
    // Clear the session
    req.session.destroy((err) => {
      if (err) {
        console.log('Session destroy error:', err);
      }
      // Redirect to home page after logout
      res.redirect('/');
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).send('Logout failed');
  }
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Kinde Auth Server running on http://localhost:${PORT}`);
    console.log(`📝 Routes available:`);
    console.log(`   - http://localhost:${PORT}/ (Home)`);
    console.log(`   - http://localhost:${PORT}/login (Login)`);
    console.log(`   - http://localhost:${PORT}/callback (OAuth callback)`);
});
