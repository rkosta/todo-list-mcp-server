# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Model Context Protocol (MCP) server that provides todo list management with Kinde authentication and Neon PostgreSQL database. The architecture uses a **two-server model**: an MCP server for tool operations and a separate Express authentication server for OAuth flows.

## Development Commands

### Local Development
```bash
npm run build              # Compile TypeScript to JavaScript
npm run dev                # Run MCP server locally with tsx
npm run auth-server        # Run authentication server on port 3000
npm run setup-db           # Initialize database schema
```

### Docker Development
```bash
npm run docker:dev                      # Start both servers in dev mode
npm run docker:dev:auth-server         # Run auth server in Docker
npm run docker:dev:auth-server:debug   # Run auth server with debugger on port 9229
npm run docker:dev:setup               # Initialize database in Docker
npm run docker:dev:setup:debug         # Initialize database with debugger
npm run docker:dev:logs                # View container logs
npm run docker:dev:down                # Stop dev containers
```

### Docker Production
```bash
npm run docker:prod                    # Start production containers
npm run docker:prod:setup              # Initialize database in production
npm run docker:prod:logs               # View production logs
npm run docker:prod:restart            # Restart production containers
npm run docker:prod:down               # Stop production containers
```

## Architecture Overview

### Two-Server Model

**1. MCP Server** ([src/server.ts](src/server.ts))
- Runs on stdio transport (standard MCP protocol)
- Provides tools for todo CRUD operations
- Handles JWT token verification via JWKS
- Stores authentication tokens in `.auth-token` file (mode 0o600)
- Does NOT handle OAuth flows directly

**2. Authentication Server** ([src/kinde-auth-server.ts](src/kinde-auth-server.ts))
- Runs on HTTP (port 3000) with Express
- Handles Kinde OAuth2 authorization code flow
- Manages user sessions with express-session
- Provides web UI for login/logout
- Automatically creates/updates user records in database
- Users copy JWT tokens from this server to use with MCP tools

### Authentication Flow

1. User calls `login` tool → receives URL to authentication server
2. User visits http://localhost:3000 and completes Kinde OAuth flow
3. Auth server stores tokens in session and displays them in web UI
4. User copies ID token and calls `save_token` tool
5. MCP server stores token in `.auth-token` file
6. Subsequent tool calls use stored token automatically

### Database Schema

**tables** table:
- Stores todo items with `user_id` (from Kinde JWT sub claim)
- Fields: `id`, `user_id`, `title`, `description`, `completed`, `created_at`, `updated_at`
- Indexed on `user_id` and `created_at`

**users** table:
- Tracks user subscription status and todo usage limits
- Fields: `id`, `user_id`, `name`, `email`, `subscription_status`, `plan`, `free_todos_used`, `created_at`, `updated_at`
- Subscription status: `free`, `active`, `cancelled`
- Free tier: 1 todo limit (for testing), paid: unlimited

### MCP Protocol Implementation

The server implements three MCP capabilities:

1. **Tools** (primary feature)
   - `login`: Returns authentication URL
   - `save_token`: Stores JWT for future use
   - `list_todos`: Lists user's todos
   - `create_todo`: Creates new todo (respects billing limits)
   - `update_todo`: Updates existing todo by ID
   - `delete_todo`: Deletes todo by ID
   - `get_subscription_status`: Shows plan and usage
   - `upgrade_subscription`: Simulates subscription upgrade
   - `get_kinde_billing`: Fetches billing from Kinde
   - `refresh_billing_status`: Force refreshes billing data
   - `logout`: Clears stored token

2. **Prompts** (empty, for future expansion)

3. **Resources** (empty, for future expansion)

### JWT Token Verification Strategy

The `verifyToken` function ([src/server.ts:89-175](src/server.ts#L89-L175)) implements a two-tier approach:

1. **Primary**: JWKS signature verification with public key from Kinde
2. **Fallback**: Decode-only with manual validation (issuer, expiration)

This ensures resilience if JWKS endpoint is temporarily unavailable while maintaining security.

## Key Patterns

### Tool Handler Pattern

All tools follow this pattern:
1. Get token from args or stored file
2. Verify token and extract user info
3. Check authorization/billing limits if needed
4. Execute database operation
5. Return JSON response with `success` boolean

### Response Format

All tool responses return JSON with consistent structure:
```typescript
{
  success: boolean,
  // On success:
  data?: any,
  message?: string,
  // On error:
  error?: string,
  details?: string
}
```

### Update Tool Pattern

The `update_todo` tool demonstrates the conditional update pattern:
- Only updates fields explicitly provided in arguments
- Preserves existing values for omitted fields
- Validates todo ownership before update
- Returns error if no fields provided

### Error Handling

- Global error handlers prevent MCP server crashes ([src/server.ts:1102-1112](src/server.ts#L1102-L1112))
- All tool handlers wrapped in try-catch ([src/server.ts:476-1084](src/server.ts#L476-L1084))
- Errors logged to stderr, never cause process exit

## Environment Configuration

Required environment variables (see [.env.example](.env.example)):
```
DATABASE_URL=postgresql://...          # Neon PostgreSQL connection string
KINDE_ISSUER_URL=https://...kinde.com  # Kinde domain
KINDE_CLIENT_ID=...                     # Kinde OAuth client ID
KINDE_CLIENT_SECRET=...                 # Kinde OAuth client secret
JWT_SECRET=...                          # Session secret (generate with crypto.randomBytes)
NODE_ENV=development|production         # Environment mode
```

## Type Definitions

All types are centralized in [src/types/index.ts](src/types/index.ts):
- `JwksKey`: JWKS client key format
- `KindeJwtPayload`: Extended JWT payload with Kinde claims
- `BillingStatus`: Subscription and usage limits
- `SessionData`: Express session data structure
- `ValidationResult`: Argument validation results

## Database Setup

Database initialization creates tables and indexes automatically:
- Run `npm run setup-db` for local development
- Run `npm run docker:dev:setup` for Docker development
- Run `npm run docker:prod:setup` for Docker production

The setup script is idempotent (uses `IF NOT EXISTS`).

## Security Features

1. **Token file permissions**: `.auth-token` created with mode 0o600 (owner-only)
2. **Session security**: httpOnly, sameSite strict, secure in production
3. **JWT verification**: JWKS signature validation with public key
4. **User isolation**: All queries filtered by `user_id` from token
5. **Restart policy**: Docker containers restart on failure (not on normal exit)

## Debugging

For debugging with Docker:
- Auth server: `npm run docker:dev:auth-server:debug` (debugger on 9229)
- Database setup: `npm run docker:dev:setup:debug` (debugger on 9229)
- Connect with Chrome DevTools or VS Code debugger to `localhost:9229`

## Important Notes

- The MCP server runs on stdio (not HTTP) - it cannot be accessed via browser
- The authentication server must be running for login flows to work
- Token persistence allows MCP tools to work after auth server is stopped
- Free tier limit is set to 1 todo for testing purposes (see `getKindeBillingStatus`)
- Duplicate `logout` tool at line 464 and 430 should be cleaned up
