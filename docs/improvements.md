# Todo List MCP Server - Code Improvements

## Overview
This document tracks all improvements identified in the comprehensive TypeScript code analysis, including implemented changes and future work.

---

## ✅ Phase 1: Critical Security & Bug Fixes (COMPLETED)

### 1.1 Session Manager Logic Bug
- **Status**: ✅ Fixed
- **Location**: `src/kinde-auth-server.ts:69`
- **Issue**: Backwards conditional logic `if (!req.session)` should be `if (req.session)`
- **Impact**: Session values were never being saved
- **Fix**: Corrected conditional logic in all SessionManager methods

### 1.2 Duplicate Logout Tool
- **Status**: ✅ Fixed
- **Location**: `src/server.ts:370-376`
- **Issue**: `kinde_logout` tool registered twice
- **Impact**: MCP protocol violation, confusing tool listing
- **Fix**: Removed duplicate registration

### 1.3 File Permissions Security
- **Status**: ✅ Fixed
- **Location**: `src/server.ts:23`
- **Issue**: Token file created with default permissions (readable by all)
- **Impact**: Security risk - tokens accessible to other users
- **Fix**: Set mode to `0o600` (owner-only read/write)

### 1.4 Session Configuration Hardening
- **Status**: ✅ Fixed
- **Location**: `src/kinde-auth-server.ts:52-62`
- **Issues**:
  - `resave: true` causes unnecessary session saves
  - `saveUninitialized: true` creates sessions for unauthenticated users
  - `secure` not conditionally set based on environment
  - `sameSite: 'lax'` allows some cross-site requests
- **Fixes**:
  - Set `resave: false`
  - Set `saveUninitialized: false`
  - Set `secure: process.env.NODE_ENV === 'production'`
  - Changed `sameSite: 'strict'`

### 1.5 JWT Token Verification
- **Status**: ✅ Fixed
- **Location**: `src/server.ts:84-164`
- **Issues**:
  - No cryptographic signature verification
  - JWKS client callback vs promise mismatch
  - Incorrect key property access
- **Fixes**:
  - Implemented proper JWKS signature verification
  - Added callback-to-promise wrapper
  - Fixed `key.publicKey` property access
  - Added fallback validation with expiration checking

### 1.6 Crash Prevention
- **Status**: ✅ Fixed
- **Location**: `src/server.ts:1049-1060`
- **Issues**:
  - No global error handlers for uncaught exceptions
  - Tool handlers not wrapped in try-catch
  - `process.exit(1)` in error handling causes immediate shutdown
- **Fixes**:
  - Added `uncaughtException` handler
  - Added `unhandledRejection` handler
  - Removed `process.exit(1)` from error handling
  - Wrapped all tool handlers in try-catch blocks

### 1.7 Docker Restart Policy
- **Status**: ✅ Fixed
- **Location**: `docker-compose.dev.yml:32`
- **Issue**: `restart: "no"` means container never restarts on failure
- **Fix**: Changed to `restart: "on-failure:3"` for automatic recovery

### 1.8 JSON Format Consistency
- **Status**: ✅ Fixed
- **Location**: All tool response handlers
- **Issues**:
  - Mixed plain text and JSON responses
  - Emojis causing JSON parsing errors in Claude Desktop
- **Fixes**:
  - Standardized all responses to JSON format
  - Removed all emojis from responses
  - All responses now return `{ success: true/false, ... }`

### 1.9 MCP Protocol Compliance
- **Status**: ✅ Fixed
- **Location**: `src/server.ts:1036-1047`
- **Issues**:
  - Missing `prompts/list` handler
  - Missing `resources/list` handler
  - Capabilities not declared
- **Fixes**:
  - Added `prompts/list` handler
  - Added `resources/list` handler
  - Declared capabilities: tools, prompts, resources

### 1.10 Docker Compose Version Warnings
- **Status**: ✅ Fixed
- **Location**: `docker-compose.yml`, `docker-compose.dev.yml`
- **Issue**: Obsolete `version: '3.8'` declaration causes warnings
- **Fix**: Removed version field from both compose files

---

## ✅ Phase 2: Type Safety & Code Quality (COMPLETED)

### 2.1 Centralized Type Definitions
- **Status**: ✅ Implemented
- **Location**: `src/types/index.ts` (NEW FILE)
- **Achievement**: Created centralized type definitions file with:
  - JWKS Client Types (`JwksKey`)
  - Kinde Authentication Types (`KindeJwtPayload`, `KindeTokenResponse`)
  - Session Types (`SessionData`, `SessionValue`)
  - Billing Types (`BillingFeatures`, `BillingStatus`)
  - Validation Types (`ValidationResult<T>`)

### 2.2 Eliminate 'any' Types
- **Status**: ✅ Completed (10/10 replaced)
- **Files Modified**:
  - `src/server.ts`: 6 'any' types replaced
  - `src/kinde-auth-server.ts`: 4 'any' types replaced
- **Specific Fixes**:
  - JWKS key type: `any` → `JwksKey`
  - JWT decode: `any` → `KindeJwtPayload | null`
  - Billing status: `any` → `BillingStatus`
  - Validation: `any` → `ValidationResult`
  - Session manager: `any` → `unknown` with proper type guards
  - Session module augmentation: Added index signature

### 2.3 Stdout Pollution
- **Status**: ✅ Fixed
- **Location**: `src/server.ts` (Lines 137, 191, 205, 998)
- **Issue**: `console.log()` pollutes stdout causing JSON parsing errors
- **Fix**: Removed all `console.log()` calls, kept only `console.error()` for actual errors

---

## ✅ Phase 3: Environment & Configuration (COMPLETED)

### 3.1 Environment Variable Validation
- **Status**: ✅ Fixed
- **Location**: `src/config.ts` (NEW FILE)
- **Issues**:
  - No startup validation for required env vars
  - Processes can start with invalid configuration
  - Runtime failures instead of startup failures
- **Implementation**:
  - Created `src/config.ts` with Zod schema validation
  - Validates all required variables at module import (fail fast)
  - Clear, actionable error messages with field-level details
  - Type-safe configuration exports with TypeScript inference
  - All 3 entry points now import from centralized config module

### 3.2 Hardcoded Values
- **Status**: ✅ Fixed
- **Location**: Multiple files migrated
- **Issues Resolved**:
  - Port 3000 → `config.PORT` (default: 3000, configurable)
  - localhost:3000 URLs → `config.AUTH_SERVER_URL` (9+ instances replaced)
  - Portal URLs → `config.KINDE_PORTAL_URL` (4+ instances replaced)
  - Token filename → `config.TOKEN_FILE_PATH` (default: '.auth-token')
  - JWKS cache → `config.JWKS_CACHE_MAX_AGE` (default: 600000ms)
  - Free tier limit → `config.FREE_TIER_TODO_LIMIT` (unified to 5, was inconsistent 1/5)
  - Session expiration → `config.SESSION_MAX_AGE` (default: 7 days)
  - JWT algorithm → `config.JWT_ALGORITHM` (default: 'RS256')
- **Files Modified**:
  - `src/server.ts`: 54+ changes, removed all `process.env` references
  - `src/kinde-auth-server.ts`: Removed manual validation, uses config
  - `src/setup-db.ts`: Simplified to 4 lines, uses config
  - `.env.example`: Added 8 optional variables with documentation
  - `CLAUDE.md`: Added comprehensive configuration documentation section

### 3.3 Configuration Module Features
- **Zod Validation**: Runtime schema validation with detailed error messages
- **Type Safety**: TypeScript types automatically inferred from Zod schema
- **Computed Values**: Automatic derivation of redirect URLs, JWKS URIs, portal URLs
- **Single Source of Truth**: All configuration accessed via `import { config } from './config.js'`
- **Fail Fast**: Process exits immediately on invalid configuration with clear guidance
- **Backward Compatible**: All existing environment variables work unchanged
- **Flexible Defaults**: 8 optional variables with sensible defaults for development

### 3.4 Environment Variables
**Required (5):**
- `DATABASE_URL`: PostgreSQL connection string (with URL validation)
- `KINDE_ISSUER_URL`: Kinde OAuth domain (with URL validation)
- `KINDE_CLIENT_ID`: OAuth client ID
- `KINDE_CLIENT_SECRET`: OAuth client secret
- `JWT_SECRET`: Session encryption secret

**Optional (8 with defaults):**
- `PORT`: Auth server port (default: 3000)
- `NODE_ENV`: Environment mode (default: 'development')
- `AUTH_SERVER_URL`: Auth server base URL (default: computed from PORT)
- `TOKEN_FILE_PATH`: Token storage path (default: '.auth-token')
- `JWKS_CACHE_MAX_AGE`: JWKS cache duration (default: 600000ms)
- `FREE_TIER_TODO_LIMIT`: Free tier limit (default: 5)
- `SESSION_MAX_AGE`: Session expiration (default: 604800000ms)
- `JWT_ALGORITHM`: JWT signing algorithm (default: 'RS256')

---

## 🔄 Phase 4: Error Handling & Validation (IN PROGRESS)

### 4.1 Database Error Handling
- **Status**: ⏳ Pending
- **Location**: All database operations
- **Issues**:
  - Generic "Failed to..." messages
  - No distinction between:
    - Connection errors
    - Constraint violations
    - Transaction failures
    - Query syntax errors
- **Proposed Solution**:
  - Create error type hierarchy
  - Map PostgreSQL error codes to meaningful messages
  - Add retry logic for transient failures
  - Distinguish between user errors and system errors

### 4.2 Input Validation
- **Status**: ✅ Completed
- **Location**: `src/validation/` (NEW MODULE), All tool handlers
- **Issues Resolved**:
  - ✅ Replaced basic validateArgs with comprehensive Zod validation
  - ✅ Added title validation: 1-255 chars, trimmed, required
  - ✅ Added description validation: max 2000 chars, optional
  - ✅ Added TodoId validation: positive integers only
  - ✅ Added JWT token format validation (3 dot-separated parts)
  - ✅ Added boolean type validation for completed field
  - ✅ Automatic whitespace trimming on all string inputs
- **Implementation**:
  - Created `src/validation/schemas.ts` with Zod schemas for all tool arguments
  - Created `src/validation/index.ts` with validation utilities
  - Updated all 9 tool handlers to use Zod validation:
    - `save_token`, `get_todo`, `delete_todo` (simple tools)
    - `create_todo`, `update_todo`, `get_subscription_status`, `upgrade_subscription` (complex tools)
  - Removed old `validateArgs` function
  - Added validation type exports to `src/types/index.ts`
  - All validations provide clear, user-friendly error messages
- **Benefits**:
  - Runtime type safety ensures data integrity
  - Prevents malformed data from reaching database
  - Clear validation errors: "Title cannot exceed 255 characters"
  - Automatic sanitization (trimming, type coercion)
  - Type-safe argument interfaces with full TypeScript inference

### 4.3 Billing Limit Enforcement
- **Status**: ⏳ Pending (Partial - check exists but not enforced consistently)
- **Location**: `create_todo` handler
- **Issues**:
  - Billing check only happens in create_todo
  - User can bypass by direct database access
  - No check in update operations
  - No tracking of actual usage
- **Proposed Solution**:
  - Move billing check to database trigger
  - Add usage tracking table
  - Implement middleware for all operations
  - Add audit logging

---

## 🔄 Phase 5: Code Organization & Architecture (PENDING)

### 5.1 Separate Concerns
- **Status**: ⏳ Pending
- **Location**: `src/server.ts` (1100+ lines)
- **Issues**:
  - Single file contains:
    - MCP server setup
    - JWT verification
    - Database operations
    - Billing logic
    - Tool handlers
  - Hard to test individual components
  - Difficult to maintain
- **Proposed Solution**:
  - Create `src/services/auth.ts` for JWT/JWKS
  - Create `src/services/billing.ts` for billing logic
  - Create `src/services/database.ts` for DB operations
  - Create `src/handlers/` directory for tool handlers
  - Create `src/middleware/` for validation, auth

### 5.2 Duplicate Code
- **Status**: ⏳ Pending
- **Location**: Multiple handlers
- **Issues**:
  - Token reading repeated in every handler (16 times)
  - JWT verification repeated
  - Database connection pattern repeated
  - Error handling pattern repeated
- **Proposed Solution**:
  - Create authentication middleware
  - Create database transaction wrapper
  - Create error response builder
  - Use dependency injection

### 5.3 Testing Infrastructure
- **Status**: ⏳ Pending
- **Location**: Project root (no tests exist)
- **Issues**:
  - No unit tests
  - No integration tests
  - No test database setup
  - No CI/CD pipeline
- **Proposed Solution**:
  - Add Jest or Vitest
  - Create test database setup
  - Add unit tests for:
    - JWT verification
    - Billing logic
    - Input validation
  - Add integration tests for:
    - Tool handlers
    - Authentication flow
    - Database operations
  - Set up GitHub Actions

---

## 🔄 Phase 6: Database & Performance (PENDING)

### 6.1 Database Connection Pooling
- **Status**: ⏳ Pending
- **Location**: `src/server.ts` (database connection)
- **Issues**:
  - No connection pooling configured
  - Default pool size may be inadequate
  - No connection timeout settings
  - No idle connection cleanup
- **Proposed Solution**:
  - Configure pool size based on workload
  - Add connection timeout (30s)
  - Add idle timeout (10 minutes)
  - Add connection retry logic
  - Monitor pool usage

### 6.2 SQL Query Optimization
- **Status**: ⏳ Pending
- **Location**: All database queries
- **Issues**:
  - No indexes defined beyond primary key
  - No query analysis
  - N+1 query pattern in list operations
- **Proposed Solution**:
  - Add index on `todos(user_id)`
  - Add composite index on `todos(user_id, completed)`
  - Use EXPLAIN ANALYZE for slow queries
  - Consider query result caching

### 6.3 Transaction Management
- **Status**: ⏳ Pending
- **Location**: `create_todo`, `update_todo`
- **Issues**:
  - No explicit transactions
  - Race conditions possible:
    - Two creates at limit boundary
    - Concurrent updates to same todo
- **Proposed Solution**:
  - Wrap operations in transactions
  - Use row-level locking where needed
  - Add optimistic locking (version field)

---

## 🔄 Phase 7: Security Hardening (PENDING)

### 7.1 SQL Injection Prevention
- **Status**: ✅ Partially Complete (using parameterized queries)
- **Location**: All database operations
- **Current State**: Using parameterized queries is good
- **Remaining Work**:
  - Add input sanitization layer
  - Add query logging for security audits
  - Consider using an ORM (Prisma, TypeORM)

### 7.2 Rate Limiting
- **Status**: ⏳ Pending
- **Location**: OAuth server, MCP handlers
- **Issues**:
  - No rate limiting on any endpoint
  - Vulnerable to:
    - Brute force attacks
    - DoS attacks
    - API abuse
- **Proposed Solution**:
  - Add express-rate-limit middleware
  - Implement per-user rate limits
  - Add exponential backoff
  - Log rate limit violations

### 7.3 Token Storage Security
- **Status**: ⏳ Pending (file permissions fixed, but storage method questionable)
- **Location**: `.kinde_token` file
- **Issues**:
  - Tokens stored in plain text file
  - File-based storage not suitable for production
  - No token rotation
  - No token revocation mechanism
- **Proposed Solution**:
  - Move to encrypted database storage
  - Implement token rotation (refresh tokens)
  - Add token revocation endpoint
  - Consider Redis for session storage

### 7.4 Audit Logging
- **Status**: ⏳ Pending
- **Location**: All sensitive operations
- **Issues**:
  - No audit trail for:
    - Authentication attempts
    - Todo creation/deletion
    - Billing limit violations
    - Error conditions
- **Proposed Solution**:
  - Create audit_log table
  - Log all authentication events
  - Log all data modifications
  - Log security violations
  - Add log retention policy

---

## 🔄 Phase 8: Monitoring & Observability (PENDING)

### 8.1 Structured Logging
- **Status**: ⏳ Pending
- **Location**: All log statements
- **Issues**:
  - Using console.error only
  - No structured format (JSON)
  - No log levels
  - No request correlation IDs
- **Proposed Solution**:
  - Add winston or pino logger
  - Use JSON format for parsing
  - Add log levels (debug, info, warn, error)
  - Add request IDs for tracing
  - Add log aggregation (ELK, Datadog)

### 8.2 Health Checks
- **Status**: ⏳ Pending (healthcheck disabled in dev)
- **Location**: Docker compose files
- **Issues**:
  - No health check endpoint
  - No database connectivity check
  - No OAuth server health check
  - Cannot detect partial failures
- **Proposed Solution**:
  - Add `/health` endpoint
  - Check database connectivity
  - Check OAuth server status
  - Return detailed health status
  - Enable in production

### 8.3 Metrics & Monitoring
- **Status**: ⏳ Pending
- **Location**: None currently
- **Issues**:
  - No metrics collection
  - No performance monitoring
  - Cannot track:
    - Request latency
    - Error rates
    - Todo creation rate
    - Billing limit hits
- **Proposed Solution**:
  - Add Prometheus metrics
  - Track request duration
  - Track error rates by type
  - Track business metrics (todos created, limits hit)
  - Set up Grafana dashboards

---

## 🔄 Phase 9: Developer Experience (PENDING)

### 9.1 API Documentation
- **Status**: ⏳ Pending
- **Location**: None currently
- **Issues**:
  - No tool documentation
  - No API examples
  - No architecture diagrams
  - No setup instructions
- **Proposed Solution**:
  - Add JSDoc comments to all tools
  - Create ARCHITECTURE.md
  - Create API.md with examples
  - Update README.md with setup guide
  - Add mermaid diagrams

### 9.2 Development Workflow
- **Status**: ⏳ Pending (partial - Docker dev setup exists)
- **Location**: Project root
- **Issues**:
  - No hot reload for TypeScript changes
  - No pre-commit hooks
  - No code formatting setup
  - No linting rules
- **Proposed Solution**:
  - Add ts-node-dev for hot reload
  - Add husky for git hooks
  - Add prettier with config
  - Add ESLint with TypeScript rules
  - Add lint-staged

### 9.3 Debugging Support
- **Status**: ⏳ Pending (debugger port exposed but not configured)
- **Location**: `docker-compose.dev.yml:29`
- **Issues**:
  - Debug port exposed but no VS Code config
  - No debug documentation
  - No source maps configuration verified
- **Proposed Solution**:
  - Add `.vscode/launch.json`
  - Document debugging setup
  - Verify source maps working
  - Add debug npm script

---

## Priority Recommendations

### High Priority (Next Phase)
1. **Database Error Handling** (Phase 4.1)
   - Distinguish between error types (connection, constraint, etc.)
   - Provide actionable error messages to users
   - Add retry logic for transient failures
   - Implement transaction support for multi-statement operations

2. **Billing Limit Enforcement** (Phase 4.3)
   - Close security bypass vulnerabilities
   - Implement atomic quota operations
   - Add database-level constraints
   - Add audit logging for quota changes

3. **Testing Infrastructure** (Phase 5.3)
   - Enable confidence in refactoring
   - Catch regressions early
   - Document expected behavior

### Medium Priority
1. **Code Organization** (Phase 5.1)
   - Makes future work easier
   - Improves maintainability
   - Enables better testing
   - Separates concerns in 1100+ line server.ts

2. **Database Connection Pooling** (Phase 6.1)
3. **Rate Limiting** (Phase 7.2)
4. **Structured Logging** (Phase 8.1)

### Lower Priority (Polish)
1. **API Documentation** (Phase 9.1)
2. **Metrics & Monitoring** (Phase 8.3)
3. **Development Workflow** (Phase 9.2)

---

## Statistics

- **Total Improvements Identified**: 40+
- **Completed (Phases 1, 2, 3, & 4.2)**: 18
- **In Progress (Phase 4)**: 2 (4.1 and 4.3 pending)
- **Pending (Phases 5-9)**: 20+
- **Completion**: 45%

---

## Notes

- All completed improvements have been tested and verified working
- **Phase 1** addressed critical security bugs and crash prevention
- **Phase 2** improved type safety and eliminated 'any' types
- **Phase 3** centralized configuration with Zod validation and eliminated hardcoded values
- **Phase 4.2** implemented comprehensive Zod-based input validation across all tool handlers
- Remaining work in Phase 4 focuses on database error handling and billing enforcement
- Future phases focus on code organization, testing, performance, and developer experience
- This document serves as a living roadmap for future development
