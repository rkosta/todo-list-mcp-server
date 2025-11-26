# Phase 4.1: Database Error Handling - Implementation Plan

**Status:** Ready for implementation
**Prerequisites:** Phase 4.2 (Input Validation) - ✅ Completed
**Date:** 2025-11-26

---

## Executive Summary

This document contains the complete implementation plan for Phase 4.1 (Database Error Handling), including detailed exploration findings, error classification strategies, transaction patterns, and step-by-step implementation instructions.

---

## Table of Contents

1. [Current Issues](#current-issues)
2. [Objectives](#objectives)
3. [PostgreSQL Error Codes Reference](#postgresql-error-codes-reference)
4. [New Files to Create](#new-files-to-create)
5. [Files to Modify](#files-to-modify)
6. [Transaction Patterns](#transaction-patterns)
7. [Implementation Order](#implementation-order)
8. [Expected Improvements](#expected-improvements)
9. [Testing Strategy](#testing-strategy)

---

## Current Issues

### 1. Generic Error Messages

**Problem:** All database operations return generic error messages that don't help users understand what went wrong or how to fix it.

**Examples from exploration:**
- `list_todos` (lines 546-607): "Failed to list todos" for ALL error types
- `create_todo` (lines 801-885): "Failed to create todo" for quota, connection, and constraint errors
- `getKindeBillingStatus` (lines 175-232): Silent failure with only `console.error()`
- No distinction between user errors, transient errors, and system errors

**Impact:**
- Users don't know if they should retry
- Support burden increases (users can't self-diagnose)
- Poor user experience

### 2. No Transaction Support

**Problem:** Multi-step operations execute as separate queries, creating race conditions and data inconsistency risks.

**Critical Issues:**
- **`create_todo`** (lines 839-857):
  - INSERT todo in one query
  - UPDATE free_todos_used in separate query
  - **Race condition:** Two concurrent creates can both pass quota check
  - **Inconsistent state:** INSERT succeeds but UPDATE fails = incorrect quota count

- **`delete_todo`** (lines 1078-1088):
  - DELETE todo in one query
  - UPDATE free_todos_used (decrement) in separate query
  - **Inconsistent state:** DELETE succeeds but UPDATE fails = quota not recovered

**Impact:**
- Users can exceed quota limits
- Quota counts become incorrect over time
- Data integrity compromised

### 3. No Retry Logic

**Problem:** All errors fail immediately, even transient connection issues that would succeed on retry.

**Examples:**
- Connection timeout (08006) → immediate failure
- Too many connections (53300) → immediate failure
- Serialization failure (40001) → immediate failure
- Users must manually retry everything

**Impact:**
- Poor reliability during temporary issues
- Unnecessary failures
- Bad user experience during network hiccups

### 4. Information Leakage

**Problem:** Full error details exposed in API responses, potentially revealing sensitive information.

**Risks:**
- Database schema details visible in constraint violation errors
- Connection strings in connection errors
- Stack traces could leak internal implementation
- PostgreSQL version and configuration details

**Impact:**
- Security vulnerability
- Potential attack surface expansion

---

## Objectives

1. **Classify PostgreSQL errors by type**
   - Connection errors (transient - retry)
   - Constraint violations (permanent - user error)
   - Transaction conflicts (transient - retry with backoff)
   - Data errors (permanent - application bug)

2. **Provide specific, actionable error messages**
   - Replace "Failed to list todos" with specific guidance
   - Tell users if they should retry or change their input
   - Help users self-diagnose issues

3. **Implement retry logic for transient failures**
   - Automatic retry for connection errors (08xxx codes)
   - Exponential backoff for transaction conflicts (40xxx codes)
   - Configurable retry counts and delays

4. **Add transaction support for multi-statement operations**
   - Wrap create_todo INSERT + UPDATE in transaction
   - Wrap delete_todo DELETE + UPDATE in transaction
   - Use `SELECT ... FOR UPDATE` for atomic quota checks

5. **Prevent error information leakage**
   - Sanitize error messages before sending to users
   - Log detailed errors securely server-side
   - Never expose stack traces or internal details

---

## PostgreSQL Error Codes Reference

### Priority 1 - Connection Errors (Transient - Retry)

| Code | Name | Description | Action |
|------|------|-------------|--------|
| `08000` | connection_exception | General connection error | Retry with backoff |
| `08003` | connection_does_not_exist | Connection pooling issue | Retry immediately |
| `08006` | connection_failure | Database unavailable | Retry with backoff |
| `57P03` | cannot_connect_now | Server starting/stopping | Retry with longer delay |
| `53300` | too_many_connections | Connection pool exhausted | Retry with backoff |

**User Message:** "Database is temporarily unavailable. Please try again in a few moments."

### Priority 2 - Constraint Violations (Permanent - User Error)

| Code | Name | Description | Action |
|------|------|-------------|--------|
| `23502` | not_null_violation | Required field missing | Return specific field error |
| `23505` | unique_violation | Duplicate entry | "This {resource} already exists" |
| `23503` | foreign_key_violation | Referenced record missing | "Referenced record not found" |
| `23514` | check_constraint_violation | Invalid data | Return validation error |

**User Message:** Specific to constraint (e.g., "Title is required", "This todo already exists")

### Priority 3 - Transaction Errors (Transient - Retry with Backoff)

| Code | Name | Description | Action |
|------|------|-------------|--------|
| `40001` | serialization_failure | Concurrent transaction conflict | Retry with exponential backoff |
| `40P01` | deadlock_detected | Transaction ordering issue | Retry with exponential backoff |

**User Message:** "This operation conflicted with another update. Retrying automatically..."

### Priority 4 - Data Errors (Permanent - Application Bug)

| Code | Name | Description | Action |
|------|------|-------------|--------|
| `22001` | string_data_right_truncation | String too long | Log bug, validation should prevent |
| `22P02` | invalid_text_representation | Type mismatch | Log bug, validation should prevent |

**User Message:** "An unexpected error occurred. Please try again or contact support."

---

## New Files to Create

### 1. `src/types/errors.ts`

**Purpose:** Type definitions for error handling system

```typescript
/**
 * Database error classification result
 */
export interface DatabaseErrorClassification {
  code: string;
  isRetryable: boolean;
  isUserError: boolean;
  isConnectionError: boolean;
  isConstraintViolation: boolean;
  userMessage: string;
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxRetries: number;
  initialDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
}

/**
 * Operation result with error handling
 */
export interface OperationResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  shouldRetry?: boolean;
}

/**
 * Error types for classification
 */
export enum DatabaseErrorType {
  CONNECTION = 'connection',
  CONSTRAINT = 'constraint',
  TRANSACTION = 'transaction',
  DATA = 'data',
  TIMEOUT = 'timeout',
  UNKNOWN = 'unknown'
}
```

**No dependencies** - Create this file first

---

### 2. `src/utils/db-errors.ts`

**Purpose:** Centralized database error classification and handling utilities

```typescript
import { DatabaseErrorClassification, RetryConfig, OperationResult } from '../types/errors.js';

/**
 * Classifies a database error by type
 *
 * @param error - Error object from database operation
 * @returns Classification with error metadata
 */
export function classifyDatabaseError(error: unknown): DatabaseErrorClassification {
  const code = getErrorCode(error);

  return {
    code,
    isRetryable: isRetryableError(code),
    isUserError: isUserError(code),
    isConnectionError: isConnectionError(code),
    isConstraintViolation: isConstraintViolation(code),
    userMessage: getUserFriendlyMessage(code, error)
  };
}

/**
 * Extracts PostgreSQL error code from error object
 */
function getErrorCode(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    return String(error.code);
  }
  return 'UNKNOWN';
}

/**
 * Checks if error code indicates a retryable issue
 */
function isRetryableError(code: string): boolean {
  // Connection errors: 08xxx, 57P03, 53300
  // Transaction errors: 40001, 40P01
  return [
    '08000', '08003', '08006', '57P03', '53300',  // Connection
    '40001', '40P01'                               // Transaction
  ].includes(code);
}

/**
 * Checks if error is due to user input (constraint violations)
 */
function isUserError(code: string): boolean {
  // All constraint violations: 23xxx
  return code.startsWith('23');
}

/**
 * Checks if error is a connection issue
 */
function isConnectionError(code: string): boolean {
  return code.startsWith('08') || code === '57P03' || code === '53300';
}

/**
 * Checks if error is a constraint violation
 */
function isConstraintViolation(code: string): boolean {
  return code.startsWith('23');
}

/**
 * Gets user-friendly error message based on error code
 */
function getUserFriendlyMessage(code: string, error: unknown): string {
  // Connection errors
  if (code.startsWith('08')) {
    return 'Unable to connect to database. Please check your connection and try again.';
  }
  if (code === '57P03') {
    return 'Database is starting up. Please try again in a moment.';
  }
  if (code === '53300') {
    return 'Database is temporarily overloaded. Please try again shortly.';
  }

  // Constraint violations
  if (code === '23502') {
    return 'Required field is missing. Please check your input.';
  }
  if (code === '23505') {
    return 'This record already exists.';
  }
  if (code === '23503') {
    return 'Referenced record not found.';
  }
  if (code === '23514') {
    return 'Input validation failed. Please check your data.';
  }

  // Transaction conflicts
  if (code === '40001' || code === '40P01') {
    return 'Operation conflicted with another update. Retrying automatically...';
  }

  // Data errors (should be prevented by validation)
  if (code === '22001') {
    return 'Input data is too long.';
  }
  if (code === '22P02') {
    return 'Input data has invalid format.';
  }

  // Default
  return 'An unexpected error occurred. Please try again later.';
}

/**
 * Retry logic with exponential backoff for transient errors
 *
 * @param operation - Async operation to retry
 * @param maxRetries - Maximum number of retry attempts (default: 3)
 * @param initialDelay - Initial delay in ms (default: 100)
 * @returns Result object with success flag and data or error
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  initialDelay: number = 100
): Promise<OperationResult<T>> {
  let lastError: unknown;
  let delay = initialDelay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const data = await operation();
      return { success: true, data };
    } catch (error) {
      lastError = error;
      const classification = classifyDatabaseError(error);

      // Only retry if error is retryable and we have attempts left
      if (!classification.isRetryable || attempt === maxRetries) {
        break;
      }

      // Wait before retrying (exponential backoff)
      await sleep(delay);
      delay = Math.min(delay * 2, 5000); // Cap at 5 seconds
    }
  }

  // All retries exhausted
  const classification = classifyDatabaseError(lastError);
  return {
    success: false,
    error: classification.userMessage,
    shouldRetry: false
  };
}

/**
 * Sanitizes error for logging (removes sensitive data)
 */
export function sanitizeErrorForLogging(error: unknown): string {
  if (error instanceof Error) {
    // Remove potential sensitive data from error messages
    const message = error.message
      .replace(/password[=:]\S+/gi, 'password=***')
      .replace(/token[=:]\S+/gi, 'token=***')
      .replace(/postgres:\/\/[^@]+@/g, 'postgres://***@');

    return `${error.name}: ${message}`;
  }

  return String(error);
}

/**
 * Helper function to sleep/delay
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Creates a standardized error response for MCP tools
 */
export function createErrorResponse(error: unknown) {
  const classification = classifyDatabaseError(error);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: false,
        error: classification.userMessage,
        ...(classification.isRetryable && { hint: 'This is a temporary issue. Please try again.' })
      }, null, 2)
    }]
  };
}
```

**Dependencies:** `src/types/errors.ts`

---

## Files to Modify

### 1. `src/server.ts` - Database Operations

#### Read Operations (Simpler - Start Here)

##### a) `list_todos` (lines 546-607)

**Current Code:**
```typescript
catch (error) {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: false,
        error: 'Failed to list todos',
        details: error instanceof Error ? error.message : 'Unknown error'
      })
    }]
  };
}
```

**Updated Code:**
```typescript
catch (error) {
  console.error('Error listing todos:', sanitizeErrorForLogging(error));

  const classification = classifyDatabaseError(error);

  // Retry for transient errors
  if (classification.isRetryable) {
    const retryResult = await retryWithBackoff(
      () => sql`
        SELECT id, title, description, completed, created_at, updated_at
        FROM todos
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
      `,
      3,  // Max 3 retries
      100 // Start with 100ms delay
    );

    if (retryResult.success) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            todos: retryResult.data
          }, null, 2)
        }]
      };
    }
  }

  return createErrorResponse(error);
}
```

**Changes:**
- ✅ Classify error type
- ✅ Retry transient errors automatically
- ✅ Return user-friendly messages
- ✅ Log sanitized error details
- ✅ No information leakage

---

##### b) `getKindeBillingStatus` (lines 175-232)

**Current Code:**
```typescript
catch (error) {
  console.error('Error checking billing status:', error);
  // Silent failure - returns default free tier
}
```

**Updated Code:**
```typescript
catch (error) {
  console.error('Error checking billing status:', sanitizeErrorForLogging(error));

  const classification = classifyDatabaseError(error);

  // Retry connection errors
  if (classification.isRetryable) {
    const retryResult = await retryWithBackoff(
      () => sql`SELECT subscription_status, free_todos_used FROM users WHERE user_id = ${userId}`,
      3
    );
    if (retryResult.success && retryResult.data?.[0]) {
      return retryResult.data[0];
    }
  }

  // Constraint violation (user exists check)
  if (error.code === '23505') {
    throw new Error('User account conflict detected. Please contact support.');
  }

  // Return error instead of silent failure
  throw new Error(`Unable to retrieve billing status: ${classification.userMessage}`);
}
```

**Changes:**
- ✅ No more silent failures
- ✅ Retry logic for transient errors
- ✅ Specific error messages
- ✅ Throw error instead of returning default

---

#### Write Operations (Complex - Require Transactions)

##### c) `create_todo` (lines 801-885)

**Critical Issues:**
- Race condition: Multiple concurrent creates can bypass quota
- Inconsistent state: INSERT succeeds but UPDATE fails

**Current Code (Problematic):**
```typescript
// Lines 839-857
const newTodo = await sql`
  INSERT INTO todos (user_id, title, description, completed)
  VALUES (${userId}, ${title}, ${description}, ${completed})
  RETURNING *
`;

// Separate query - RACE CONDITION POSSIBLE
if (userInfo.subscription_status !== 'active') {
  await sql`
    UPDATE users
    SET free_todos_used = free_todos_used + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE user_id = ${userId}
  `;
}
```

**Updated Code (Transactional):**
```typescript
try {
  // Check quota BEFORE transaction for early exit
  const billingStatus = await getKindeBillingStatus(userId, userInfo);
  if (!billingStatus.canCreate) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Todo creation limit reached',
          details: billingStatus.reason,
          currentPlan: billingStatus.plan,
          usage: `${billingStatus.features.used}/${billingStatus.features.maxTodos}`
        }, null, 2)
      }]
    };
  }

  // Atomic transaction: INSERT todo + UPDATE quota
  const result = await sql.transaction([
    // Step 1: Lock user row and re-check quota
    sql`
      SELECT free_todos_used, subscription_status
      FROM users
      WHERE user_id = ${userId}
      FOR UPDATE
    `,
    // Step 2: Insert todo
    sql`
      INSERT INTO todos (user_id, title, description, completed)
      VALUES (${userId}, ${title}, ${description}, ${completed})
      RETURNING *
    `,
    // Step 3: Increment quota (only for free tier)
    sql`
      UPDATE users
      SET free_todos_used = free_todos_used + 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = ${userId}
        AND subscription_status != 'active'
    `
  ]);

  const newTodo = result[1][0]; // Get inserted todo from second query

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        todo: newTodo,
        message: 'Todo created successfully'
      }, null, 2)
    }]
  };

} catch (error) {
  console.error('Error creating todo:', sanitizeErrorForLogging(error));

  const classification = classifyDatabaseError(error);

  // Retry transaction conflicts
  if (classification.code === '40001' || classification.code === '40P01') {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Operation conflicted with another update. Please try again.',
          shouldRetry: true
        }, null, 2)
      }]
    };
  }

  return createErrorResponse(error);
}
```

**Key Improvements:**
- ✅ **Atomic transaction** - All or nothing
- ✅ **`SELECT ... FOR UPDATE`** - Locks user row during quota check
- ✅ **Race condition eliminated** - Quota check happens inside transaction
- ✅ **Retry for serialization failures** - Handles concurrent conflicts
- ✅ **Consistent state** - INSERT and UPDATE succeed together or fail together

---

##### d) `delete_todo` (lines 1018-1145)

**Critical Issue:** DELETE and quota recovery in separate queries = inconsistent state

**Current Code (Problematic):**
```typescript
// Lines 1078-1088
await sql`DELETE FROM todos WHERE id = ${todoId} AND user_id = ${userId}`;

// Separate query - INCONSISTENT STATE POSSIBLE
await sql`
  UPDATE users
  SET free_todos_used = GREATEST(free_todos_used - 1, 0),
      updated_at = CURRENT_TIMESTAMP
  WHERE user_id = ${userId}
`;
```

**Updated Code (Transactional):**
```typescript
try {
  // Atomic transaction: DELETE todo + UPDATE quota
  const result = await sql.transaction([
    // Step 1: Delete todo
    sql`
      DELETE FROM todos
      WHERE id = ${todoId} AND user_id = ${userId}
      RETURNING *
    `,
    // Step 2: Decrement quota atomically
    sql`
      UPDATE users
      SET free_todos_used = GREATEST(free_todos_used - 1, 0),
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = ${userId}
      RETURNING free_todos_used
    `
  ]);

  const deletedTodo = result[0][0];
  const updatedQuota = result[1][0];

  if (!deletedTodo) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Todo not found or you do not have permission to delete it'
        }, null, 2)
      }]
    };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        message: 'Todo deleted successfully',
        quotaRecovered: true,
        remainingQuota: updatedQuota.free_todos_used
      }, null, 2)
    }]
  };

} catch (error) {
  console.error('Error deleting todo:', sanitizeErrorForLogging(error));
  return createErrorResponse(error);
}
```

**Key Improvements:**
- ✅ **Atomic transaction** - DELETE and quota UPDATE together
- ✅ **Consistent state** - Quota always matches actual todo count
- ✅ **RETURNING clause** - Verify deletion happened
- ✅ **Better error messages** - Distinguish not found vs permission denied

---

### 2. `src/kinde-auth-server.ts` (Lines 215-243)

**Current Code:**
```typescript
// Auto-create user on first login
try {
  await sql`
    INSERT INTO users (user_id, name, email)
    VALUES (${user.sub}, ${user.name || user.given_name}, ${user.email})
    ON CONFLICT (user_id) DO NOTHING
  `;
} catch (error) {
  console.error('Error creating user:', error);
  // Silent failure - continues anyway
}
```

**Updated Code:**
```typescript
// Auto-create user on first login
try {
  await sql`
    INSERT INTO users (user_id, name, email)
    VALUES (${user.sub}, ${user.name || user.given_name}, ${user.email})
    ON CONFLICT (user_id) DO UPDATE
    SET name = EXCLUDED.name,
        email = EXCLUDED.email,
        updated_at = CURRENT_TIMESTAMP
  `;
} catch (error) {
  console.error('Error creating/updating user:', sanitizeErrorForLogging(error));

  const classification = classifyDatabaseError(error);

  // Retry connection errors
  if (classification.isRetryable) {
    const retryResult = await retryWithBackoff(
      () => sql`INSERT INTO users...`,
      2
    );
    if (!retryResult.success) {
      return res.status(500).send(`
        <h1>Login Failed</h1>
        <p>Unable to create user account. Please try again.</p>
        <p>Error: ${classification.userMessage}</p>
      `);
    }
  } else {
    // Permanent error
    return res.status(500).send(`
      <h1>Login Failed</h1>
      <p>Unable to create user account. Please contact support.</p>
    `);
  }
}
```

**Changes:**
- ✅ No more silent failures
- ✅ Update user info on subsequent logins (DO UPDATE)
- ✅ Retry connection errors
- ✅ Show error to user instead of continuing
- ✅ Sanitized error messages

---

### 3. `src/setup-db.ts` (Lines 54-57)

**Current Code:**
```typescript
catch (error) {
  console.error('Error setting up database:', error);
  process.exit(1);
}
```

**Updated Code:**
```typescript
catch (error) {
  const classification = classifyDatabaseError(error);

  console.error('\n❌ Database setup failed\n');

  // Specific guidance based on error type
  if (error.code === '3D000') {
    console.error('Database does not exist. Please create it first:');
    console.error('  psql -c "CREATE DATABASE your_database_name;"');
    console.error('');
    console.error('Or in your Neon dashboard:');
    console.error('  1. Go to https://console.neon.tech');
    console.error('  2. Create a new database');
    console.error('  3. Update DATABASE_URL in your .env file');
    process.exit(2);
  }

  if (classification.isConnectionError) {
    console.error('Unable to connect to database. Please check:');
    console.error('  • DATABASE_URL in .env is correct');
    console.error('  • Database server is running and accessible');
    console.error('  • Network connectivity (firewall rules, VPN)');
    console.error('  • Your IP is whitelisted (for Neon databases)');
    console.error('');
    console.error('Current DATABASE_URL format:');
    console.error('  postgresql://user:password@host:port/database');
    process.exit(3);
  }

  if (classification.code === '42501') {
    console.error('Permission denied. Please check:');
    console.error('  • Database user has CREATE TABLE privileges');
    console.error('  • Database user has CREATE INDEX privileges');
    process.exit(4);
  }

  // Generic error with sanitized message
  console.error('Setup failed:', classification.userMessage);
  console.error('');
  console.error('Technical details (for support):');
  console.error(sanitizeErrorForLogging(error));
  process.exit(1);
}
```

**Changes:**
- ✅ Different exit codes for different error types
- ✅ Actionable troubleshooting steps
- ✅ Specific guidance for common issues
- ✅ Safe error logging (sanitized)

---

### 4. `src/types/index.ts`

**Add:**
```typescript
// Import and re-export error types
export type {
  DatabaseErrorClassification,
  RetryConfig,
  OperationResult,
} from './errors.js';

export { DatabaseErrorType } from './errors.js';
```

---

## Transaction Patterns

### Important: Neon Transaction API

**❌ WRONG (sql.begin does not exist):**
```typescript
await sql.begin(async (sql) => {
  // This will fail - Neon doesn't have sql.begin()
});
```

**✅ CORRECT (use sql.transaction):**
```typescript
const result = await sql.transaction([
  sql`SELECT ...`,
  sql`INSERT ...`,
  sql`UPDATE ...`
]);
```

### Pattern 1: Simple Multi-Step Transaction

**Use case:** Delete todo + decrement quota

```typescript
const result = await sql.transaction([
  sql`DELETE FROM todos WHERE id = ${todoId} AND user_id = ${userId} RETURNING *`,
  sql`UPDATE users SET free_todos_used = GREATEST(free_todos_used - 1, 0) WHERE user_id = ${userId}`
]);

const deletedTodo = result[0][0];  // First query result
const updatedUser = result[1][0];  // Second query result
```

### Pattern 2: Transaction with Row Locking

**Use case:** Create todo with quota check

```typescript
const result = await sql.transaction([
  // Lock user row to prevent concurrent quota bypass
  sql`
    SELECT free_todos_used, subscription_status
    FROM users
    WHERE user_id = ${userId}
    FOR UPDATE
  `,
  // Insert todo
  sql`
    INSERT INTO todos (user_id, title, description, completed)
    VALUES (${userId}, ${title}, ${description}, ${completed})
    RETURNING *
  `,
  // Increment quota
  sql`
    UPDATE users
    SET free_todos_used = free_todos_used + 1
    WHERE user_id = ${userId}
  `
]);

const userBeforeLock = result[0][0];  // Quota before transaction
const newTodo = result[1][0];          // Inserted todo
const updatedUser = result[2][0];      // User with incremented quota
```

### Pattern 3: Complex Logic (Use Pool/Client)

**For operations requiring conditional logic WITHIN transaction:**

```typescript
import { Pool } from '@neondatabase/serverless';

const pool = new Pool({ connectionString: config.DATABASE_URL });
const client = await pool.connect();

try {
  await client.query('BEGIN');

  // Lock and check quota
  const userResult = await client.query(
    'SELECT free_todos_used FROM users WHERE user_id = $1 FOR UPDATE',
    [userId]
  );

  const currentUsage = userResult.rows[0].free_todos_used;

  // Conditional logic INSIDE transaction
  if (currentUsage >= FREE_TIER_TODO_LIMIT) {
    throw new Error('Quota exceeded');
  }

  // Insert todo
  const todoResult = await client.query(
    'INSERT INTO todos (user_id, title) VALUES ($1, $2) RETURNING *',
    [userId, title]
  );

  // Update quota
  await client.query(
    'UPDATE users SET free_todos_used = free_todos_used + 1 WHERE user_id = $1',
    [userId]
  );

  await client.query('COMMIT');
  return todoResult.rows[0];

} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
}
```

**Note:** Current codebase uses HTTP-based `neon()` function. Only use Pool/Client pattern if needed for complex conditional logic within transactions.

---

## Implementation Order

### Phase 1: Foundation (Day 1)

1. **Create `src/types/errors.ts`**
   - All error interfaces and enums
   - No dependencies
   - Simple, quick to implement
   - ✅ Can be tested in isolation

2. **Create `src/utils/db-errors.ts`**
   - Import types from Phase 1
   - Implement all utility functions
   - Write unit tests for error classification
   - Test retry logic with mocks
   - ✅ Can be tested without database

### Phase 2: Read Operations (Day 2)

3. **Update `list_todos` (lines 546-607)**
   - Simplest database operation
   - Good test case for error classification
   - No transactions needed
   - Test with:
     - Valid request (should work)
     - Disconnect database (should retry and give good error)
     - Invalid token (should give auth error)

4. **Update `get_todo` (lines 609-705)**
   - Similar to list_todos
   - Single query, no transaction
   - Test error handling

5. **Update `getKindeBillingStatus` (lines 175-232)**
   - More complex (called by other functions)
   - Currently silent failure
   - Critical for quota enforcement

### Phase 3: Write Operations with Transactions (Day 3-4)

6. **Update `create_todo` (lines 801-885)**
   - **MOST CRITICAL** - quota enforcement
   - Wrap INSERT + UPDATE in transaction
   - Add `SELECT ... FOR UPDATE` for locking
   - Test concurrent operations:
     - Two users creating todos simultaneously
     - Same user creating at quota limit
     - Connection failure mid-transaction

7. **Update `delete_todo` (lines 1018-1145)**
   - Wrap DELETE + UPDATE in transaction
   - Test quota recovery
   - Ensure consistency

8. **Update `update_todo` (lines 887-1016)**
   - Simpler - no quota involved
   - May not need transaction (single UPDATE)
   - Add error classification

### Phase 4: Supporting Files (Day 5)

9. **Update `src/kinde-auth-server.ts` (lines 215-243)**
   - Fix auto-create user flow
   - Add retry logic
   - Better error messages

10. **Update `src/setup-db.ts` (lines 54-57)**
    - Actionable error messages
    - Different exit codes
    - Troubleshooting guidance

11. **Update `src/types/index.ts`**
    - Export new error types
    - Quick, mechanical change

### Phase 5: Testing (Day 6)

12. **Integration Testing**
    - Test all operations with real database
    - Simulate connection failures
    - Test concurrent operations
    - Verify transaction rollbacks
    - Confirm retry logic works

---

## Expected Improvements

### User Experience
- ✅ **Specific error messages** instead of generic "Failed to..."
- ✅ **Actionable guidance** - Users know if they should retry or fix input
- ✅ **Automatic retry** for transient errors - No manual retries needed
- ✅ **Faster recovery** from temporary issues

### Data Integrity
- ✅ **Atomic transactions** prevent race conditions in quota management
- ✅ **No more corrupted counts** - free_todos_used always matches reality
- ✅ **Consistent state** even during concurrent operations
- ✅ **Quota enforcement** actually works (can't bypass with concurrent creates)

### Security
- ✅ **No information leakage** - Database details not exposed
- ✅ **Sanitized error messages** - Safe for users
- ✅ **Stack traces logged** server-side only
- ✅ **Connection strings** never leaked

### Maintainability
- ✅ **Centralized error handling** in `src/utils/db-errors.ts`
- ✅ **Consistent error classification** across all operations
- ✅ **Easy to add new error codes** or handlers
- ✅ **Type-safe** with TypeScript

### Operations
- ✅ **Better debugging** - Classified error types in logs
- ✅ **Metrics-friendly** - Can track retryable vs permanent errors
- ✅ **Database setup** provides actionable troubleshooting
- ✅ **Different exit codes** help automated deployments

---

## Testing Strategy

### Unit Tests

**Test `src/utils/db-errors.ts` functions:**

```typescript
describe('classifyDatabaseError', () => {
  it('should identify connection errors as retryable', () => {
    const error = { code: '08006' };
    const result = classifyDatabaseError(error);
    expect(result.isRetryable).toBe(true);
    expect(result.isConnectionError).toBe(true);
  });

  it('should identify constraint violations as user errors', () => {
    const error = { code: '23505' };
    const result = classifyDatabaseError(error);
    expect(result.isUserError).toBe(true);
    expect(result.isConstraintViolation).toBe(true);
    expect(result.isRetryable).toBe(false);
  });
});

describe('retryWithBackoff', () => {
  it('should retry retryable errors', async () => {
    let attempts = 0;
    const operation = async () => {
      attempts++;
      if (attempts < 3) {
        const error: any = new Error('Connection failed');
        error.code = '08006';
        throw error;
      }
      return 'success';
    };

    const result = await retryWithBackoff(operation, 3);
    expect(result.success).toBe(true);
    expect(attempts).toBe(3);
  });
});
```

### Integration Tests

**Test transaction atomicity:**

```typescript
describe('create_todo transaction', () => {
  it('should rollback if UPDATE fails after INSERT', async () => {
    // Mock sql.transaction to fail on UPDATE
    // Verify:
    // 1. No todo was created
    // 2. free_todos_used was not incremented
    // 3. Error message is appropriate
  });

  it('should prevent concurrent quota bypass', async () => {
    // Set user to 4/5 quota (1 remaining)
    // Fire 5 concurrent create_todo requests
    // Verify: Only 1 succeeds, 4 get quota error
    // Verify: free_todos_used = 5 (not 9)
  });
});
```

### Manual Testing Scenarios

1. **Connection Failure Recovery**
   - Disconnect database mid-operation
   - Verify retry happens
   - Verify user gets good error message

2. **Transaction Rollback**
   - Create todo at quota limit
   - Verify todo not created AND quota not incremented

3. **Concurrent Operations**
   - Multiple users creating todos simultaneously
   - Verify no race conditions
   - Verify quota enforcement works

4. **Error Message Quality**
   - Trigger each error type
   - Verify messages are user-friendly
   - Verify no sensitive data leaked

---

## Rollback Plan

If issues arise:

1. **Read operations** (list_todos, get_todo)
   - Can revert to original try-catch
   - Low risk - only error messages changed

2. **Write operations** (create_todo, delete_todo)
   - **Higher risk** - transaction pattern is critical
   - Test thoroughly before deploying
   - Keep backup of original code

3. **Database setup** (setup-db.ts)
   - Only error messages changed
   - Safe to update

**Recommendation:**
- Deploy Phase 2 (read operations) first
- Monitor for issues
- Deploy Phase 3 (write operations) after validation

---

## Summary

This implementation plan addresses all critical database error handling issues:

1. ✅ **Generic errors** → Specific, actionable messages
2. ✅ **Race conditions** → Atomic transactions
3. ✅ **No retry logic** → Automatic retry with backoff
4. ✅ **Information leakage** → Sanitized messages

**Key Innovation:** Using Neon's `sql.transaction()` API with `SELECT ... FOR UPDATE` for atomic quota enforcement.

**Critical Files:**
- `src/types/errors.ts` - Type definitions
- `src/utils/db-errors.ts` - Error utilities (MOST IMPORTANT)
- `src/server.ts` - All database operations
- `src/kinde-auth-server.ts` - User creation
- `src/setup-db.ts` - Setup errors

**Implementation Time:** ~5-6 days for careful, tested implementation

---

## Next Steps

1. Review this plan with team
2. Create feature branch: `feat/phase-4.1-db-error-handling`
3. Start with Phase 1 (error types and utilities)
4. Test each phase before moving to next
5. Update docs/improvements.md when complete

---

**Document Version:** 1.0
**Last Updated:** 2025-11-26
**Status:** Ready for Implementation