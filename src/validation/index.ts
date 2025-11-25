import { z, ZodSchema, ZodError } from 'zod';

// Re-export all schemas for convenient importing
export * from './schemas.js';

/**
 * Validates tool arguments against a Zod schema
 *
 * @param schema - Zod schema to validate against
 * @param args - Arguments to validate
 * @returns Validated and type-safe arguments
 * @throws Error with detailed validation message if validation fails
 */
export function validateToolArgs<T>(schema: ZodSchema<T>, args: unknown): T {
  try {
    return schema.parse(args);
  } catch (error) {
    if (error instanceof ZodError) {
      // Format Zod errors into user-friendly messages
      const errorMessages = error.issues.map((err) => {
        const path = err.path.join('.');
        return path ? `${path}: ${err.message}` : err.message;
      }).join('; ');

      throw new Error(`Validation failed: ${errorMessages}`);
    }
    throw error;
  }
}

/**
 * Sanitizes a string by trimming whitespace
 *
 * @param input - String to sanitize
 * @returns Trimmed string
 */
export function sanitizeString(input: string): string {
  return input.trim();
}

/**
 * Validates JWT token format (basic check for 3 dot-separated parts)
 *
 * @param token - Token string to validate
 * @returns True if token has valid JWT structure
 */
export function isValidJWTFormat(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3 && parts.every(part => part.length > 0);
}

/**
 * Safe parse that returns a result object instead of throwing
 * Useful for cases where you want to handle validation errors without try-catch
 *
 * @param schema - Zod schema to validate against
 * @param args - Arguments to validate
 * @returns Object with success flag and either data or error
 */
export function safeValidate<T>(
  schema: ZodSchema<T>,
  args: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(args);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errorMessages = result.error.issues.map((err) => {
    const path = err.path.join('.');
    return path ? `${path}: ${err.message}` : err.message;
  }).join('; ');

  return { success: false, error: errorMessages };
}
