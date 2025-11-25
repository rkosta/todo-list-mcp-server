import { z } from 'zod';

/**
 * Base field schemas for reusable validation
 */

// Todo ID must be a positive integer
export const TodoIdSchema = z.number().int().positive('Todo ID must be a positive integer');

// Title: required, trimmed, 1-255 characters
export const TitleSchema = z.string()
  .trim()
  .min(1, 'Title is required and cannot be empty')
  .max(255, 'Title cannot exceed 255 characters');

// Description: optional, trimmed, max 2000 characters
export const DescriptionSchema = z.string()
  .trim()
  .max(2000, 'Description cannot exceed 2000 characters')
  .optional();

// Completed status: boolean only
export const CompletedSchema = z.boolean().optional();

// JWT Token: minimum length with basic format validation
export const TokenSchema = z.string()
  .min(10, 'Token is too short to be valid')
  .refine(
    (token) => {
      // JWT format: three parts separated by dots
      const parts = token.split('.');
      return parts.length === 3 && parts.every(part => part.length > 0);
    },
    { message: 'Token must be a valid JWT format (header.payload.signature)' }
  );

// User ID from JWT claims
export const UserIdSchema = z.string().min(1, 'User ID is required');

/**
 * Tool-specific argument schemas
 */

// save_token tool arguments
export const SaveTokenArgsSchema = z.object({
  token: TokenSchema,
});

// get_todo tool arguments
export const GetTodoArgsSchema = z.object({
  authToken: z.string().optional(), // Token can come from args or file
  todoId: TodoIdSchema,
});

// create_todo tool arguments
export const CreateTodoArgsSchema = z.object({
  authToken: z.string().optional(), // Token can come from args or file
  title: TitleSchema.optional(), // Optional to support interactive mode
  description: DescriptionSchema,
  completed: CompletedSchema,
});

// update_todo tool arguments
export const UpdateTodoArgsSchema = z.object({
  authToken: z.string().optional(), // Token can come from args or file
  todoId: TodoIdSchema,
  title: TitleSchema.optional(), // All update fields are optional
  description: DescriptionSchema,
  completed: CompletedSchema,
}).refine(
  (data) => {
    // At least one field must be provided for update
    return data.title !== undefined || data.description !== undefined || data.completed !== undefined;
  },
  {
    message: 'At least one field (title, description, or completed) must be provided for update',
  }
);

// delete_todo tool arguments
export const DeleteTodoArgsSchema = z.object({
  authToken: z.string().optional(), // Token can come from args or file
  todoId: TodoIdSchema.optional(), // Optional for interactive mode
});

// get_subscription_status tool arguments
export const GetSubscriptionStatusArgsSchema = z.object({
  authToken: TokenSchema,
});

// upgrade_subscription tool arguments
export const UpgradeSubscriptionArgsSchema = z.object({
  authToken: TokenSchema,
});

/**
 * Type exports for use in handlers
 */
export type SaveTokenArgs = z.infer<typeof SaveTokenArgsSchema>;
export type GetTodoArgs = z.infer<typeof GetTodoArgsSchema>;
export type CreateTodoArgs = z.infer<typeof CreateTodoArgsSchema>;
export type UpdateTodoArgs = z.infer<typeof UpdateTodoArgsSchema>;
export type DeleteTodoArgs = z.infer<typeof DeleteTodoArgsSchema>;
export type GetSubscriptionStatusArgs = z.infer<typeof GetSubscriptionStatusArgsSchema>;
export type UpgradeSubscriptionArgs = z.infer<typeof UpgradeSubscriptionArgsSchema>;
