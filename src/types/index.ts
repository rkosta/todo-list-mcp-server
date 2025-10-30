import { JwtPayload } from 'jsonwebtoken';

// =============================================================================
// JWKS Client Types
// =============================================================================

export interface JwksKey {
    publicKey?: string;
    rsaPublicKey?: string;
    getPublicKey?: () => string;
}

// =============================================================================
// Kinde Authentication Types
// =============================================================================

export interface KindeJwtPayload extends JwtPayload {
    sub: string;
    email?: string;
    given_name?: string;
    name?: string;
}

// =============================================================================
// Billing Types
// =============================================================================

export interface BillingFeatures {
    maxTodos: number;
    used?: number;
}

export interface BillingStatus {
    plan: string;
    features: BillingFeatures;
    canCreate: boolean;
    reason?: string;
}

// =============================================================================
// Session Types
// =============================================================================

export interface KindeTokenResponse {
    access_token: string;
    id_token: string;
    token_type: string;
    expires_in: number;
    scope?: string;
}

export interface SessionData {
    accessToken?: string;
    idToken?: string;
    userInfo?: KindeTokenResponse;
    userName?: string;
    userEmail?: string;
    [key: string]: unknown;
}

export type SessionValue = string | object | undefined;

// =============================================================================
// Validation Types
// =============================================================================

export interface ValidationResult<T = Record<string, unknown>> {
    valid: boolean;
    error?: string;
    validatedArgs?: T;
}
