import dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables once at module level (silent mode to avoid stdout pollution)
dotenv.config({ debug: false });

// Zod schema for environment variables
const envSchema = z.object({
    // Required environment variables
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    KINDE_ISSUER_URL: z.string().url('KINDE_ISSUER_URL must be a valid URL'),
    KINDE_CLIENT_ID: z.string().min(1, 'KINDE_CLIENT_ID is required'),
    KINDE_CLIENT_SECRET: z.string().min(1, 'KINDE_CLIENT_SECRET is required'),
    JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),

    // Optional environment variables with defaults
    PORT: z.string().optional().transform(val => val ? parseInt(val, 10) : 3000),
    NODE_ENV: z.enum(['development', 'production']).optional().default('development'),
    AUTH_SERVER_URL: z.string().url().optional(),
    TOKEN_FILE_PATH: z.string().optional().default('.auth-token'),
    JWKS_CACHE_MAX_AGE: z.string().optional().transform(val => val ? parseInt(val, 10) : 600000),
    FREE_TIER_TODO_LIMIT: z.string().optional().transform(val => val ? parseInt(val, 10) : 5),
    SESSION_MAX_AGE: z.string().optional().transform(val => val ? parseInt(val, 10) : 604800000),
    JWT_ALGORITHM: z.string().optional().default('RS256'),
});

// Validate and parse environment variables
let parsedEnv: z.infer<typeof envSchema>;

try {
    parsedEnv = envSchema.parse({
        DATABASE_URL: process.env.DATABASE_URL,
        KINDE_ISSUER_URL: process.env.KINDE_ISSUER_URL,
        KINDE_CLIENT_ID: process.env.KINDE_CLIENT_ID,
        KINDE_CLIENT_SECRET: process.env.KINDE_CLIENT_SECRET,
        JWT_SECRET: process.env.JWT_SECRET,
        PORT: process.env.PORT,
        NODE_ENV: process.env.NODE_ENV,
        AUTH_SERVER_URL: process.env.AUTH_SERVER_URL,
        TOKEN_FILE_PATH: process.env.TOKEN_FILE_PATH,
        JWKS_CACHE_MAX_AGE: process.env.JWKS_CACHE_MAX_AGE,
        FREE_TIER_TODO_LIMIT: process.env.FREE_TIER_TODO_LIMIT,
        SESSION_MAX_AGE: process.env.SESSION_MAX_AGE,
        JWT_ALGORITHM: process.env.JWT_ALGORITHM,
    });
} catch (error) {
    if (error instanceof z.ZodError) {
        console.error('Configuration validation failed:');
        console.error('');
        error.issues.forEach((err: z.ZodIssue) => {
            console.error(`  - ${err.path.join('.')}: ${err.message}`);
        });
        console.error('');
        console.error('Please check your .env file and ensure all required variables are set.');
        console.error('See .env.example for reference.');
        process.exit(1);
    }
    throw error;
}

// Create configuration object with computed values
class Config {
    // Required configuration
    readonly DATABASE_URL: string;
    readonly KINDE_ISSUER_URL: string;
    readonly KINDE_CLIENT_ID: string;
    readonly KINDE_CLIENT_SECRET: string;
    readonly JWT_SECRET: string;

    // Optional configuration with defaults
    readonly PORT: number;
    readonly NODE_ENV: 'development' | 'production';
    readonly TOKEN_FILE_PATH: string;
    readonly JWKS_CACHE_MAX_AGE: number;
    readonly FREE_TIER_TODO_LIMIT: number;
    readonly SESSION_MAX_AGE: number;
    readonly JWT_ALGORITHM: string;

    // Private field for AUTH_SERVER_URL
    private readonly _authServerUrl: string;

    constructor(env: z.infer<typeof envSchema>) {
        this.DATABASE_URL = env.DATABASE_URL;
        this.KINDE_ISSUER_URL = env.KINDE_ISSUER_URL;
        this.KINDE_CLIENT_ID = env.KINDE_CLIENT_ID;
        this.KINDE_CLIENT_SECRET = env.KINDE_CLIENT_SECRET;
        this.JWT_SECRET = env.JWT_SECRET;
        this.PORT = env.PORT;
        this.NODE_ENV = env.NODE_ENV;
        this.TOKEN_FILE_PATH = env.TOKEN_FILE_PATH;
        this.JWKS_CACHE_MAX_AGE = env.JWKS_CACHE_MAX_AGE;
        this.FREE_TIER_TODO_LIMIT = env.FREE_TIER_TODO_LIMIT;
        this.SESSION_MAX_AGE = env.SESSION_MAX_AGE;
        this.JWT_ALGORITHM = env.JWT_ALGORITHM;

        // Compute AUTH_SERVER_URL if not provided
        this._authServerUrl = env.AUTH_SERVER_URL || `http://localhost:${this.PORT}`;
    }

    // Computed properties (getters)
    get AUTH_SERVER_URL(): string {
        return this._authServerUrl;
    }

    get KINDE_REDIRECT_URL(): string {
        return `${this.AUTH_SERVER_URL}/callback`;
    }

    get KINDE_LOGOUT_REDIRECT_URL(): string {
        return this.AUTH_SERVER_URL;
    }

    get KINDE_JWKS_URI(): string {
        return `${this.KINDE_ISSUER_URL}/.well-known/jwks.json`;
    }

    get KINDE_PORTAL_URL(): string {
        // Extract domain from KINDE_ISSUER_URL (remove https://)
        return this.KINDE_ISSUER_URL.replace('https://', '');
    }
}

// Export singleton instance
export const config = new Config(parsedEnv);

// Export type for consumers
export type ConfigType = typeof config;
