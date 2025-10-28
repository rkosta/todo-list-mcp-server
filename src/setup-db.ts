import { neon } from '@neondatabase/serverless';
import dotenv from 'dotenv';

dotenv.config();

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
    throw new Error('DATABASE_URL is not defined in environment variables');
}

const sql = neon(databaseUrl);

async function setupDatabase() {
    console.log('Setting up database schema...');
    try {
        await sql`
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `;

        await sql`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            user_id TEXT UNIQUE NOT NULL,
            name TEXT,
            email TEXT,
            subscription_status TEXT DEFAULT 'free' CHECK (subscription_status IN ('free', 'active', 'cancelled')),
            plan TEXT DEFAULT 'free',
            free_todos_used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        `;

        await sql`
        CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id)
        `;

        await sql`
        CREATE INDEX IF NOT EXISTS idx_todos_created_at ON todos(created_at)
        `;

        await sql`
        CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id)
        `;

        console.log('✅ Database schema created successfully!');
        console.log('📋 Tables created:');
        console.log('  - todos (id, user_id, title, description, completed, created_at, updated_at)');
        console.log('  - users (id, user_id, subscription_status, plan, free_todos_used, created_at, updated_at)');
        console.log('🔍 Indexes created for optimal performance');

        process.exit(0);
    } catch (error) {
        console.error('❌ Error setting up database:', error);
        process.exit(1);
    }
}

setupDatabase();