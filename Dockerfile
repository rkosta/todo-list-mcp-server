# Multi-stage Dockerfile for Todo List MCP Server

# ============================================
# Base Stage - Common setup for all environments
# ============================================
FROM node:20-alpine AS base

# Set working directory
WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Copy package files
COPY package*.json ./

# ============================================
# Dependencies Stage - Install all dependencies
# ============================================
FROM base AS dependencies

# Install ALL dependencies (including dev dependencies)
RUN npm ci

# ============================================
# Development Stage - For local development
# ============================================
FROM dependencies AS development

# Copy all source code
COPY . .

# Development environment
ENV NODE_ENV=development

# Expose ports
# 3000 for auth-server, 9229 for Node.js debugger
EXPOSE 3000 9229

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Development command with hot reload
CMD ["npm", "run", "dev"]

# ============================================
# Builder Stage - Compile TypeScript
# ============================================
FROM dependencies AS builder

# Copy TypeScript config and source code
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript to JavaScript
RUN npm run build

# ============================================
# Production Dependencies Stage - Smaller node_modules
# ============================================
FROM base AS prod-dependencies

# Install only production dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

# ============================================
# Test Stage - For running tests in CI/CD
# ============================================
FROM dependencies AS test

# Copy all source code and tests
COPY . .

# Set test environment
ENV NODE_ENV=test

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Test command
CMD ["npm", "test"]

# ============================================
# Production Stage - Optimized for production
# ============================================
FROM base AS production

# Copy only production dependencies
COPY --from=prod-dependencies /app/node_modules ./node_modules

# Copy compiled application
COPY --from=builder /app/dist ./dist

# Copy source files needed for scripts (setup-db uses tsx)
COPY --from=builder /app/src ./src
COPY tsconfig.json ./

# Copy package.json for metadata
COPY package*.json ./

# Production environment
ENV NODE_ENV=production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
# 3000 for auth-server, MCP server typically uses stdio
EXPOSE 3000

# Health check (adjust endpoint based on your implementation)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})" || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Production command
CMD ["npm", "start"]
