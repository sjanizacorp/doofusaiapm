# ── DoofusAI SPM — API + Engine ───────────────────────────────────────────────
# Multi-stage build: builder installs deps, runner is the lean production image.
# Uses Node 20 LTS (Alpine) — sql.js is pure JS, no native compilation needed.

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for layer caching
COPY package.json ./
COPY api/package.json ./api/

# Install all dependencies (root package.json has everything engine+api needs)
RUN npm install --omit=dev --silent

# Copy source
COPY engine/ ./engine/
COPY api/    ./api/

# ── Stage 2: production runtime ───────────────────────────────────────────────
FROM node:20-alpine AS runner

# Security: run as non-root
RUN addgroup -S doofusai && adduser -S doofusai -G doofusai

WORKDIR /app

# Copy built deps and source from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/engine       ./engine
COPY --from=builder /app/api          ./api

# Data directory for SQLite database
RUN mkdir -p /app/data && chown doofusai:doofusai /app/data

# Custom policies directory (user can mount their own)
RUN mkdir -p /app/engine/custom-policies && chown doofusai:doofusai /app/engine/custom-policies

USER doofusai

EXPOSE 3001

ENV NODE_ENV=production
ENV PORT=3001
ENV DB_PATH=/app/data/doofusai.db

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3001/api/v1/health || exit 1

CMD ["node", "api/server.js"]
