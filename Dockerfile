FROM oven/bun:1.3.11-alpine

WORKDIR /app

# --ignore-scripts skips the "prepare" script (husky), a dev-only git hook setup.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production --ignore-scripts

COPY tsconfig.json openapi.yaml ./
COPY src ./src
# For `docker compose exec auth bun run reset-mfa <email>`.
COPY scripts/reset-mfa.ts ./scripts/

# The SQLite database lives in /data, mounted as a volume by compose.yaml.
RUN mkdir /data && chown bun:bun /data

USER bun
EXPOSE 4000
CMD ["bun", "src/app.ts"]
