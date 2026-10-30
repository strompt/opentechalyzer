FROM node:22-bookworm-slim
WORKDIR /app

# Chromium requires glibc and OS browser dependencies (not Alpine).
COPY package*.json ./
RUN npm ci --no-audit --no-fund \
    && npm install --no-save --no-audit --no-fund playwright@1.64.1 \
    && npx playwright install --with-deps chromium

COPY . .
RUN npm run build

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
CMD ["node", "dist/mcp.js", "--http", "--host", "0.0.0.0", "--port", "3000"]
