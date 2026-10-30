FROM node:22-bookworm-slim
WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --no-audit --no-fund && npm install --no-save --no-audit --no-fund playwright && npx playwright install --with-deps chromium
COPY . .
RUN npm run build
ENV NODE_ENV=production PORT=3000 OPENTECHALYZER_DB_PATH=/data/opentechalyzer/external-db.json OPENTECHALYZER_TRANCO_PATH=/data/opentechalyzer/tranco.json
RUN mkdir -p /data/opentechalyzer && chown -R node:node /data/opentechalyzer /app /ms-playwright
USER node
EXPOSE 3000
CMD ["node", "dist/mcp.js", "--http", "--host", "0.0.0.0", "--port", "3000"]
