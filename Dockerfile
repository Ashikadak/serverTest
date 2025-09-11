# Use Node 20 LTS and npm
FROM node:20-alpine

WORKDIR /app

# Install dependencies using npm
COPY package.json package-lock.json* ./
RUN npm ci || npm install --production

# Copy source
COPY src ./src

# Environment
ENV NODE_ENV=production

# Expose the default port (app still reads PORT from env)
EXPOSE 4000

# Start the server
CMD ["node", "src/index.js"]







