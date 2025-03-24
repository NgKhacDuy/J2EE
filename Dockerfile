FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY . .

RUN npm install -g @nestjs/cli

RUN npm run build

FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

# Set environment variables
ENV DB_HOST=18.136.102.97
ENV DB_NAME=ecommerce
ENV DB_PORT=5432
ENV DB_USER=postgres
ENV DB_PASSWORD=postgresql

EXPOSE 3000

CMD [ "node", "dist/src/main.js" ]