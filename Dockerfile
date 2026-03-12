FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS backend-build
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci
COPY backend/ .
RUN npx tsc

FROM golang:1.23-alpine AS relay-build
WORKDIR /src
COPY relay/go.mod relay/go.sum ./
RUN go mod download
COPY relay/*.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /relay .

FROM node:20-alpine
WORKDIR /app
COPY --from=frontend-build /app/dist ./dist
COPY --from=backend-build /app/dist ./backend
COPY --from=backend-build /app/node_modules ./backend/node_modules
COPY --from=relay-build /relay /usr/local/bin/relay
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
