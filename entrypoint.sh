#!/bin/sh
# Start relay on 8081 (relay defaults to 8080, override to avoid conflict with backend)
relay -addr :8081 &

# Start Node.js backend on 8080 (serves frontend + API, proxies /ws to relay:8081)
node backend/server.js
