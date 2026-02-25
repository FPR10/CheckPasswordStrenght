# ── Stage 1: build Angular ───────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json .
RUN npm install

COPY . .
RUN npm run build

# ── Stage 2: serve con Nginx ─────────────────────────────────────────────────
FROM nginx:alpine

# Angular 17 emette in dist/<project-name>/browser
COPY --from=builder /app/dist/password-analyzer/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]