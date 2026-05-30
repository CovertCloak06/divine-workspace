# Small, deploy-anywhere image for the poller (VPS, Fly.io, Pi, etc.).
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
# State is persisted here; mount a volume to keep it across restarts.
VOLUME /app/data
CMD ["node", "dist/index.js"]
