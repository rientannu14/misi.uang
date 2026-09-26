FROM node:22.13.0-bookworm-slim
WORKDIR /app
COPY package.json ./
COPY . .
ENV NODE_ENV=production
CMD ["npm","start"]
