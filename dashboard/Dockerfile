FROM node:24-alpine AS build

WORKDIR /app/dashboard
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

ENV NODE_ENV=production
USER node
EXPOSE 3000
CMD ["npm", "run", "start", "--", "--port", "3000"]
