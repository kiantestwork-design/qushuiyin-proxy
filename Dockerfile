FROM node:20-alpine
WORKDIR /app
COPY . .
EXPOSE 80
CMD ["node", "server.js"]
