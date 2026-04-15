# Project: Sentinel-Patch
# Using an old, vulnerable image to trigger the engine
FROM node:20-alpine

WORKDIR /app
COPY . .

# Simulate an app install
RUN echo "Installing dependencies..."

EXPOSE 3000
CMD ["node", "index.js"]