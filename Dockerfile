# Project: Sentinel-Patch Enterprise Service
# Vulnerable Base: node:14.15.0 (Triggers the Sentinel Engine)
FROM node:14.15.0

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# In a real project, we would copy package.json first to cache layers
COPY package*.json ./
RUN npm install --only=production

# Bundle app source (The new enterprise structure)
COPY . .

# Security Note: Application should run as non-root user in production
# USER node 

EXPOSE 8080

# Entry point for the service
CMD [ "node", "src/api/server.js" ]