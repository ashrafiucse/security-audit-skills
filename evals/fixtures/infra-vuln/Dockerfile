# Fixture: intentionally insecure container/infra files. FAKE data only.

# SEC-01: runs as root (no USER)
# SEC-02: untagged/latest base image
FROM node:latest

# SEC-03: secret baked into image layer (persists even if deleted later)
ENV DATABASE_URL=postgres://app:Fake4EvalsDoNotUse@db.internal.example.com/shop

WORKDIR /app
COPY . .
RUN curl -s https://get.example-example.com/install.sh | bash   # SEC-04: curl | sh
RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
