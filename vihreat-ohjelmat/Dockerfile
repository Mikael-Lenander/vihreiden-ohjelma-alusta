# Stage 1: build image
FROM node:22-alpine AS build-base

# Install pnpm with corepack
RUN corepack enable && corepack prepare pnpm@latest --activate
ENV PNPM_HOME=/usr/local/bin

# Set up vihreat-ohjelmat
COPY ./vihreat-ohjelmat/ /app/vihreat-ohjelmat/
WORKDIR /app/vihreat-ohjelmat
RUN pnpm install
RUN pnpm build

# Package dist in nginx
FROM nginx:mainline AS ohjelmat
COPY --from=build-base /app/vihreat-ohjelmat/dist/ /usr/share/nginx/html
EXPOSE 80