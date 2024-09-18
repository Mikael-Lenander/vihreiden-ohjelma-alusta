FROM node:22-alpine AS build-base

# Install pnpm with corepack
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@latest --activate
ENV PNPM_HOME=/usr/local/bin

WORKDIR /vihreat-ohjelmat

VOLUME /vihreat-ohjelmat
CMD [ "sh", "lint.sh" ]