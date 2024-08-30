FROM node:22-alpine

# Install pnpm with corepack
RUN corepack enable && corepack prepare pnpm@latest --activate
ENV PNPM_HOME=/usr/local/bin

# Set up vihreat-ohjelmat and start watching
WORKDIR /vihreat-ohjelmat
COPY ./vihreat-ohjelmat/dev-entrypoint.sh /

EXPOSE 5176
VOLUME "/vihreat-ohjelmat"
ENTRYPOINT ["sh", "/dev-entrypoint.sh"]

