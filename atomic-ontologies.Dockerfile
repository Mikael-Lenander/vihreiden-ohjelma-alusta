FROM joepmeneer/atomic-server:master AS atomic-ontology-generator
# Install Python 3
RUN apk add python3
RUN apk add nodejs
RUN apk add curl

# Install pnpm
RUN curl -L https://unpkg.com/@pnpm/self-installer | node

# Generate ontologies from data
COPY --chmod=755 ./vihreat-data/ /app/vihreat-data/
WORKDIR /app/vihreat-data
RUN mkdir -p src/ontologies
RUN pnpm install

VOLUME /vihreat-ohjelmat

ENTRYPOINT [ "sh", "/app/vihreat-data/generate-types.sh" ]
