FROM python:3.10-alpine AS build-ontologies
# Generate ontologies
COPY ./vihreat-data/ /app/vihreat-data/
WORKDIR /app/vihreat-data
RUN python3 generate.py
RUN python3 bundle_programs.py

FROM joepmeneer/atomic-server:master AS atomic-server-initializer
COPY --from=build-ontologies /app/vihreat-data/ /vihreat-data/
WORKDIR /vihreat-data
RUN chmod 755 /vihreat-data/import-data.sh
VOLUME "/atomic-storage"
ENTRYPOINT ["/bin/sh", "/vihreat-data/import-data.sh"]