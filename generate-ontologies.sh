#!/bin/bash

docker build . \
    --file     vihreat-data/generate-ontologies.Dockerfile \
    --platform linux/amd64 \
    --tag      generate-ontologies

docker run \
    --platform linux/amd64 \
    --volume   "./atomic-storage:/atomic-storage" \
    --volume   "./vihreat-ohjelmat:/vihreat-ohjelmat" \
    --publish  "9883:9883" \
    --env-file dev.env \
    generate-ontologies

bash lint-vihreat-ohjelmat.sh
