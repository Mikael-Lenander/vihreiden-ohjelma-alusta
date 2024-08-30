#!/bin/bash

docker build . -f vihreat-data/atomic-ontologies.Dockerfile \
    --platform linux/amd64 \
    -t atomic-ontology-generator 
docker run \
    --platform linux/amd64 \
    -v "./atomic-storage:/atomic-storage" \
    -v "./vihreat-ohjelmat:/vihreat-ohjelmat" \
    --env-file dev.env \
    -p "9883:9883" \
    atomic-ontology-generator 