#!/bin/bash
mkdir -p atomic-storage

docker build . \
    -f vihreat-data/atomic-initializer.Dockerfile \
    --platform linux/amd64  \
    -t atomic-server-initializer
docker run \
    --platform linux/amd64 \
    -v "./atomic-storage:/atomic-storage" \
    -p "9883:9883" \
    --env-file dev.env \
    atomic-server-initializer 