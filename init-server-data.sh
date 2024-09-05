#!/bin/bash

rm -rf atomic-storage
mkdir -p atomic-storage

docker build . \
    --file     vihreat-data/init-server-data.Dockerfile \
    --platform linux/amd64 \
    --tag      init-server-data

docker run \
    --platform linux/amd64 \
    --volume   "./json-ad:/json-ad" \
    --volume   "./atomic-storage:/atomic-storage" \
    --env-file dev.env \
    init-server-data