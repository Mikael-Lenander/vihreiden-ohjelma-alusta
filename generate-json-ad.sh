#!/bin/bash
rm -rf json-ad
mkdir -p json-ad

docker build . \
    --file     vihreat-data/generate-json-ad.Dockerfile \
    --platform linux/amd64 \
    --tag      generate-json-ad

docker run \
    --platform linux/amd64 \
    --volume   "./json-ad:/json-ad" \
    --env-file dev.env \
    generate-json-ad