#!/bin/bash

docker build . \
    -f ./vihreat-ohjelmat/lint.Dockerfile \
    --platform linux/amd64 \
    -t vihreat-ohjelmat-lint 
docker run \
    --platform linux/amd64 \
    -v "./vihreat-ohjelmat:/vihreat-ohjelmat" \
    -t vihreat-ohjelmat-lint