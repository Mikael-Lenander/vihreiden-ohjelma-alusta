#!/bin/bash
if [[ "$*" == *"--init"* ]]
then
    bash generate-json-ad.sh
    bash init-server-data.sh
    bash generate-ontologies.sh
fi
if [[ "$*" == *"--build"* ]]
then
    docker compose -f stack-dev.yml up --force-recreate
else
    docker compose -f stack-dev.yml up
fi
