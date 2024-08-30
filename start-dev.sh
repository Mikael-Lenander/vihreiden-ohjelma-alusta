#!/bin/bash
if [[ "$*" == *"--init"* ]]
then
    bash initialize-server.sh
fi
if [[ "$*" == *"--build"* ]]
then
    docker-compose -f stack-dev.yml up --force-recreate
else
    docker-compose -f stack-dev.yml up
fi
