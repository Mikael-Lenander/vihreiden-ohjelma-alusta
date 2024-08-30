#!/bin/bash

docker-compose -f stack-dev.yml down
if [[ "$*" == *"--clean"* ]]
then
    bash clean-dev.sh
fi