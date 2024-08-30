#!/bin/bash
docker-compose -f stack-dev.yml down
rm -rf atomic-storage/*
docker rmi vihreat-ohjelmat-app-dev