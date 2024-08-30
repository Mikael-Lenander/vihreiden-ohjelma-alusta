#!/bin/bash
docker-compose -f stack-prod.yml down
rm -rf atomic-storage/*
docker rmi vihreat-ohjelmat-app-prod