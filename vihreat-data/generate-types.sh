#!/bin/bash
set -e

here=$(dirname $(realpath $0))

#python3 generate.py

# Start atomic-server in the background
source $here/with-atomic-server-in-background.sh

# Regenerate the .ts files describing our ontology
cd /app/vihreat-data
pnpm run generate-ontologies
cp src/ontologies/ontology.ts /vihreat-ohjelmat/src/ontologies/ontology.ts
cp src/ontologies/index.ts /vihreat-ohjelmat/src/ontologies/index.ts
cd /vihreat-ohjelmat
pnpm install
pnpm run lint-fix