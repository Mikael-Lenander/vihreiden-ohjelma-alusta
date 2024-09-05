#!/bin/sh
if [ "$ATOMIC_HTTPS" == "true" ]; then
    export ATOMIC_SERVER_URL="https://$ATOMIC_DOMAIN:$ATOMIC_PORT_HTTPS"
else
    export ATOMIC_SERVER_URL="http://$ATOMIC_DOMAIN:$ATOMIC_PORT"
fi
echo "Base URL: $ATOMIC_SERVER_URL"

# Start atomic-server in the background
echo "Starting atomic-server in the background..."
/atomic-server-bin &
server_pid=$!

cleanup() {
    echo "Killing background job..."
    kill $server_pid
    sleep 2
}
trap cleanup EXIT

sleep 2

# Regenerate the .ts files describing our ontology
sed "s^ATOMIC_SERVER_URL^$ATOMIC_SERVER_URL^g" atomic.config.json.in > atomic.config.json
pnpm run generate-ontologies
cp src/ontologies/ontology.ts /vihreat-ohjelmat/src/ontologies/ontology.ts
cp src/ontologies/index.ts /vihreat-ohjelmat/src/ontologies/index.ts