#!/bin/sh
if [ "$ATOMIC_HTTPS" == "true" ]; then
    export ATOMIC_SERVER_URL="https://$ATOMIC_DOMAIN:$ATOMIC_PORT_HTTPS"
else
    export ATOMIC_SERVER_URL="http://$ATOMIC_DOMAIN:$ATOMIC_PORT"
fi

echo 'export const SERVER_URL = "'$ATOMIC_SERVER_URL'";' > /vihreat-ohjelmat/src/config.ts

pnpm install
pnpm start