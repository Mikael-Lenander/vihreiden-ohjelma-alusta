if [ "$ATOMIC_HTTPS" == "true" ]; then
    export ATOMIC_SERVER_URL="https://$ATOMIC_DOMAIN:$ATOMIC_PORT_HTTPS"
else
    export ATOMIC_SERVER_URL="http://$ATOMIC_DOMAIN:$ATOMIC_PORT"
fi
echo "Base URL: $ATOMIC_SERVER_URL"

export JSON_AD_DIR=/json-ad
python3 generate-json-ad.py
python3 bundle-programs.py