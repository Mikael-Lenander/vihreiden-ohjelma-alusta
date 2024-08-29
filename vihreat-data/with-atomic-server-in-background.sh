#!/bin/bash
set -e

here=$(dirname $(realpath $0))

echo "Starting atomic-server in the background..."
cd $here/..
/atomic-server-bin &
server_pid=$!
echo "Server started with pid $server_pid"

cleanup() {
    echo "Killing background job..."
    kill $server_pid
    sleep 2
}
trap cleanup EXIT

sleep 2