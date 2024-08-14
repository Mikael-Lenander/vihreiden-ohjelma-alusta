#!/bin/bash
set -e

root=$(dirname $(realpath $0))
data=$root/vihreat-data

# (Re)generate the JSONs
cd $data
python3 generate.py

# Make sure the server is up to date
cd $root
cargo build

# Wipe out existing database.
# The user will need to confirm with "y" (unless --force is specified).
# Fails if database does not exist in the first place, so we suppress failures here.
if [ "$1" = "--force" ]; then
    ./server.sh reset --force || true
else
    ./server.sh reset || true
fi

# Import bootstrap data
./server.sh import --file $data/json/ontology.json
for file in $data/json/p*.json
do 
    ./server.sh import --file $file
done

# Export
./server.sh export -p $data/json/debug_export.json

# Typescript types
$data/generate-types.sh