#!/bin/sh

echo "Importing ontologies"
/atomic-server-bin import --file /json-ad/ontology.json

echo "Importing programs"
/atomic-server-bin import --file /json-ad/all_programs.json

echo "Exporting data dump (for debugging)"
/atomic-server-bin export -p /json-ad/export.json
