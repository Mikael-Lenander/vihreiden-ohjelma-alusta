#!/bin/sh
echo "Importing ontologies"
/atomic-server-bin import --file /vihreat-data/json/ontology.json
echo "Importing programs"
/atomic-server-bin import --file /vihreat-data/json/all_programs.json

rm -r /vihreat-data
