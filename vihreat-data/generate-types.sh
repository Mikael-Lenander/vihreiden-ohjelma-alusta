# Generates typescript types for the ontology
set -e

here=$(dirname $(realpath $0))

cd $here/../browser/vihreat-lib
pnpm run generate-ontologies
pnpm run build