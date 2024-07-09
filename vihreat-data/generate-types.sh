# Generates typescript types for the ontology
set -e

current_dir=$(pwd)

cd $current_dir/browser/vihreat-lib
npx ad-generate ontologies
pnpm run build