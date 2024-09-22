import { useEffect, useState } from 'react';
import { useCollection, useStore, core } from '@tomic/react';
import { ProgramCatalog } from '../model/ProgramCatalog';
import { ontology } from '../ontologies/ontology';

export function useProgramCatalog(): ProgramCatalog | undefined {
  const store = useStore();

  const { collection } = useCollection({
    property: core.properties.isA,
    value: ontology.classes.program,
    sort_by: ontology.properties.approvedon,
    sort_desc: true,
  });

  const [result, setResult] = useState<ProgramCatalog | undefined>(undefined);
  useEffect(() => {
    const programs = new ProgramCatalog();
    collection.getAllMembers().then(subjects => {
      programs.load(store, subjects, () => {
        setResult(programs);
      });
    });
  }, []);

  return result;
}
