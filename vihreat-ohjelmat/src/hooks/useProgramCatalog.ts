import { useEffect, useMemo, useState } from 'react';
import { useCollection, useStore, core } from '@tomic/react';
import { ProgramCatalog } from '../model/ProgramCatalog';
import { ontology } from '../ontologies/ontology';

export function useProgramCatalog(): ProgramCatalog {
  const store = useStore();

  const { collection } = useCollection({
    property: core.properties.isA,
    value: ontology.classes.program,
    sort_by: ontology.properties.approvedon,
    sort_desc: true,
  });

  const programs = useMemo(() => {
    return new ProgramCatalog();
  }, []);
  const [ready, setReady] = useState(false);

  const onReady = () => {
    setReady(true);
  };

  useEffect(() => {
    collection.getAllMembers().then(subjects => {
      programs.load(store, subjects, onReady);
    });
  }, []);

  return programs;
}
