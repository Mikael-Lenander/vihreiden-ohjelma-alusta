import { useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { ProgramContent } from '../model/ProgramContent';
import { ontology } from '../ontologies/ontology';

export function useProgramContent(subject: string): ProgramContent | undefined {
  const store = useStore();
  const [result, setResult] = useState<ProgramContent | undefined>(undefined);
  useEffect(() => {
    store.getResource(subject).then(resource => {
      const content = new ProgramContent();
      const elements = resource.get(ontology.properties.elements);

      if (elements !== undefined) {
        content.load(store, elements, () => {
          setResult(content);
        });
      }
    });
  }, [subject]);

  return result;
}
