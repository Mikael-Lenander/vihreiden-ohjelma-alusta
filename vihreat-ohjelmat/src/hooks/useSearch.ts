import { useEffect, useRef, useState } from 'react';
import { useStore, core } from '@tomic/react';
import { SearchResults } from '../model/SearchResults';
import { ontology } from '../ontologies/ontology';

export function useSearch(q: string): SearchResults | undefined {
  const store = useStore();

  const searchOpts = {
    debounce: 1000,
    include: true,
    limit: 100000,
    filters: {
      [core.properties.isA]: ontology.classes.programelement,
    },
  };

  const [result, setResult] = useState<SearchResults | undefined>(undefined);
  const currentQueryIndexRef = useRef(0);

  useEffect(() => {
    const thisQueryId = ++currentQueryIndexRef.current;
    setResult(undefined);
    store.search(q, searchOpts).then(elements => {
      if (thisQueryId === currentQueryIndexRef.current) {
        const results = new SearchResults();
        results.load(store, elements!, () => {
          results.restrictToExact(q);
          setResult(results);
        });
      }
    });
  }, [q]);

  return result;
}
