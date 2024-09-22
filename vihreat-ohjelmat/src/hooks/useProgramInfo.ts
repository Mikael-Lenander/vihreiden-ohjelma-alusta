import { useState } from 'react';
import { useStore } from '@tomic/react';
import { ProgramInfo } from '../model/ProgramInfo';

export function useProgramInfo(subject: string): ProgramInfo | undefined {
  const store = useStore();
  const [result, setResult] = useState<ProgramInfo | undefined>(undefined);
  store.getResource(subject).then((resource) => {
    setResult(new ProgramInfo(resource));
  })
  return result;
}
