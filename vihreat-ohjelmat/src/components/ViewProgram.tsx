import {
  createContext,
  useEffect,
  useState,
  type MutableRefObject,
} from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { useResource } from '@tomic/react';
import ProgramView from './ProgramView';
import { Program } from '../ontologies/ontology';

export class HighlightState {
  public index?: number;
  public ref: MutableRefObject<HTMLDivElement | null>;

  public constructor() {
    this.index = undefined;
  }
}

export const HighlightContext = createContext(new HighlightState());

function useProgramUrl() {
  const { pid } = useParams();

  return `http://${window.location.hostname}:9883/ohjelmat/${pid}`;
}

function useHighlightState(): HighlightState {
  const [searchParams] = useSearchParams();
  const [highlightString, setHighlightString] = useState<string | undefined>(
    undefined,
  );
  useEffect(() => {
    setHighlightString(searchParams.get('h') || undefined);
  }, [searchParams]);
  const status = new HighlightState();

  if (highlightString !== undefined) {
    status.index = parseInt(highlightString);
  }

  return status;
}

export function ViewProgram(): JSX.Element {
  const subject = useProgramUrl();
  const highlightState = useHighlightState();

  return (
    <HighlightContext.Provider value={highlightState}>
      <BackButton />
      <ViewProgramImpl subject={subject} />
    </HighlightContext.Provider>
  );
}

interface ViewProgramImplProps {
  subject: string;
}

function ViewProgramImpl({ subject }: ViewProgramImplProps): JSX.Element {
  const resource = useResource<Program>(subject);

  if (resource === undefined) {
    return <p>Failed to load resource {subject}. Is the server running?</p>;
  } else {
    return <ProgramView resource={resource} />;
  }
}

function BackButton(): JSX.Element {
  return (
    <Link to='/' id='vo-back-button'>
      <span>&#x21E0; etusivulle</span>
    </Link>
  );
}
