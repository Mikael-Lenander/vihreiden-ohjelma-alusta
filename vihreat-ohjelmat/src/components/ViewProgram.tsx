import { useParams, useSearchParams, NavLink } from 'react-router-dom';
import { useEffect } from 'react';
import { useResource } from '@tomic/react';
import ProgramView from './ProgramView';
import { Program } from '../ontologies/ontology';

export function ViewProgram(): JSX.Element {
  const { pid } = useParams();
  const subject = `http://${window.location.hostname}:9883/ohjelmat/${pid}`;

  const resource = useResource<Program>(subject);

  const [searchParams, setSearchParams] = useSearchParams();
  var highlight = searchParams.get('h') || undefined;
  function setHighlight(h: string) {
    setSearchParams({'h': h});
  }
  useEffect(() => {
    highlight = searchParams.get('h') || undefined;
  }, [searchParams]);

  if (resource === undefined) {
    return (
      <>
        <BackButton />
        <p>Failed to load resource {subject}. Is the server running?</p>
      </>
    );
  } else {
    return (
      <>
        <BackButton />
        <ProgramView resource={resource} highlight={highlight} setHighlight={setHighlight} />;
      </>
    );
  }
}
export default ViewProgram;

function BackButton(): JSX.Element {
  return (
    <NavLink to='/' id='vo-back-button'>
      <span>&#x21E0; etusivulle</span>
    </NavLink>
  );
}
