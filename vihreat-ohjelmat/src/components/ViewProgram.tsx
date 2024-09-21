import { useParams, useSearchParams, Link } from 'react-router-dom';
import { useResource } from '@tomic/react';
import ProgramView from './ProgramView';
import { Program } from '../ontologies/ontology';

export function ViewProgram(): JSX.Element {
  const { pid } = useParams();
  const subject = `http://${window.location.hostname}:9883/ohjelmat/${pid}`;

  const resource = useResource<Program>(subject);

  const [searchParams] = useSearchParams();
  const highlight = searchParams.get('h') || undefined;

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
        <ProgramView resource={resource} highlight={highlight} />;
      </>
    );
  }
}
export default ViewProgram;

function BackButton(): JSX.Element {
  return (
    <Link to='/' id='vo-back-button'>
      <span>&#x21E0; etusivulle</span>
    </Link>
  );
}
