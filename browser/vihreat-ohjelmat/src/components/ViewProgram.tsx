import { useParams, NavLink } from 'react-router-dom';
import { useResource } from '@tomic/react';
import { ProgramView, Program } from 'vihreat-lib';

export function ViewProgram(): JSX.Element {
  const { id } = useParams();
  const subject = `http://${window.location.hostname}:9883/ohjelmat/${id}`;

  const resource = useResource<Program>(subject);

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
        <ProgramView resource={resource} />;
      </>
    );
  }
}
export default ViewProgram;

function BackButton(): JSX.Element {
  return (
    <NavLink to='/' id='vo-back-button'>
      <span>&#x2190; ohjelmien etusivulle</span>
    </NavLink>
  );
}