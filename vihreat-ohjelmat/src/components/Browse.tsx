import { Collection } from '@tomic/lib';
import {
  useResource,
  useString,
  core,
} from '@tomic/react';
import { useStatusInfo } from './program/Status';
import { usePrograms, Program } from './usePrograms';
import { ontology } from '../ontologies/ontology';
import { ProgramCard } from './ProgramCard';

export function Browse(): JSX.Element {
  const programs = usePrograms();

  if (!programs.ready) {
    return <Loading />;
  } else {
    return (
      <>
        <BrowseHint />
        <div className='vo-browse'>
          {programs.active.map(p => (
            <Card
              key={p.subject}
              program={p}
            />
          ))}
        </div>
      </>
    );
  }
}
export default Browse;

function BrowseHint(): JSX.Element {
  return <p className='vo-browse-hint'>Kaikki ohjelmat</p>;
}

function Loading(): JSX.Element {
  return <p className='vo-browse-loading-msg'>Haetaan ohjelmia...</p>;
}

interface CardProps {
  program: Program;
}

function Card({ program }: CardProps): JSX.Element {
  return (
    <ProgramCard
      linkPath={program.linkPath}
      title={program.title}
      subtitle={program.subtitle}
      status={program.status}
    />
  );
}
