import { useState } from 'react';
import { usePrograms, ProgramInfo } from './usePrograms';
import { ProgramCard } from './ProgramCard';

export function Browse(): JSX.Element {
  const programs = usePrograms();
  const [expandRetired, setExpandRetired] = useState(false);

  if (programs === undefined) {
    return <Loading />;
  } else {
    return (
      <>
        <HeadlineProgramsHead />
        <div className='vo-browse'>
          {programs.headlinePrograms.map(p => (
            <Card key={p.subject} program={p} />
          ))}
        </div>
        <ThematicProgramsHead />
        <div className='vo-browse'>
          {programs.thematicPrograms.map(p => (
            <Card key={p.subject} program={p} />
          ))}
        </div>
        <OpenersHead />
        <div className='vo-browse'>
          {programs.openers.map(p => (
            <Card key={p.subject} program={p} />
          ))}
        </div>
        <RetiredProgramsHead
          expand={expandRetired}
          setExpand={setExpandRetired}
        />
        {expandRetired ? (
          <div className='vo-browse' id='vo-browse-retired'>
            {programs.retiredPrograms.map(p => (
              <Card key={p.subject} program={p} />
            ))}
          </div>
        ) : (
          <></>
        )}
      </>
    );
  }
}
export default Browse;

function HeadlineProgramsHead(): JSX.Element {
  return <p className='vo-browse-all-hint'>Voimassa olevat ohjelmat</p>;
}

function ThematicProgramsHead(): JSX.Element {
  return <p className='vo-browse-sector-hint'>Teemaohjelmat</p>;
}

function OpenersHead(): JSX.Element {
  return <p className='vo-browse-sector-hint'>Avaukset</p>;
}

interface RetiredProgramsHeadProps {
  expand: boolean;
  setExpand: (boolean) => void;
}

function RetiredProgramsHead({
  expand,
  setExpand,
}: RetiredProgramsHeadProps): JSX.Element {
  if (expand) {
    return (
      <button
        className='vo-browse-retired-hint'
        onClick={() => setExpand(false)}
      >
        &#x2191;&#x2191; piilota vanhentuneet ohjelmat &#x2191;&#x2191;
      </button>
    );
  } else {
    return (
      <button
        className='vo-browse-retired-hint'
        onClick={() => setExpand(true)}
      >
        &#x2193;&#x2193; näytä vanhentuneet ohjelmat &#x2193;&#x2193;
      </button>
    );
  }
}

function Loading(): JSX.Element {
  return <p className='vo-browse-loading-msg'>Haetaan ohjelmia...</p>;
}

interface CardProps {
  program: ProgramInfo;
}

function Card({ program }: CardProps): JSX.Element {
  return (
    <ProgramCard
      linkPath={program.linkPath}
      title={program.title}
      subtitle={program.species}
      status={program.status}
    />
  );
}
