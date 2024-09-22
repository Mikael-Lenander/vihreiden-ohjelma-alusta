import { Resource } from '@tomic/react';
import { Program } from '../ontologies/ontology';
import { Body } from './program/Body';
import { FrontMatter } from './program/FrontMatter';
import { Title } from './program/Title';
import { ProgramInfo } from '../model/ProgramInfo';
import { useProgramContent } from '../hooks/useProgramContent';
import type { ProgramContent } from '../model/ProgramContent';

interface ProgramViewProps {
  resource: Resource<Program>;
  highlight?: string;
}

export default function ProgramView({
  resource,
  highlight,
}: ProgramViewProps): JSX.Element {
  const info = new ProgramInfo(resource);
  const content = useProgramContent(resource.subject);

  return (
    <div className='vo-program-container'>
      <Title title={info.title ?? ''} subtitle={info.species} />
      <div className='vo-program-content'>
        <FrontMatter status={info.status} />
        <BodyOrLoading content={content} highlight={highlight} />
      </div>
    </div>
  );
}

interface BodyOrLoadingProps {
  content?: ProgramContent;
  highlight?: string;
}

function BodyOrLoading({
  content,
  highlight,
}: BodyOrLoadingProps): JSX.Element {
  if (content === undefined) {
    return <p>Ohjelman sisältöä ladataan...</p>;
  } else {
    return <Body content={content} highlight={highlight} />;
  }
}
