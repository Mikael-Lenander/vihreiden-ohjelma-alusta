import Markdown from 'react-markdown';
import { useArray, useDate, useString, Resource } from '@tomic/react';
import { Program, ontology } from '../ontologies/ontology';
import { Body } from './program/Body';
import { FrontMatter } from './program/FrontMatter';
import { useStatusInfo } from './program/Status';
import { Title } from './program/Title';

interface ProgramViewProps {
  resource: Resource<Program>;
}

export function ProgramView({ resource }: ProgramViewProps): JSX.Element {
  const [title] = useString(resource, ontology.properties.title);
  const [subtitle] = useString(resource, ontology.properties.subtitle);
  const [elements] = useArray(resource, ontology.properties.elements);
  const status = useStatusInfo(resource);

  if (title !== undefined && elements !== undefined) {
    return (
      <div className='vo-container'>
        <DevBanner />
        <Title title={title} subtitle={subtitle} />
        <div className='vo-program-content'>
          <FrontMatter status={status} />
          <Body elements={elements} />
        </div>
      </div >
    );
  } else {
    return (
      <>
        <p>Failed to load resource {resource.subject}. Is the server running?</p>;
      </>
    );
  }
}

function DevBanner(): JSX.Element {
  return (
    <p className='vo-program-dev-banner'>
      ⚠ Sivusto on kehitysvaiheessa eikä sen sisältö välttämättä vastaa Vihreiden virallisia ohjelmia.
    </p>
    );
}