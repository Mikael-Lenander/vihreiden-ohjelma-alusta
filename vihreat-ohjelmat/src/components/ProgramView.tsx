import { useArray, useString, Resource, core } from '@tomic/react';
import { Program, ontology } from '../ontologies/ontology';
import { Body } from './program/Body';
import { FrontMatter } from './program/FrontMatter';
import { useStatusInfo } from './program/Status';
import { Title } from './program/Title';

interface ProgramViewProps {
  resource: Resource<Program>;
  highlight: string|undefined;
  setHighlight: Function;
}

export default function ProgramView({
  resource,
  highlight,
  setHighlight
}: ProgramViewProps): JSX.Element {
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, ontology.properties.subtitle);
  const [elements] = useArray(resource, ontology.properties.elements);
  const status = useStatusInfo(resource);

  if (title !== undefined && elements !== undefined) {
    return (
      <div className='vo-program-container'>
        <Title title={title} subtitle={subtitle} />
        <div className='vo-program-content'>
          <FrontMatter status={status} />
          <Body elements={elements} highlight={highlight} setHighlight={setHighlight} />
        </div>
      </div>
    );
  } else {
    return (
      <>
        <p>
          Failed to load resource {resource.subject}. Is the server running?
        </p>
        ;
      </>
    );
  }
}
