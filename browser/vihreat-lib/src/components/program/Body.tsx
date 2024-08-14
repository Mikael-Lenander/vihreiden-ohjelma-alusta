import { core, useNumber, useResource, useString } from '@tomic/react';
import { ontology } from '../../ontologies/ontology';
import { useProgramClass } from '../../hooks';
import Markdown from 'react-markdown';

interface BodyProps {
  elements: string[];
}

export function Body({ elements }: BodyProps): JSX.Element {
  return (
    <div className='vo-program-body'>
      {elements.map(subject => (
        <Element subject={subject} key={subject} />
      ))}
    </div>
  );
}

interface ElementProps {
  subject: string;
}

function Element({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const klass = useProgramClass(resource);

  switch (klass!) {
    case ontology.classes.paragraph:
      return <Paragraph subject={subject} />;
    case ontology.classes.heading:
      return <Heading subject={subject} />;
    case ontology.classes.actionitem:
      return <ActionItem subject={subject} />;
    default:
      return <Loading subject={subject} />;
  }
}

function Paragraph({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.description);

  if (text !== undefined) {
    return <Markdown>{text}</Markdown>;
  } else {
    return (
      <p>
        <strong>Failed to get element text!</strong>
      </p>
    );
  }
}

function Heading({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.name);
  const [level] = useNumber(resource, ontology.properties.headinglevel);

  switch (level) {
    case 1:
    default:
      return <h1>{text}</h1>;
    case 2:
      return <h2>{text}</h2>;
    case 3:
      return <h3>{text}</h3>;
    case 4:
      return <h4>{text}</h4>;
    case 5:
      return <h5>{text}</h5>;
    case 6:
      return <h6>{text}</h6>;
  }
}

function ActionItem({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.name);

  return (
    <ul>
      <li>{text}</li>
    </ul>
  );
}

function Loading({ subject }: ElementProps): JSX.Element {
  return (
    <p className='vo-cell-loading' title={subject}>
      sisältöä haetaan...
    </p>
  );
}
