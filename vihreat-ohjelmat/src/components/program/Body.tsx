import { useState, useEffect, RefObject } from 'react';
import { core, useNumber, useResource, useString, useArray } from '@tomic/react';
import { ontology } from '../../ontologies/ontology';
import { useProgramClass } from '../../hooks';
import Markdown from 'react-markdown';

interface BodyProps {
  elements: string[];
  highlight?: string;
  setHighlight: Function;
}

export function Body({ elements, highlight, setHighlight }: BodyProps): JSX.Element {
  const [highlightRef, setHighlightRef] = useState<HTMLElement>();
  useEffect(() => {
    if (highlightRef) {
      highlightRef.scrollIntoView({
          behavior: 'instant',
          block: 'start',
          inline: 'nearest',
      });
    } else {
      window.scrollTo(0, 0);
    }
  }, [highlightRef]);

  return (
    <div className='vo-program-body'>
      {elements.map(subject => (
        <Element
          subject={subject}
          key={subject}
          highlight={highlight}
          setHighlight={setHighlight}
          setHighlightRef={setHighlightRef}
        />
      ))}
    </div>
  );
}

function getElementId(subject: string): string|undefined {
  return subject.split('/').pop()?.split('e').pop();
}
function isHighLighted(subject: string, highlight: string|undefined) {
  const elementId = getElementId(subject);
  return elementId == highlight;
}

function addHighlightProps(
  component: JSX.Element,
  subject: string,
  highlight: string|undefined,
  setHighlightRef: Function,
  setHighlight: Function) {
    const elementId = getElementId(subject);
    return <component.type
      {...component.props}
      ref={isHighLighted(subject, highlight) ? setHighlightRef : undefined}
      className={isHighLighted(subject, highlight) ? 'vo-program-element-highlight' : undefined}
      onClick={() => {setHighlight(elementId);}}
      style={{'cursor': 'pointer'}}/>;
}

interface ElementProps {
  subject: string;
  highlight?: string;
  setHighlight: Function;
  setHighlightRef: Function;
}

function Element({ subject, highlight, setHighlight, setHighlightRef }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const klass = useProgramClass(resource);

  const defaultProps = {
    subject: subject
  };

  switch (klass!) {
    case ontology.classes.paragraph:
      return addHighlightProps(<div className="vo-program-element"><Paragraph {...defaultProps} /></div>,
        subject, highlight, setHighlightRef, setHighlight);
    case ontology.classes.heading:
      return addHighlightProps(<div className="vo-program-element"><Heading {...defaultProps} /></div>,
        subject, highlight, setHighlightRef, setHighlight);
    case ontology.classes.actionitem:
      return <ActionItem {...defaultProps} />;
    case ontology.classes.actionlist:
      return <ActionList subject={subject} highlight={highlight} setHighlightRef={setHighlightRef} setHighlight={setHighlight} />
    default:
      return <Loading {...defaultProps} />;
  }
}

interface ComponentProps {
  subject: string;
}

function Paragraph({ subject }: ComponentProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.description);

  if (text !== undefined) {
    return <Markdown>{text}</Markdown>
  } else {
    return (
      <p>
        <strong>Failed to get element text!</strong>
      </p>
    );
  }
}

function Heading({ subject }: ComponentProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.name);
  const [level] = useNumber(resource, ontology.properties.headinglevel);

  switch (level) {
    case 1:
    default:
      return <h1>{text}</h1>
    case 2:
      return <h2>{text}</h2>
    case 3:
      return <h3>{text}</h3>
    case 4:
      return <h4>{text}</h4>
    case 5:
      return <h5>{text}</h5>
    case 6:
      return <h6>{text}</h6>
  }
}

function ActionList({ subject, highlight, setHighlight, setHighlightRef }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [elements] = useArray(resource, ontology.properties.elements);
  return (
    <ul>
      {
      elements.map(subject => (
        addHighlightProps(<div className="vo-program-element">
          <ActionItem subject={subject} key={subject} /></div>, subject, highlight, setHighlightRef, setHighlight)))
        }
    </ul>
  );
}

function ActionItem ({ subject }: ComponentProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, core.properties.description);

  return (<li>{text}</li>);
};

function Loading({ subject }: ComponentProps): JSX.Element {
  return (
    <p className='vo-cell-loading' title={subject}>
      sisältöä haetaan...
    </p>
  );
}
