import { useRef, useEffect } from 'react';
import Markdown from 'react-markdown';
import { Link } from 'react-router-dom';
import { ElementInfo } from '../../model/ElementInfo';
import { ProgramContent } from '../../model/ProgramContent';
import { ontology } from '../../ontologies/ontology';

interface BodyProps {
  content: ProgramContent;
  highlight?: string;
}

export function Body({ content, highlight }: BodyProps): JSX.Element {
  const highlightRef = useRef<any>(null);

  useEffect(() => {
    if (highlightRef.current) {
      highlightRef.current.scrollIntoView({
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
      {content.elements.map(element => (
        <HighlightableElement
          element={element}
          key={element.subject}
          highlight={
            highlight && element.subject.endsWith('e' + highlight)
              ? highlightRef
              : undefined
          }
        />
      ))}
    </div>
  );
}

interface HighlightableElementProps {
  element: ElementInfo;
  highlight: any;
}

function HighlightableElement({
  element,
  highlight,
}: HighlightableElementProps): JSX.Element {
  if (highlight) {
    return (
      <Link to={`?h=${element.index}`} className='vo-program-element-a'>
        <div
          ref={highlight}
          className='vo-program-element vo-program-element-highlight'
        >
          <p className='vo-program-element-link'>&#x1F517;</p>
          <Element element={element} />
        </div>
      </Link>
    );
  } else {
    return (
      <Link to={`?h=${element.index}`} className='vo-program-element-a'>
        <div className='vo-program-element'>
          <p className='vo-program-element-link'>&#x1F517;</p>
          <Element element={element} />
        </div>
      </Link>
    );
  }
}

interface ElementProps {
  element: ElementInfo;
}

function Element({ element }: ElementProps): JSX.Element {
  switch (element.elementClass!) {
    case ontology.classes.paragraph:
      return <Paragraph element={element} />;
    case ontology.classes.heading:
      return <Heading element={element} />;
    case ontology.classes.actionitem:
      return <ActionItem element={element} />;
    default:
      return <Loading element={element} />;
  }
}

function Paragraph({ element }: ElementProps): JSX.Element {
  if (element.description !== undefined) {
    return <Markdown>{element.description}</Markdown>;
  } else {
    return (
      <p>
        <strong>Failed to get element text!</strong>
      </p>
    );
  }
}

function Heading({ element }: ElementProps): JSX.Element {
  switch (element.level) {
    case 1:
    default:
      return <h1>{element.name}</h1>;
    case 2:
      return <h2>{element.name}</h2>;
    case 3:
      return <h3>{element.name}</h3>;
    case 4:
      return <h4>{element.name}</h4>;
    case 5:
      return <h5>{element.name}</h5>;
    case 6:
      return <h6>{element.name}</h6>;
  }
}

function ActionItem({ element }: ElementProps): JSX.Element {
  return (
    <ul>
      <li>{element.name}</li>
    </ul>
  );
}

function Loading({ element }: ElementProps): JSX.Element {
  return (
    <p className='vo-cell-loading' title={element.subject}>
      sisältöä haetaan...
    </p>
  );
}
