import { useContext, useEffect, useRef } from 'react';
import Markdown from 'react-markdown';
import { Link } from 'react-router-dom';
import { ElementInfo } from '../../model/ElementInfo';
import { ProgramContent, TreeNode } from '../../model/ProgramContent';
import { ontology } from '../../ontologies/ontology';
import { HighlightContext } from '../ViewProgram';

interface BodyProps {
  content: ProgramContent;
  highlight?: string;
}

export function Body({ content }: BodyProps): JSX.Element {
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
      <RenderTreeNode node={content.tree} />
    </div>
  );
}

interface RenderTreeNodeProps {
  node: TreeNode;
}

function RenderTreeNode({ node }: RenderTreeNodeProps): JSX.Element {
  if (node.isActionList) {
    return (
      <ul>
        <RenderTreeNodeChildren children={node.children} />
      </ul>
    );
  } else if (node.element) {
    return (
      <>
        <InteractiveElement element={node.element} />
        <RenderTreeNodeChildren children={node.children} />
      </>
    );
  } else {
    return <RenderTreeNodeChildren children={node.children} />;
  }
}

interface ElementProps {
  element: ElementInfo;
}

function InteractiveElement({ element }: ElementProps): JSX.Element {
  const highlightState = useContext(HighlightContext);

  if (highlightState.index === element.index) {
    return (
      <Link to={`?h=${element.index}`} className='vo-program-element-a'>
        <div className='vo-program-element vo-program-element-highlight'>
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

function Element({ element }: ElementProps): JSX.Element {
  switch (element.elementClass) {
    case ontology.classes.paragraph:
      return <Paragraph element={element} />;
    case ontology.classes.heading:
      return <Heading element={element} />;
    case ontology.classes.actionitem:
      return <ActionItem element={element} />;
    default:
      return <></>;
  }
}

interface RenderTreeNodeChildrenProps {
  children: TreeNode[];
}

function RenderTreeNodeChildren({
  children,
}: RenderTreeNodeChildrenProps): JSX.Element {
  return (
    <>
      {children.map(node => (
        <RenderTreeNode node={node} />
      ))}
    </>
  );
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
  return <li>{element.name}</li>;
}
