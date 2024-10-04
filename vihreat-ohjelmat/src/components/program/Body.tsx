import { useContext, useEffect, useRef, useState } from 'react';
import Markdown from 'react-markdown';
import { useNavigate } from 'react-router-dom';
import { ElementInfo } from '../../model/ElementInfo';
import { ProgramContent, TreeNode } from '../../model/ProgramContent';
import { ontology } from '../../ontologies/ontology';
import { HighlightContext } from '../ViewProgram';
import { FocusContext } from '../ProgramView';

interface BodyProps {
  content: ProgramContent;
}

function scrollTo(element?: HTMLElement) {
  if (element) {
    element.scrollIntoView({
      behavior: 'smooth',
      block: 'center',
      inline: 'center',
    });
  }
}

export function Body({ content }: BodyProps): JSX.Element {
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
  const navigate = useNavigate();
  const highlightState = useContext(HighlightContext);
  const focusUrl = `${window.location.origin}${location.pathname}?h=${element.index}`;
  const ref = useRef<HTMLDivElement | null>(null);
  const isHighlighted = highlightState.index === element.index;
  if (isHighlighted) {
    console.log(`Highlighted ${element.index}`)
  }

  const focusState = useContext(FocusContext);
  const [isFocused, setIsFocused] = useState(false);
  useEffect(() => {
    setIsFocused(false);
  }, [focusState]);

  let className = 'vo-program-element';

  if (isHighlighted) {
    className += ' vo-program-element-highlight';
  }

  if (isFocused) {
    className += ' vo-program-element-focused';
  }

  const focusThis = () => {
    focusState.set(setIsFocused);
  };

  const highlightThis = () => {
    setIsFocused(false);
    scrollTo(ref.current || undefined);
    navigate(`?h=${element.index}`, { replace: true });
  };

  const copyLinkToThis = () => {
    navigator.clipboard.writeText(focusUrl);
  };

  useEffect(() => {
    if (isHighlighted) {
      scrollTo(ref.current || undefined);
    }
  }, [isHighlighted]);

  return (
    <div ref={ref} className={className} onMouseEnter={focusThis}>
      <div className='vo-program-element-aura' onMouseEnter={focusThis}></div>
      <Element element={element} />
      {isFocused ? (
        <div className='vo-program-element-buttons'>
          <ElementButton title='Korosta tämä teksti' onClick={highlightThis}>
            &#x1F58D;
          </ElementButton>
          <ElementButton
            title='Kopioi linkki tähän tekstiin'
            onClick={copyLinkToThis}
          >
            &#x1F517;
          </ElementButton>
        </div>
      ) : (
        <></>
      )}
    </div>
  );
}

interface ElementButtonProps {
  children: React.ReactNode;
  title: string;
  onClick: () => void;
}

function ElementButton({
  children,
  title,
  onClick,
}: ElementButtonProps): JSX.Element {
  return (
    <button
      className='vo-program-element-button'
      title={title}
      onClick={onClick}
    >
      {children}
    </button>
  );
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
        <RenderTreeNode key={node.id} node={node} />
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
