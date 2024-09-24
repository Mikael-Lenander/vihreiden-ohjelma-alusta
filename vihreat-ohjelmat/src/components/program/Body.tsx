import {
  useContext,
  useEffect,
  useRef,
  useState,
  MutableRefObject,
} from 'react';
import Markdown from 'react-markdown';
import { useNavigate } from 'react-router-dom';
import { ElementInfo } from '../../model/ElementInfo';
import { ProgramContent, TreeNode } from '../../model/ProgramContent';
import { ontology } from '../../ontologies/ontology';
import { HighlightContext } from '../ViewProgram';
import { FocusContext } from '../ProgramView';

type NullableDiv = HTMLDivElement | null;
type NullableDivRef = MutableRefObject<NullableDiv>;

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
  const highlightRef = useRef<NullableDiv>(null);

  useEffect(() => {
    if (highlightRef.current) {
      scrollTo(highlightRef.current);
    }
  }, [highlightRef]);

  return (
    <div className='vo-program-body'>
      <RenderTreeNode node={content.tree} highlightRef={highlightRef} />
    </div>
  );
}

interface RenderTreeNodeProps {
  node: TreeNode;
  highlightRef: NullableDivRef;
}

function RenderTreeNode({
  node,
  highlightRef,
}: RenderTreeNodeProps): JSX.Element {
  if (node.isActionList) {
    return (
      <ul>
        <RenderTreeNodeChildren
          children={node.children}
          highlightRef={highlightRef}
        />
      </ul>
    );
  } else if (node.element) {
    return (
      <>
        <InteractiveElement
          element={node.element}
          highlightRef={highlightRef}
        />
        <RenderTreeNodeChildren
          children={node.children}
          highlightRef={highlightRef}
        />
      </>
    );
  } else {
    return (
      <RenderTreeNodeChildren
        children={node.children}
        highlightRef={highlightRef}
      />
    );
  }
}

interface ElementProps {
  element: ElementInfo;
  highlightRef?: NullableDivRef;
}

function InteractiveElement({
  element,
  highlightRef,
}: ElementProps): JSX.Element {
  const navigate = useNavigate();
  const highlightState = useContext(HighlightContext);
  const focusState = useContext(FocusContext);
  const [isFocused, setIsFocused] = useState(false);
  const focusUrl = `${window.location.origin}${location.pathname}?h=${element.index}`;

  const isHighlight = highlightState.index === element.index;

  const ref = isHighlight ? highlightRef : null;
  let className = 'vo-program-element';

  if (isHighlight) {
    className += ' vo-program-element-highlight';
  }

  if (isFocused) {
    className += ' vo-program-element-focused';
  }

  const focusThis = () => {
    focusState.set(setIsFocused);
  };

  const highlightThis = () => {
    navigate(`?h=${element.index}`, { replace: true });
  };

  const copyLinkToThis = () => {
    navigator.clipboard.writeText(focusUrl);
  };

  return (
    <div ref={ref} className={className} onMouseEnter={focusThis}>
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
  highlightRef: NullableDivRef;
}

function RenderTreeNodeChildren({
  children,
  highlightRef,
}: RenderTreeNodeChildrenProps): JSX.Element {
  return (
    <>
      {children.map(node => (
        <RenderTreeNode key={node.id} node={node} highlightRef={highlightRef} />
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
