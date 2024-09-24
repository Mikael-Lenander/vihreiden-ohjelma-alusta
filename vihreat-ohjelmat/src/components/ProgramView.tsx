import { createContext } from 'react';
import { Resource } from '@tomic/react';
import { Program } from '../ontologies/ontology';
import { Body } from './program/Body';
import { FrontMatter } from './program/FrontMatter';
import { Title } from './program/Title';
import { ProgramInfo } from '../model/ProgramInfo';
import { useProgramContent } from '../hooks/useProgramContent';
import type { ProgramContent } from '../model/ProgramContent';

export class FocusState {
  private setIsFocused: (boolean) => void;

  public constructor() {
    this.setIsFocused = () => {};
  }

  public set(f: (boolean) => void) {
    this.setIsFocused(false);
    this.setIsFocused = f;
    this.setIsFocused(true);
  }
}

export const FocusContext = createContext(new FocusState());

interface ProgramViewProps {
  resource: Resource<Program>;
}

export default function ProgramView({
  resource,
}: ProgramViewProps): JSX.Element {
  const info = new ProgramInfo(resource);
  const content = useProgramContent(resource.subject);

  return (
    <FocusContext.Provider value={new FocusState()}>
      <div className='vo-program-container'>
        <Title title={info.title ?? ''} subtitle={info.species} />
        <div className='vo-program-content'>
          <FrontMatter status={info.status} />
          <BodyOrLoading content={content} />
        </div>
      </div>
    </FocusContext.Provider>
  );
}

interface BodyOrLoadingProps {
  content?: ProgramContent;
}

function BodyOrLoading({ content }: BodyOrLoadingProps): JSX.Element {
  if (content === undefined) {
    return <p>Ohjelman sisältöä ladataan...</p>;
  } else {
    return <Body content={content} />;
  }
}
