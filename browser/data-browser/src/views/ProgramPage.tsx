import * as React from 'react';
import { useArray, useString, useDate, useResource } from '@tomic/react';

import { ResourcePageProps } from './ResourcePage';
import Markdown from '../components/datatypes/Markdown';

const elementsProp = "http://localhost:9883/o/elements";
const titleProp = "http://localhost:9883/o/title";
const textProp = "http://localhost:9883/o/text";
const approvedOnProp = "http://localhost:9883/o/approvedOn";

interface ElementProps {
  subject: string;
}

export function Element({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, textProp);
  return (
    <>
      <Markdown text={text || ''} />
    </>
  );
}

export function ProgramPage({ resource }: ResourcePageProps): JSX.Element {
  const [elements] = useArray(resource, elementsProp);
  const [title] = useString(resource, titleProp);
  const approvedOn = useDate(resource, approvedOnProp);

  return (
    <div className='vihreat-ohjelma'>
      <h1 className='vihreat-otsikko'>{title}</h1>
      {
        (approvedOn) ?
          <p>Hyväksytty {approvedOn!.toLocaleString('fi-FI', { year: 'numeric', month: 'long', day: 'numeric' })}</p> : ""
      }
      {elements.map(subject => (
        <Element subject={subject} key={subject} />
      ))}
    </div>
  );
}

export default ProgramPage;
