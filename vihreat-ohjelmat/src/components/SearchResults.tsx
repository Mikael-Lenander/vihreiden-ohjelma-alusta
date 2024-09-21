import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useResource, useServerSearch, useString, core } from '@tomic/react';
import { ontology } from '../ontologies/ontology';
import { useProgramClass } from '../hooks';
import Markdown from 'react-markdown';
import './Search.css';

export function Search(): JSX.Element {
  const [searchText, setSearchText] = useState('');

  return (
    <>
      <div id='vo-search-container'>
        <SearchHint />
        <search>
          <input
            id='vo-search-bar'
            type='text'
            placeholder='Kirjoita hakutermi, esim. ydinvoima, perustulo, biokaasu, ...'
            value={searchText}
            onChange={e => setSearchText(e.target.value)}
          />
        </search>
        {searchText ? <Result searchText={searchText} /> : <Idle />}
      </div>
    </>
  );
}
export default Search;

function SearchHint(): JSX.Element {
  return <p className='vo-search-hint'>Hae ohjelmateksteistä:</p>;
}

function Idle(): JSX.Element {
  return <></>;
}

function Loading(): JSX.Element {
  return <p className='vo-search-loading-msg'>Haetaan tuloksia...</p>;
}

interface ResultProps {
  searchText: string;
}

function Result({ searchText }: ResultProps): JSX.Element {
  const query = useServerSearch(searchText, {
    debounce: 200,
    include: true,
    limit: 100000,
    filters: {
      [core.properties.isA]: ontology.classes.programelement,
    },
  });

  if (query.loading) {
    return <Loading />;
  } else {
    return (
      <>
        <Count searchText={searchText} count={query.results.length} />
        <Results results={query.results} />
      </>
    );
  }
}

interface CountProps {
  searchText: string;
  count: number;
}

function Count({ count }: CountProps): JSX.Element {
  if (count <= 0) {
    return <p className='vo-search-summary-msg'>Ei löytynyt osumia.</p>;
  } else if (count === 1) {
    return <p className='vo-search-summary-msg'>Löytyi yksi osuma.</p>;
  } else {
    return <p className='vo-search-summary-msg'>Löytyi {count} osumaa.</p>;
  }
}

interface ResultsProps {
  results: string[];
}

function Results({ results }: ResultsProps): JSX.Element {
  return (
    <>
      {groupByProgram(results).map(e => (
        <FoundProgram
          key={e.program}
          program={e.program}
          elements={e.elements}
        />
      ))}
    </>
  );
}

interface FoundProgramProps {
  program: string;
  elements: string[];
}

function FoundProgram({ program, elements }: FoundProgramProps): JSX.Element {
  const resource = useResource(program);
  const id = program.split('/').pop();
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, ontology.properties.subtitle);

  return (
    <>
      <div className='vo-search-results-program'>
        <table className='vo-search-results-program-head'>
          <tr>
            haista vittu
            <td>{subtitle}</td>
            <td>{elements.length} osumaa</td>
          </tr>
          <tr>
            <td>
              <Link to={`/ohjelmat/${id}`}>{title}</Link>
            </td>
            <td>
              <a>&#9660;</a>
            </td>
          </tr>
        </table>
        {elements.map(subject => (
          <FoundElement key={subject} subject={subject} />
        ))}
      </div>
    </>
  );
}

interface FoundElementProps {
  subject: string;
}

export function FoundElement({ subject }: FoundElementProps) {
  const resource = useResource(subject);
  const programId = getProgramId(subject);
  const elementId = getProgramElementId(subject);
  const elementClass = useProgramClass(resource);
  const [text] = useString(resource, core.properties.description);
  const [name] = useString(resource, core.properties.name);

  return (
    <>
      <div className='vo-search-results-element'>
        <SearchResultElementHead
          programId={programId}
          elementId={elementId}
          elementClass={elementClass}
        />
        <SearchResultElementBody
          text={text}
          name={name}
          elementClass={elementClass}
        />
      </div>
    </>
  );
}

interface SearchResultsElementHeadProps {
  programId: string;
  elementId: string;
  elementClass?: string;
}

export function SearchResultElementHead({
  programId,
  elementId,
  elementClass,
}: SearchResultsElementHeadProps): JSX.Element {
  let inessiivi = 'tuntemattomassa alkiossa';

  switch (elementClass) {
    case ontology.classes.paragraph:
      inessiivi = 'tekstikappaleessa';
      break;
    case ontology.classes.heading:
      inessiivi = 'otsikossa';
      break;
    case ontology.classes.actionitem:
      inessiivi = 'linjauksessa';
      break;
  }

  return (
    <p>
      Osuma{' '}
      <Link to={`/ohjelmat/p${programId}#e${elementId}`}>
        {inessiivi} #{elementId}
      </Link>
    </p>
  );
}

interface SearchResultsElementBodyProps {
  text?: string;
  name?: string;
  elementClass?: string;
}

export function SearchResultElementBody({
  text,
  name,
  elementClass,
}: SearchResultsElementBodyProps): JSX.Element {
  switch (elementClass) {
    case ontology.classes.paragraph:
      return <Markdown>{text}</Markdown>;
    case ontology.classes.heading:
      return <h3>{name}</h3>;
    case ontology.classes.actionitem:
      return (
        <p>
          <ul>
            <li>{name}</li>
          </ul>
        </p>
      );
    default:
      return (
        <p>
          {name}
          {text}
        </p>
      );
  }
}

function parentProgramSubject(subject: string) {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'e') {
      return subject.substring(0, i);
    }

    if (subject[i] === '/') {
      return subject;
    }
  }

  return subject;
}

function getProgramId(subject: string): string {
  subject = parentProgramSubject(subject);

  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'p') {
      return subject.substring(i + 1, subject.length);
    }

    if (subject[i] === '/') {
      return '';
    }
  }

  return '';
}

function getProgramElementId(subject: string): string {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'e') {
      return subject.substring(i + 1, subject.length);
    }

    if (subject[i] === '/') {
      return '';
    }
  }

  return '';
}

function isInteger(id: string): boolean {
  for (let i = 0; i < id.length; ++i) {
    if (!'0123456789'.includes(id[i])) {
      return false;
    }
  }

  return true;
}

function groupByProgram(src: string[]): FoundProgramProps[] {
  const programs: string[] = [];
  const byProgram = {};
  src.forEach(element => {
    const programSubject = parentProgramSubject(element);
    const programId = getProgramId(programSubject);

    if (isInteger(programId)) {
      if (!(programSubject in byProgram)) {
        byProgram[programSubject] = [];
        programs.push(programSubject);
      }

      byProgram[programSubject].push(element);
    }
  });
  programs.sort();
  programs.reverse();

  return programs.map(p => ({ program: p, elements: byProgram[p] }));
}
