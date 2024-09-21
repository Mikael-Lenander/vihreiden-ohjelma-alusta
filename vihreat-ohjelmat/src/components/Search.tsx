import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  useArray,
  useResource,
  useServerSearch,
  useString,
  core,
} from '@tomic/react';
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
        <SearchBar value={searchText} setValue={setSearchText} />
        {searchText ? <SearchResults searchText={searchText} /> : <Idle />}
      </div>
    </>
  );
}
export default Search;

interface SearchBarProps {
  value: string;
  setValue: (string) => void;
}

function SearchBar({ value, setValue }: SearchBarProps): JSX.Element {
  return (
    <search>
      <input
        id='vo-search-bar'
        type='search'
        placeholder='Kirjoita hakutermi, esim. ydinvoima, perustulo, biokaasu, ...'
        value={value}
        onChange={e => setValue(e.target.value)}
      />
    </search>
  );
}

function SearchHint(): JSX.Element {
  return <p className='vo-search-hint'>Hae ohjelmateksteistä:</p>;
}

function Idle(): JSX.Element {
  return <></>;
}

interface SearchResultsProps {
  searchText: string;
}

function SearchResults({ searchText }: SearchResultsProps): JSX.Element {
  const query = useServerSearch(searchText, {
    debounce: 1000,
    include: true,
    limit: 100000,
    filters: {
      [core.properties.isA]: ontology.classes.programelement,
    },
  });

  if (query.loading) {
    return <Loading />;
  } else if (query.results.length === 0) {
    return <NoResultsFound />;
  } else {
    return (
      <div id='vo-search-results-container'>
        {groupByProgram(query.results).map(e => {
          return (
            <FoundProgram key={e.program} program={e.program} hits={e.hits} />
          );
        })}
      </div>
    );
  }
}

function Loading(): JSX.Element {
  return <p className='vo-search-loading-msg'>Haetaan tuloksia...</p>;
}

function NoResultsFound(): JSX.Element {
  return <p className='vo-search-no-results-msg'>Ei tuloksia.</p>;
}

interface FoundProgramProps {
  program: string;
  hits: string[];
}

function FoundProgram({ program, hits }: FoundProgramProps): JSX.Element {
  const resource = useResource(program);
  const id = program.split('/').pop();
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, ontology.properties.subtitle);
  const [elements] = useArray(resource, ontology.properties.elements);
  const [expand, setExpand] = useState(false);

  return (
    <>
      <div className='vo-search-results-program'>
        <Title
          programId={id!}
          title={title}
          subtitle={subtitle}
          hits={hits.length}
          expand={expand}
          onToggleExpand={() => setExpand(!expand)}
        />
        {expand ? (
          <FoundProgramHits hits={hits} programLength={elements.length} />
        ) : (
          <></>
        )}
      </div>
    </>
  );
}

interface FoundProgramHitsProps {
  hits: string[];
  programLength: number;
}

function FoundProgramHits({
  hits,
  programLength,
}: FoundProgramHitsProps): JSX.Element {
  return (
    <>
      {hits.map(subject => (
        <FoundElement
          key={subject}
          subject={subject}
          totalElements={programLength}
        />
      ))}
    </>
  );
}

interface TitleProps {
  programId: string;
  title?: string;
  subtitle?: string;
  hits: number;
  expand: boolean;
  onToggleExpand: () => void;
}

function Title({
  programId,
  title,
  subtitle,
  hits,
  expand,
  onToggleExpand,
}: TitleProps): JSX.Element {
  return (
    <div className='vo-search-results-program-head'>
      <Link
        to={`/ohjelmat/${programId}`}
        className='vo-search-results-program-head-link'
      >
        <span className='vo-search-results-program-head-subtitle'>
          {subtitle}
        </span>
        <span className='vo-search-results-program-head-title'>{title}</span>
      </Link>
      <div>
        <span className='vo-search-results-program-head-hits'>
          {hits} osuma{hits === 1 ? '' : 'a'}
        </span>
        <button className='vo-search-toggle-expand' onClick={onToggleExpand}>
          {expand ? '\u2014' : '+'}
        </button>
      </div>
    </div>
  );
}

interface FoundElementProps {
  subject: string;
  totalElements: number;
}

export function FoundElement({ subject, totalElements }: FoundElementProps) {
  const resource = useResource(subject);
  const programId = getProgramId(subject);
  const elementId = getProgramElementId(subject);
  const elementClass = useProgramClass(resource);
  const [text] = useString(resource, core.properties.description);
  const [name] = useString(resource, core.properties.name);

  return (
    <>
      <div className='vo-search-results-element'>
        <SearchResultElementBody
          text={text}
          name={name}
          elementClass={elementClass}
        />
        <SearchResultElementHead
          programId={programId!}
          elementId={elementId!}
          elementClass={elementClass}
          totalElements={totalElements}
        />
      </div>
    </>
  );
}

interface SearchResultsElementHeadProps {
  programId: number;
  elementId: number;
  elementClass?: string;
  totalElements: number;
}

export function SearchResultElementHead({
  programId,
  elementId,
}: SearchResultsElementHeadProps): JSX.Element {
  return (
    <>
      <Link
        to={`/ohjelmat/p${programId}?h=${elementId}`}
        className='vo-search-results-element-head'
      >
        Siirry tekstikohtaan &#x2192;
      </Link>
    </>
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
      return (
        <div className='vo-search-results-element-body'>
          <Markdown>{text}</Markdown>
        </div>
      );
    case ontology.classes.heading:
      return (
        <div className='vo-search-results-element-body'>
          <h3>{name}</h3>
        </div>
      );
    case ontology.classes.actionitem:
      return (
        <div className='vo-search-results-element-body'>
          <p>
            <ul>
              <li>{name}</li>
            </ul>
          </p>
        </div>
      );
    default:
      return (
        <div className='vo-search-results-element-body'>
          <p>
            {name}
            {text}
          </p>
        </div>
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

function getProgramId(subject: string): number | undefined {
  subject = parentProgramSubject(subject);

  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'p') {
      return parseInt(subject.substring(i + 1, subject.length));
    }

    if (subject[i] === '/') {
      return undefined;
    }
  }

  return undefined;
}

function getProgramElementId(subject: string): number | undefined {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'e') {
      return parseInt(subject.substring(i + 1, subject.length));
    }

    if (subject[i] === '/') {
      return undefined;
    }
  }

  return undefined;
}

function groupByProgram(src: string[]): FoundProgramProps[] {
  const programs: string[] = [];
  const byProgram = {};
  src.forEach(elementSubject => {
    const programSubject = parentProgramSubject(elementSubject);
    const elementId = getProgramElementId(elementSubject);
    const programId = getProgramId(programSubject);

    if (programId) {
      if (!(programSubject in byProgram)) {
        byProgram[programSubject] = [];
        programs.push(programSubject);
      }

      byProgram[programSubject].push({
        subject: elementSubject,
        id: elementId,
      });
    }
  });

  programs.sort();
  programs.reverse();

  for (const p in byProgram) {
    byProgram[p].sort((a, b) => a.id - b.id);
  }

  return programs.map(p => ({
    program: p,
    hits: byProgram[p].map(e => e.subject),
  }));
}
