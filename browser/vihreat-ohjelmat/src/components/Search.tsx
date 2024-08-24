import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { useResource, useServerSearch, useString, core } from '@tomic/react';
import { ontology as vihreat, useProgramClass } from 'vihreat-lib';
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
      [core.properties.isA]: vihreat.classes.programelement,
    },
  });

  if (query.loading) {
    return <Loading />;
  } else if (query.results.length == 0) {
    return <NoResultsFound />;
  } else {
    return (
      <div id='vo-search-results-container'>
        {
          groupByProgram(query.results).map((e) => {
            return <FoundProgram program={e.program} hits={e.hits} />;
          })
        }
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
  const klass = useProgramClass(resource);
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, vihreat.properties.subtitle);
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
        {expand ? <FoundProgramHits hits={hits} /> : <></>}
      </div>
    </>
  );
}

interface FoundProgramHitsProps {
  hits: string[];
}
function FoundProgramHits({ hits }: FoundProgramHitsProps): JSX.Element {
  return <>{hits.map((subject) => (<FoundElement subject={subject} />))}</>;
}

interface TitleProps {
  programId: string;
  title?: string;
  subtitle?: string;
  hits: number;
  expand: boolean;
  onToggleExpand: () => void;
}
function Title({ programId, title, subtitle, hits, expand, onToggleExpand }: TitleProps): JSX.Element {

  return (
    <div className='vo-search-results-program-head'>
      <NavLink to={`/ohjelmat/${programId}`} className='vo-search-results-program-head-link'>
        <span className='vo-search-results-program-head-subtitle'>
          {subtitle}
        </span>
        <span className='vo-search-results-program-head-title'>
          {title}
        </span>
      </NavLink>
      <div>
        <span className='vo-search-results-program-head-hits'>
          {hits} osuma{hits == 1 ? '' : 'a'}
        </span>
        <a className='vo-search-toggle-expand' onClick={onToggleExpand}>
          {expand ? '\u2014' : '+'}
        </a>
      </div>
    </div>
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
        <SearchResultElementHead programId={programId!} elementId={elementId!} elementClass={elementClass} />
        <SearchResultElementBody text={text} name={name} elementClass={elementClass} />
      </div>
    </>
  );
}

interface SearchResultsElementHeadProps {
  programId: number;
  elementId: number;
  elementClass?: string;
}

export function SearchResultElementHead({ programId, elementId, elementClass }: SearchResultsElementHeadProps): JSX.Element {
  let desc = "Tuntematon";
  switch (elementClass) {
    case vihreat.classes.paragraph:
      desc = "Tekstikappale";
      break;
    case vihreat.classes.heading:
      desc = "Otsikko";
      break;
    case vihreat.classes.actionitem:
      desc = "Linjaus";
      break;
  }
  return (
    <NavLink to={`/ohjelmat/p${programId}?h=${elementId}`} className='vo-search-results-element-head'>
      #{elementId}
    </NavLink>
  );
}

interface SearchResultsElementBodyProps {
  text?: string;
  name?: string;
  elementClass?: string;
}

export function SearchResultElementBody({ text, name, elementClass }: SearchResultsElementBodyProps): JSX.Element {
  switch (elementClass) {
    case vihreat.classes.paragraph:
      return (
        <div className='vo-search-results-element-body'>
          <Markdown>{text}</Markdown>
        </div>
      );
    case vihreat.classes.heading:
      return (
        <div className='vo-search-results-element-body'>
          <h3>{name}</h3>
        </div>
      );
    case vihreat.classes.actionitem:
      return (
        <div className='vo-search-results-element-body'>
          <p><ul><li>{name}</li></ul></p>
        </div>
      );
    default:
      return (
        <div className='vo-search-results-element-body'>
          <p>{name}{text}</p>
        </div>
      );
  }
}


function parentProgramSubject(subject: string) {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] == 'e') {
      return subject.substring(0, i);
    }
    if (subject[i] == '/') {
      return subject;
    }
  }
  return subject;
}

function getProgramId(subject: string): number | undefined {
  subject = parentProgramSubject(subject);
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] == 'p') {
      return parseInt(subject.substring(i + 1, subject.length));
    }
    if (subject[i] == '/') {
      return undefined;
    }
  }
  return undefined;
}

function getProgramElementId(subject: string): number | undefined {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] == 'e') {
      return parseInt(subject.substring(i + 1, subject.length));
    }
    if (subject[i] == '/') {
      return undefined;
    }
  }
  return undefined;
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
  let programs: string[] = [];
  let byProgram = {};
  src.forEach((elementSubject) => {
    const programSubject = parentProgramSubject(elementSubject);
    const elementId = getProgramElementId(elementSubject);
    const programId = getProgramId(programSubject);
    if (programId) {
      if (!(programSubject in byProgram)) {
        byProgram[programSubject] = [];
        programs.push(programSubject);
      }
      byProgram[programSubject].push({ subject: elementSubject, id: elementId });
    }
  });

  programs.sort();
  programs.reverse();
  for (const p in byProgram) {
    byProgram[p].sort((a, b) => a.id - b.id);
  }

  return programs.map((p) => ({ program: p, hits: byProgram[p].map((e) => e.subject) }));
}