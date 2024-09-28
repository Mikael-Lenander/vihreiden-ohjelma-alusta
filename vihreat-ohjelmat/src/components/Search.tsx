import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ontology } from '../ontologies/ontology';
import { useSearch } from '../hooks/useSearch';
import Markdown from 'react-markdown';
import './Search.css';
import type { SearchHitsInProgram, SearchHit } from '../model/SearchResults';
import type { ProgramInfo } from '../model/ProgramInfo';

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
  return (
    <div id='vo-search-instructions'>
      <h2>Tekstihaku</h2>
      <p>
        Tässä voit hakea tekstisisältöä voimassa olevista ohjelmista.<br />
        Haku alkaa heti, kun kenttään kirjoitetaan.
      </p>
    </div>
  );
}

function Idle(): JSX.Element {
  return <></>;
}

interface SearchResultsProps {
  searchText: string;
}

function SearchResults({ searchText }: SearchResultsProps): JSX.Element {
  const search = useSearch(searchText);

  if (search === undefined) {
    return <Loading />;
  } else if (search.active.length === 0) {
    return <NoResultsFound />;
  } else {
    return (
      <div id='vo-search-results-container'>
        {search.active.map(hits => (
          <FoundProgram key={hits.program.id} hits={hits} />
        ))}
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
  hits: SearchHitsInProgram;
}

function FoundProgram({ hits }: FoundProgramProps): JSX.Element {
  const [expand, setExpand] = useState(false);

  return (
    <>
      <div className='vo-search-results-program'>
        <Title
          programId={`p${hits.program.id}`}
          title={hits.program.title}
          subtitle={hits.program.species}
          hits={hits.hits.length}
          expand={expand}
          onToggleExpand={() => setExpand(!expand)}
        />
        {expand ? <FoundProgramHits hits={hits} /> : <></>}
      </div>
    </>
  );
}

interface FoundProgramHitsProps {
  hits: SearchHitsInProgram;
}

function FoundProgramHits({ hits }: FoundProgramHitsProps): JSX.Element {
  return (
    <>
      {hits.hits.map(hit => (
        <FoundElement program={hits.program} hit={hit} />
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
  program: ProgramInfo;
  hit: SearchHit;
}

export function FoundElement({ program, hit }: FoundElementProps) {
  return (
    <>
      <div className='vo-search-results-element'>
        <SearchResultElementBody
          text={hit.element.description}
          name={hit.element.name}
          elementClass={hit.element.elementClass}
        />
        <SearchResultElementHead
          programId={program.index}
          elementId={hit.element.index}
        />
      </div>
    </>
  );
}

interface SearchResultsElementHeadProps {
  programId: number;
  elementId: number;
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
