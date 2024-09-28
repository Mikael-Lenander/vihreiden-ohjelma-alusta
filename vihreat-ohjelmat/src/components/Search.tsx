import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ontology } from '../ontologies/ontology';
import { useSearch } from '../hooks/useSearch';
import './Search.css';
import type {
  SearchHitsInProgram,
  SearchHit,
  SearchHitLocation,
} from '../model/SearchResults';
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
        Tässä voit hakea tekstisisältöä voimassa olevista ohjelmista. Haku alkaa
        heti, kun kenttään kirjoitetaan. Haku etsii tarkkaa osumaa (ei ole sumea
        haku).
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
        <SearchResultElementBody hit={hit} />
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
  hit: SearchHit;
}

export function SearchResultElementBody({
  hit,
}: SearchResultsElementBodyProps): JSX.Element {
  switch (hit.element.elementClass) {
    case ontology.classes.paragraph:
      return (
        <div className='vo-search-results-element-body'>
          <SearchHitWithHighlights hit={hit} field='description' />
        </div>
      );
    case ontology.classes.heading:
      return (
        <div className='vo-search-results-element-body'>
          <h3>
            <SearchHitWithHighlights hit={hit} field='name' />
          </h3>
        </div>
      );
    case ontology.classes.actionitem:
      return (
        <div className='vo-search-results-element-body'>
          <p>
            <ul>
              <li>
                <SearchHitWithHighlights hit={hit} field='name' />
              </li>
            </ul>
          </p>
        </div>
      );
    default:
      return (
        <div className='vo-search-results-element-body'>
          <p>
            <SearchHitWithHighlights hit={hit} field='name' />
            <SearchHitWithHighlights hit={hit} field='description' />
          </p>
        </div>
      );
  }
}

interface SearchHitWithHighlightsProps {
  hit: SearchHit;
  field: string;
}

export function SearchHitWithHighlights({
  hit,
  field,
}: SearchHitWithHighlightsProps): JSX.Element {
  let text = '';

  if (field === 'name') {
    text = hit.element.name;
  } else if (field === 'description') {
    text = hit.element.description;
  }

  const locations = hit.locations?.filter(loc => loc.field === field);

  if (locations) {
    return (
      <ReactMarkdown rehypePlugins={[rehypeRaw]}>
        {highlight(text, locations)}
      </ReactMarkdown>
    );
  } else {
    return <ReactMarkdown>{text}</ReactMarkdown>;
  }
}

function highlight(text: string, locations: SearchHitLocation[]): string {
  let s = '';

  for (const snip of split(text, locations)) {
    if (snip.isHit) {
      s += '<span class="vo-search-highlight">' + snip.text + '</span>';
    } else {
      s += snip.text;
    }
  }

  return s;
}

class Snip {
  public text: string;
  public isHit: boolean;

  public constructor(text: string, isHit: boolean) {
    this.text = text;
    this.isHit = isHit;
  }
}

function split(text: string, locations: SearchHitLocation[]): Snip[] {
  const snips: Snip[] = [];
  let i = 0;

  for (const loc of locations) {
    if (loc.index > i) {
      snips.push(new Snip(text.substring(i, loc.index), false));
      i = loc.index;
    }

    snips.push(
      new Snip(text.substring(loc.index, loc.index + loc.length), true),
    );
    i = loc.index + loc.length;
  }

  if (i < text.length) {
    snips.push(new Snip(text.substring(i), false));
  }

  return snips;
}
