import { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useCollection, useServerSearch, core } from '@tomic/react';
import {
  ProgramBadgeResourceItem,
  ProgramBadgeCollectionItem,
} from './ProgramBadge';
import { ontology as vihreat } from 'vihreat-lib';
import { SERVER_URL } from '../config';

export default function SideBar() {
  const [searchText, setSearchText] = useState('');

  return (
    <div className='sidebar-container'>
      <div className='sidebar'>
        <NavLink to='/' end>
          <h1>Ohjelmat</h1>
        </NavLink>
        <search>
          <input
            type='text'
            placeholder='Hae ohjelmia...'
            value={searchText}
            onChange={e => setSearchText(e.target.value)}
          />
        </search>
        {searchText === '' ? (
          <ProgramList />
        ) : (
          <ProgramSearchResults searchText={searchText} />
        )}
      </div>
      <div className='content'>
        <Outlet />
      </div>
    </div>
  );
}

export function ProgramList() {
  const { collection } = useCollection({
    property: core.properties.isA,
    value: vihreat.classes.program,
  });
  const numPrograms = collection.totalMembers;

  return (
    <>
      {numPrograms === 0 ? (
        <p>Ladataan ohjelmia...</p>
      ) : (
        range(0, numPrograms).map(index => (
          <ProgramBadgeCollectionItem
            key={index}
            collection={collection}
            index={index}
          />
        ))
      )}
    </>
  );
}

interface ProgramSearchResultsProps {
  searchText: string;
}

function ProgramSearchResults({ searchText }: ProgramSearchResultsProps) {
  const query = useServerSearch(searchText, {
    debounce: 200,
    include: true,
    limit: 100000,
    filters: {
      [core.properties.isA]: vihreat.classes.programelement,
    },
  });
  const programs = getProgramsFromProgramElements(query.results);

  return (
    <>
      {query.loading ? (
        <p>Haetaan ohjelmia...</p>
      ) : programs.length === 0 ? (
        <p>Ei tuloksia</p>
      ) : (
        programs.map(subject => (
          <ProgramBadgeResourceItem key={subject} subject={subject} />
        ))
      )}
    </>
  );
}

const range = (start, end) =>
  Array.from({ length: end - start }, (_, i) => start + i);

function getProgramsFromProgramElements(subjects: string[]) {
  const programs: Set<string> = new Set();

  for (const subject of subjects) {
    const urlEnd = subject.split('/').pop() ?? '';
    const programNameMatch = urlEnd.match(/^.*?(?=e)/);
    const programName = programNameMatch ? programNameMatch[0] : urlEnd;
    programs.add(`${SERVER_URL}/ohjelmat/${programName}`);
  }

  return Array.from(programs);
}
