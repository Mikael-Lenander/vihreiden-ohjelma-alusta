import { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useCollection } from '@tomic/react';
import { ProgramBadge } from './ProgramBadge';
import { ontology as vihreat } from 'vihreat-lib';
import { core } from '@tomic/lib';

export default function SideBar() {
  const { collection } = useCollection({
    property: core.properties.isA,
    value: vihreat.classes.program,
  });
  const numPrograms = collection.totalMembers;
  const [searchText, setSearchText] = useState('');
  const searchQuery = searchText.toLowerCase();

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
        <>
          {numPrograms === 0 ? (
            <p>Ladataan ohjelmia...</p>
          ) : (
            range(0, collection.totalMembers).map(index => (
              <ProgramBadge
                key={index}
                collection={collection}
                index={index}
                searchQuery={searchQuery}
              />
            ))
          )}
        </>
      </div>
      <div className='content'>
        <Outlet />
      </div>
    </div>
  );
}

const range = (start, end) =>
  Array.from({ length: end - start }, (_, i) => start + i);
