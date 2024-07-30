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

  return (
    <div className='sidebar-container'>
      <div className='sidebar'>
        <NavLink to='/' end>
          <h1>Ohjelmat</h1>
        </NavLink>
        <>
          {numPrograms === 0 ? (
            <p>Ladataan ohjelmia...</p>
          ) : (
            range(0, collection.totalMembers).map(index => (
              <ProgramBadge key={index} collection={collection} index={index} />
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
