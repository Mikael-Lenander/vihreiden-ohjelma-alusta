import { NavLink } from 'react-router-dom';
import { Collection } from '@tomic/lib';
import { useMemberFromCollection, useString } from '@tomic/react';
import { Program, ontology as vihreat, useStatusInfo } from 'vihreat-lib';

interface ProgramBadgeProps {
  index: number;
  collection: Collection;
  searchQuery: string;
}

export function ProgramBadge({
  index,
  collection,
  searchQuery,
}: ProgramBadgeProps): JSX.Element {
  const program = useMemberFromCollection<Program>(collection, index);
  const [title] = useString(program, vihreat.properties.title);
  const [subtitle] = useString(program, vihreat.properties.subtitle);
  const id = program.subject.split('/').pop();
  const status = useStatusInfo(program);
  const searchHit =
    title?.toLowerCase().includes(searchQuery) ||
    subtitle?.toLowerCase().includes(searchQuery);

  return (
    <>
      {searchHit && (
        <NavLink to={`/ohjelmat/${id}`} className={linkStyling}>
          <p className={`vo-programbadge vo-programbadge-${status.color}`}>
            <p className='vo-programbadge-subtitle'>{subtitle}</p>
            <p className='vo-programbadge-title' title={title}>
              {title}
            </p>
          </p>
        </NavLink>
      )}
    </>
  );
}

export default ProgramBadge;

function linkStyling({ isActive }: { isActive: boolean }) {
  return isActive ? 'vo-selected-program-link' : '';
}
