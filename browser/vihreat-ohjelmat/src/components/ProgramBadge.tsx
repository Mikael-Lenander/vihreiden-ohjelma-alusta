import { NavLink } from 'react-router-dom';
import { Collection, core } from '@tomic/lib';
import {
  useMemberFromCollection,
  useString,
  Resource,
  useResource,
} from '@tomic/react';
import { Program, ontology as vihreat, useStatusInfo } from 'vihreat-lib';

interface ProgramBadgeCollectionItemProps {
  index: number;
  collection: Collection;
}

export function ProgramBadgeCollectionItem({
  index,
  collection,
}: ProgramBadgeCollectionItemProps): JSX.Element {
  const program = useMemberFromCollection<Program>(collection, index);

  return <ProgramBadge program={program} />;
}

interface ProgramBadgeResourceItemProps {
  subject: string;
}

export function ProgramBadgeResourceItem({
  subject,
}: ProgramBadgeResourceItemProps): JSX.Element {
  const program = useResource<Program>(subject);

  return <ProgramBadge program={program} />;
}

interface ProgramBadgeProps {
  program: Resource<Program>;
}

export function ProgramBadge({ program }: ProgramBadgeProps): JSX.Element {
  const [title] = useString(program, core.properties.name);
  const [subtitle] = useString(program, vihreat.properties.subtitle);
  const id = program.subject.split('/').pop();
  const status = useStatusInfo(program);

  return (
    <NavLink to={`/ohjelmat/${id}`} className={linkStyling}>
      <div className={`vo-programbadge vo-programbadge-${status.color}`}>
        <p className='vo-programbadge-subtitle'>{subtitle}</p>
        <p className='vo-programbadge-title' title={title}>
          {title}
        </p>
      </div>
    </NavLink>
  );
}

function linkStyling({ isActive }: { isActive: boolean }) {
  return isActive ? 'vo-selected-program-link' : '';
}
