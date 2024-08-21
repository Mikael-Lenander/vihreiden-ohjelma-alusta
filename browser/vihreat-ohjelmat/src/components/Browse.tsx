import { Collection } from '@tomic/lib';
import { useCollection, useMemberFromCollection, useString, core } from '@tomic/react';
import { Program as ProgramResource, ontology as vihreat, useStatusInfo } from 'vihreat-lib';
import { ProgramCard } from './ProgramCard';

export function Browse(): JSX.Element {
  const { collection } = useCollection({
    property: core.properties.isA,
    value: vihreat.classes.program,
  });
  if (collection.totalMembers === 0) {
    return <Loading />;
  } else {
    return (
      <>
        <BrowseHint />
        <div className='vo-browse'>
          {
            [...Array(collection.totalMembers).keys()].map(
              index => <ProgramFromCollection index={index} collection={collection} />
            )
          }
        </div>
      </>
    );
  }
}
export default Browse;

function BrowseHint(): JSX.Element {
  return <p className='vo-browse-hint'>Kaikki ohjelmat</p>;
}

function Loading(): JSX.Element {
  return <p className='vo-browse-loading-msg'>Haetaan ohjelmia...</p>;
}

interface ProgramFromCollectionProps {
  index: number;
  collection: Collection;
}
function ProgramFromCollection({ index, collection }: ProgramFromCollectionProps): JSX.Element {
  const resource = useMemberFromCollection<ProgramResource>(collection, index);
  const linkPath = `/ohjelmat/${resource.subject.split('/').pop()}`;
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, vihreat.properties.subtitle);
  const status = useStatusInfo(resource);
  return <ProgramCard linkPath={linkPath} title={title} subtitle={subtitle} status={status} />;
}
