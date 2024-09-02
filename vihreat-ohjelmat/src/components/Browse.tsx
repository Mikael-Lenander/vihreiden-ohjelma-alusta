import { Collection } from "@tomic/lib";
import {
  useCollection,
  useMemberFromCollection,
  useString,
  core,
} from "@tomic/react";
import { useStatusInfo } from "./program/Status";
import { ontology, Program } from "../ontologies/ontology";
import { ProgramCard } from "./ProgramCard";

export function Browse(): JSX.Element {
  const { collection } = useCollection({
    property: core.properties.isA,
    value: ontology.classes.program,
  });

  if (collection.totalMembers === 0) {
    return <Loading />;
  } else {
    return (
      <>
        <BrowseHint />
        <div className="vo-browse">
          {[...Array(collection.totalMembers).keys()].map((index) => (
            <ProgramFromCollection
              key={index}
              index={index}
              collection={collection}
            />
          ))}
        </div>
      </>
    );
  }
}
export default Browse;

function BrowseHint(): JSX.Element {
  return <p className="vo-browse-hint">Kaikki ohjelmat</p>;
}

function Loading(): JSX.Element {
  return <p className="vo-browse-loading-msg">Haetaan ohjelmia...</p>;
}

interface ProgramFromCollectionProps {
  index: number;
  collection: Collection;
}

function ProgramFromCollection({
  index,
  collection,
}: ProgramFromCollectionProps): JSX.Element {
  const resource = useMemberFromCollection<Program>(collection, index);
  const linkPath = `/ohjelmat/${resource.subject.split("/").pop()}`;
  const [title] = useString(resource, core.properties.name);
  const [subtitle] = useString(resource, ontology.properties.subtitle);
  const status = useStatusInfo(resource);

  return (
    <ProgramCard
      linkPath={linkPath}
      title={title}
      subtitle={subtitle}
      status={status}
    />
  );
}
