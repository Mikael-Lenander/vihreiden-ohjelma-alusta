import { useArray, core, Resource } from "@tomic/react";
import { ontology } from "./ontologies/ontology";

export function useProgramClass(resource: Resource<any>) {
  const [classes] = useArray(resource, core.properties.isA);
  const programClass = classes.find((c) => c !== ontology.classes.program);

  return programClass;
}
