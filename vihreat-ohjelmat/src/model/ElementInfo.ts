import { core, Resource } from '@tomic/react';
import { ontology } from '../ontologies/ontology';

export class ElementInfo {
  public resource: Resource;
  public elementClass: string;
  public name: string;
  public description: string;
  public level?: number;

  public constructor(resource: Resource) {
    this.resource = resource;
    this.elementClass = getElementClass(resource);
    this.name = resource.get(core.properties.name);
    this.description = resource.get(core.properties.description);

    if (this.elementClass === ontology.classes.heading) {
      this.level = resource.get(ontology.properties.headinglevel);
    }
  }

  public get subject(): string {
    return this.resource.subject;
  }

  public get index(): number {
    return parseInt(this.subject.split('/').pop()?.split('e').pop() ?? '0');
  }
}

function getElementClass(resource: Resource): string {
  const classes = resource.get(core.properties.isA);

  for (const c of classes) {
    if (c !== ontology.classes.program) {
      return c;
    }
  }

  return '';
}
