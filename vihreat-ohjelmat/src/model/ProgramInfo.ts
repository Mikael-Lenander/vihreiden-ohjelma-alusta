import { core, Resource } from '@tomic/react';
import { getStatusInfo, StatusInfo } from './StatusInfo';
import { ontology } from '../ontologies/ontology';

// Metadata-level info for a single program
export class ProgramInfo {
  public resource: Resource;
  public species: string;
  public category: string;
  public title?: string;
  public status: StatusInfo;

  public constructor(resource: Resource) {
    this.resource = resource;
    this.species = this.resource.get(ontology.properties.subtitle);
    this.category = this.resource.get(ontology.properties.category);
    this.title = this.resource.get(core.properties.name);
    this.status = getStatusInfo(this.resource);
  }

  public get subject(): string {
    return this.resource.subject;
  }

  public get id(): string | undefined {
    return this.subject.split('/').pop();
  }

  public get index(): number {
    return parseInt(this.id?.split('p')?.pop() ?? '-1');
  }

  public get linkPath(): string {
    return `/ohjelmat/${this.id}`;
  }

  public get isActive(): boolean {
    return this.status.isGreen || this.status.isYellow;
  }

  public get isRetired(): boolean {
    return this.status.isRed;
  }

  public get isHeadline(): boolean {
    return (
      this.category === 'poliittinen ohjelma' ||
      this.category === 'periaateohjelma'
    );
  }

  public get isThematic(): boolean {
    return this.category === 'teemaohjelma';
  }

  public get isOpener(): boolean {
    return this.category === 'avaus';
  }
}
