import { useEffect, useState } from 'react';
import { useCollection, useStore, core, Resource, Store } from '@tomic/react';
import { StatusInfo, getStatusInfo } from './program/Status';
import { ontology } from '../ontologies/ontology';

// Metadata-level info for a single program
class ProgramInfo {
  public subject: string;
  public resource: Resource;
  public species: string;
  public category: string;
  public title?: string;
  public status: StatusInfo;

  public constructor(store: Store, subject: string) {
    this.subject = subject;
    this.resource = store.getResourceLoading(subject);
    this.species = this.resource.get(ontology.properties.subtitle);
    this.category = this.resource.get(ontology.properties.category);
    this.title = this.resource.get(core.properties.name);
    this.status = getStatusInfo(this.resource);
  }

  public get id(): string | undefined {
    return this.subject.split('/').pop();
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

// Metadata for all programs in the database
class ProgramCatalog {
  private all: ProgramInfo[];

  public constructor(store: Store, subjects: string[]) {
    this.all = [];
    subjects.forEach(subject => {
      const program = new ProgramInfo(store, subject);
      this.all.push(program);
    });
  }

  public get headlinePrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isHeadline);
  }

  public get thematicPrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isThematic);
  }

  public get openers(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isOpener);
  }

  public get retiredPrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isRetired);
  }
}

export function usePrograms(): ProgramCatalog | undefined {
  const store = useStore();

  const { collection } = useCollection({
    property: core.properties.isA,
    value: ontology.classes.program,
    sort_by: ontology.properties.approvedon,
    sort_desc: true,
  });

  const [result, setResult] = useState<ProgramCatalog | undefined>(undefined);
  useEffect(() => {
    collection.getAllMembers().then(subjects => {
      const programs = new ProgramCatalog(store, subjects);
      setResult(programs);
    });
  }, []);

  return result;
}
