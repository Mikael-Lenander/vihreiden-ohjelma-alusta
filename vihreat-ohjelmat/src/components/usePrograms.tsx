import { useEffect, useState } from 'react';
import { useCollection, useResource, useString, core } from '@tomic/react';
import { StatusInfo, useStatusInfo } from './program/Status';
import { ontology } from '../ontologies/ontology';

export class Program {
  public subject: string;
  public title?: string;
  public subtitle?: string;
  public status: StatusInfo;

  public constructor(subject: string) {
    this.subject = subject;
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
    // TODO: instead of hardcoding, use tags or similar
    return ((this.title ?? "").startsWith("Vihreiden poliittinen ohjelma")) ||
      ((this.subtitle ?? "").startsWith("Vihreiden periaateohjelma 2020-2028"));
  }
}

export class Programs {
  public ready: boolean;
  public all: Program[];

  public constructor() {
    this.ready = false;
    this.all = [];
  }

  public get headlinePrograms(): Program[] {
    return this.all.filter(p => p.isActive && p.isHeadline);
  }

  public get sectorPrograms(): Program[] {
    return this.all.filter(p => p.isActive && !p.isHeadline);
  }

  public get retiredPrograms(): Program[] {
    return this.all.filter(p => p.isRetired);
  }
}

export function useProgram(subject?: string): Program {
  const program = new Program(subject || '');
  const resource = useResource(subject);
  [program.title] = useString(resource, core.properties.name);
  [program.subtitle] = useString(resource, ontology.properties.subtitle);
  program.status = useStatusInfo(resource);

  return program;
}

export function useProgramList(subjects: string[]): Program[] {
  // TODO: terrible hack because of react hook order constraints
  const programs: Program[] = [];

  for (let i = 0; i < 128; ++i) {
    const isInRange = i < subjects.length;
    // ESLint thinks this violates rules of hooks because it occurs in a loop,
    // but it actually does not, because the loop is of constant size...
    //
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const program = useProgram(isInRange ? subjects[i] : undefined);

    if (isInRange) {
      programs.push(program);
    }
  }

  return programs;
}

export function usePrograms(): Programs {
  const subjects = useProgramsSubjects();
  const programs = new Programs();
  programs.ready = subjects !== undefined;
  programs.all = useProgramList(subjects ?? []);

  return programs;
}

export function useProgramsSubjects(): string[] | undefined {
  const { collection } = useCollection({
    property: core.properties.isA,
    value: ontology.classes.program,
    sort_by: ontology.properties.approvedon,
    sort_desc: true,
  });

  const [subjects, setSubjects] = useState<string[] | undefined>(undefined);
  useEffect(() => {
    collection.getAllMembers().then(setSubjects);
  }, []);

  return subjects;
}
