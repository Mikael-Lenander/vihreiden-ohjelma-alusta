import { useEffect, useMemo, useState } from 'react';
import { useCollection, useResource, useString, core } from '@tomic/react';
import { StatusInfo, useStatusInfo } from './program/Status';
import { ontology } from '../ontologies/ontology';

export class Program {
  public subject: string;
  public title?: string;
  public subtitle?: string;
  public status: StatusInfo;

  public constructor(subject: string) { this.subject = subject; }

  public get id(): string | undefined {
    return this.subject.split('/').pop();
  }

  public get linkPath(): string {
    return `/ohjelmat/${this.id}`;
  }
}

export class Programs {
  public ready: boolean;
  public all: Program[];

  public constructor() {
    this.ready = false;
    this.all = [];
  }

  public get active(): Program[] {
    return this.all.filter((p) => p.status.isGreen || p.status.isYellow);
  }
}

export function useProgram(subject?: string): Program {
  const program = new Program(subject || "");
  const resource = useResource(subject);
  [program.title] = useString(resource, core.properties.name);
  [program.subtitle] = useString(resource, ontology.properties.subtitle);
  program.status = useStatusInfo(resource);
  return program;
}

export function useProgramList(subjects: string[]): Program[] {
  const programs: Program[] = [];
  for (var i = 0; i < 64; ++i) {
    if (i < subjects.length) {
      programs.push(useProgram(subjects[i]));
    } else {
      useProgram(undefined);
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
  }, [collection]);

  return subjects;
}