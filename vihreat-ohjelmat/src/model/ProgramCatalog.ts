import { Store } from '@tomic/react';
import { ProgramInfo } from './ProgramInfo';

export class ProgramCatalog {
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
