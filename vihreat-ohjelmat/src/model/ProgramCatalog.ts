import { type Store, type Resource } from '@tomic/react';
import { ProgramInfo } from './ProgramInfo';

export class ProgramCatalog {
  // Info for all programs (completely unfiltered)
  public all: ProgramInfo[];

  private loaders: ProgramInfoLoader[];

  public constructor() {
    this.loaders = [];
    this.all = [];
  }

  public get headlinePrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isHeadline);
  }

  public get thematicPrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isThematic);
  }

  public get electionPrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isElection);
  }

  public get openers(): ProgramInfo[] {
    return this.all.filter(p => p.isActive && p.isOpener);
  }

  public get retiredPrograms(): ProgramInfo[] {
    return this.all.filter(p => p.isRetired);
  }

  public load(store: Store, subjects: string[], onReady: () => void) {
    const check = () => {
      this.checkReady(onReady);
    };

    this.loaders = subjects.map(subject => {
      return new ProgramInfoLoader(store, subject, check);
    });
    check();
  }

  private checkReady(onReady: () => void) {
    if (this.loaders.every(ldr => ldr.resource !== undefined)) {
      this.all = this.loaders.map(ldr => ldr.info!);
      onReady();
    }
  }
}

class ProgramInfoLoader {
  public subject: string;
  public resource?: Resource;
  public info?: ProgramInfo;

  public constructor(store: Store, subject: string, onUpdate: () => void) {
    this.subject = subject;
    this.resource = undefined;
    this.info = undefined;
    store.getResource(subject).then(resource => {
      this.resource = resource;
      this.info = new ProgramInfo(resource);
      onUpdate();
    });
  }
}
