import { Resource, type Store } from '@tomic/lib';
import { ElementInfo } from './ElementInfo';
import { ProgramInfo } from './ProgramInfo';

export class SearchResults {
  public error?: Error;

  // Search hits in active programs
  public active: SearchHitsInProgram[];

  // Search hits in no-longer-active programs
  public retired: SearchHitsInProgram[];

  private loaders: Loader[];

  public constructor() {
    this.loaders = [];
    this.active = [];
    this.retired = [];
  }

  public load(store: Store, elements: string[], onReady: () => void) {
    const check = () => this.checkReady(onReady);
    this.loaders = elements.map(subject => {
      return new Loader(store, subject, check);
    });
  }

  public restrictToExact(q: string) {
    this.active = this.restrictHitsToExact(this.active, q);
    this.retired = this.restrictHitsToExact(this.retired, q);
  }

  private restrictHitsToExact(
    src: SearchHitsInProgram[],
    q: string,
  ): SearchHitsInProgram[] {
    return src
      .map(hits => hits.restrictToExact(q))
      .filter(hits => hits !== undefined);
  }

  private checkReady(onReady: () => void) {
    if (this.loaders.every(ldr => ldr.isReady)) {
      this.loaders.forEach(ldr => {
        this.process(ldr);
      });
      this.sort();
      onReady();
    }
  }

  private process(loader: Loader) {
    this.getProgram(loader.program_info!).addHit(loader.element_info!);
  }

  private getProgram(info: ProgramInfo): SearchHitsInProgram {
    for (const p of this.active) {
      if (p.program.subject === info.subject) {
        return p;
      }
    }

    for (const p of this.retired) {
      if (p.program.subject === info.subject) {
        return p;
      }
    }

    const p = new SearchHitsInProgram(info);

    if (p.program.isActive) {
      this.active.push(p);
    } else if (p.program.isRetired) {
      this.retired.push(p);
    }

    return p;
  }

  private sort() {
    this.active.forEach(p => {
      p.sort();
    });
    this.retired.forEach(p => {
      p.sort();
    });
    this.active.sort((a, b) => {
      return (
        b.program.status.approvedOn!.getTime() -
        a.program.status.approvedOn!.getTime()
      );
    });
    this.retired.sort((a, b) => {
      return (
        b.program.status.approvedOn!.getTime() -
        a.program.status.approvedOn!.getTime()
      );
    });
  }
}

class Loader {
  public program_subject: string;
  public program_resource?: Resource;
  public program_info?: ProgramInfo;

  public element_subject: string;
  public element_resource?: Resource;
  public element_info?: ElementInfo;

  public constructor(store: Store, subject: string, onUpdate: () => void) {
    this.program_subject = getParentProgramSubjectOf(subject);
    this.element_subject = subject;
    store.getResource(this.program_subject).then(resource => {
      this.program_resource = resource;
      this.program_info = new ProgramInfo(resource);

      if (this.isReady) {
        onUpdate();
      }
    });
    store.getResource(this.element_subject).then(resource => {
      this.element_resource = resource;
      this.element_info = new ElementInfo(resource);

      if (this.isReady) {
        onUpdate();
      }
    });
  }

  public get isReady() {
    return (
      this.element_resource !== undefined && this.program_resource !== undefined
    );
  }
}

function getParentProgramSubjectOf(subject: string) {
  for (let i = subject.length - 1; i >= 0; i--) {
    if (subject[i] === 'e') {
      return subject.substring(0, i);
    }

    if (subject[i] === '/') {
      return subject;
    }
  }

  return subject;
}

export class SearchHitsInProgram {
  public program: ProgramInfo;
  public hits: SearchHit[];

  public constructor(info: ProgramInfo, hits: SearchHit[] = []) {
    this.program = info;
    this.hits = hits;
  }

  public addHit(info: ElementInfo) {
    this.hits.push(new SearchHit(info));
  }

  public sort() {
    this.hits.sort((a, b) => {
      return a.element.index - b.element.index;
    });
  }

  public restrictToExact(q: string): SearchHitsInProgram | undefined {
    const hits = this.hits
      .map(hit => hit.findExact(q))
      .filter(hit => hit !== undefined);

    if (hits.length === this.hits.length) {
      return this;
    } else if (hits.length > 0) {
      return new SearchHitsInProgram(this.program, hits);
    } else {
      return undefined;
    }
  }
}

export class SearchHit {
  public element: ElementInfo;
  public locations?: SearchHitLocation[];

  public constructor(info: ElementInfo) {
    this.element = info;
    this.locations = undefined;
  }

  public findExact(q: string): SearchHit | undefined {
    // g: search everywhere ("global")
    // i: case insensitive
    const re = new RegExp(q, 'gi');
    const inName = this.element.name ? [...this.element.name.matchAll(re)] : [];
    const inDesc = this.element.description
      ? [...this.element.description.matchAll(re)]
      : [];

    if (inName.length + inDesc.length > 0) {
      this.locations = [
        ...inName.map(m => new SearchHitLocation('name', m.index, q.length)),
        ...inDesc.map(
          m => new SearchHitLocation('description', m.index, q.length),
        ),
      ];

      return this;
    } else {
      return undefined;
    }
  }
}

export class SearchHitLocation {
  public field: string;
  public index: number;
  public length: number;

  public constructor(field: string, index: number, length: number) {
    this.field = field;
    this.index = index;
    this.length = length;
  }
}
