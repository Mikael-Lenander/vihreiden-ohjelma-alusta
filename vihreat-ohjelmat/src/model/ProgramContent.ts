import { Resource, type Store } from '@tomic/react';
import { ElementInfo } from './ElementInfo';

export class ProgramContent {
  // Linear (flattened) sequence of program elements
  public elements: ElementInfo[];

  // Program contents in their logical tree form
  public tree: ElementNode;

  private loaders: ElementInfoLoader[];

  public constructor() {
    this.loaders = [];
    this.elements = [];
  }

  public load(store: Store, subjects: string[], onReady: () => void) {
    const check = () => {
      this.checkReady(onReady);
    };

    this.loaders = subjects.map(subject => {
      return new ElementInfoLoader(store, subject, check);
    });
  }

  private checkReady(onReady: () => void) {
    if (this.loaders.every(ldr => ldr.resource !== undefined)) {
      this.elements = this.loaders.map(ldr => ldr.info!);
      this.buildTree();
      onReady();
    }
  }

  private buildTree() {
    // TODO
  }
}

class ElementNode {
  public element: ElementInfo;
}

class ElementInfoLoader {
  public subject: string;
  public resource?: Resource;
  public info?: ElementInfo;

  public constructor(store: Store, subject: string, onUpdate: () => void) {
    this.subject = subject;
    this.resource = undefined;
    this.info = undefined;
    store.getResource(subject).then(resource => {
      this.resource = resource;
      this.info = new ElementInfo(resource);
      onUpdate();
    });
  }
}
