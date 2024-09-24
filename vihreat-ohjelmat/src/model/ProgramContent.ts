import { Resource, type Store } from '@tomic/react';
import { ElementInfo } from './ElementInfo';
import { ontology } from '../ontologies/ontology';

export class ProgramContent {
  // Linear (flattened) sequence of program elements
  public elements: ElementInfo[];

  // Program contents in their logical tree form
  public tree: TreeNode;

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
    const builder = new TreeBuilder();
    this.elements.forEach(e => builder.addElement(e));
    this.tree = builder.root;
  }
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

export enum TreeNodeType {
  Root = 0,
  Heading,
  Paragraph,
  ActionList,
  ActionItem,
}

export class TreeNode {
  // Unique ID number within the tree. Can be used as the "key" prop.
  public id: number;
  public type: TreeNodeType;
  public element?: ElementInfo;
  public children: TreeNode[];

  public constructor(id: number, type: TreeNodeType, element?: ElementInfo) {
    this.id = id;
    this.type = type;
    this.element = element;
    this.children = [];
  }
  public get isRoot() {
    return this.type === TreeNodeType.Root;
  }

  public get isHeading() {
    return this.type === TreeNodeType.Heading;
  }

  public get isParagraph() {
    return this.type === TreeNodeType.Paragraph;
  }

  public get isActionList() {
    return this.type === TreeNodeType.ActionList;
  }

  public get isActionItem() {
    return this.type === TreeNodeType.ActionItem;
  }

  public canBeParentOf(element: ElementInfo): boolean {
    switch (element.elementClass) {
      case ontology.classes.paragraph:
        return !this.isActionList;
      case ontology.classes.actionitem:
        return this.isActionList;
      case ontology.classes.heading:
        return (
          this.isRoot ||
          (this.isHeading && this.element!.level! < element.level!)
        );
      default:
        return true;
    }
  }
}

class TreeBuilder {
  public root: TreeNode;
  private stack: TreeNode[];
  private nextId: number;

  public constructor() {
    this.nextId = 0;
    this.root = new TreeNode(this.assignNewId(), TreeNodeType.Root);
    this.stack = [this.root];
  }

  private get current() {
    return this.stack[this.stack.length - 1];
  }

  public addElement(e: ElementInfo) {
    switch (e.elementClass) {
      case ontology.classes.heading:
        this.addHeading(e);
        break;
      case ontology.classes.paragraph:
        this.addParagraph(e);
        break;
      case ontology.classes.actionitem:
        this.addActionItem(e);
        break;
    }
  }

  private assignNewId(): number {
    const id = this.nextId;
    this.nextId += 1;

    return id;
  }

  private createNode(type: TreeNodeType, element?: ElementInfo): TreeNode {
    return new TreeNode(this.assignNewId(), type, element);
  }

  private addHeading(e: ElementInfo) {
    this.ascend(e);
    this.addChild(TreeNodeType.Heading, e);
    this.descend();
  }

  private addParagraph(e: ElementInfo) {
    this.addChild(TreeNodeType.Paragraph, e);
  }

  private addActionItem(e: ElementInfo) {
    if (!this.current.isActionList) {
      this.addChild(TreeNodeType.ActionList);
      this.descend();
    }

    this.addChild(TreeNodeType.ActionItem, e);
  }

  private addChild(type: TreeNodeType, element?: ElementInfo): TreeNode {
    const node = this.createNode(type, element);
    this.current.children.push(node);

    return node;
  }

  // Move focus down the tree.
  //
  // The new focus will be the last child of the old focus.
  private descend() {
    const node = this.current.children[this.current.children.length - 1];
    this.stack.push(node);
  }

  // Move focus up the tree.
  //
  // The new focus will be the first element seen which can take the given
  // element as a child.
  private ascend(element: ElementInfo) {
    while (!this.current.canBeParentOf(element)) {
      this.stack.pop();
    }
  }
}
