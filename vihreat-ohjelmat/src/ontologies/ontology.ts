/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { BaseProps } from '@tomic/lib';

export const ontology = {
  classes: {
    program: 'http://localhost:9883/o/Program',
    programelement: 'http://localhost:9883/o/ProgramElement',
    heading: 'http://localhost:9883/o/Heading',
    title: 'http://localhost:9883/o/Title',
    paragraph: 'http://localhost:9883/o/Paragraph',
    actionitem: 'http://localhost:9883/o/ActionItem',
  },
  properties: {
    subtitle: 'http://localhost:9883/o/subtitle',
    category: 'http://localhost:9883/o/category',
    elements: 'http://localhost:9883/o/elements',
    approvedon: 'http://localhost:9883/o/approvedOn',
    updatedon: 'http://localhost:9883/o/updatedOn',
    retiredon: 'http://localhost:9883/o/retiredOn',
    staleon: 'http://localhost:9883/o/staleOn',
    text: 'http://localhost:9883/o/text',
    headinglevel: 'http://localhost:9883/o/headingLevel',
  },
} as const;

export type Program = typeof ontology.classes.program;
export type Programelement = typeof ontology.classes.programelement;
export type Heading = typeof ontology.classes.heading;
export type Title = typeof ontology.classes.title;
export type Paragraph = typeof ontology.classes.paragraph;
export type Actionitem = typeof ontology.classes.actionitem;

declare module '@tomic/lib' {
  interface Classes {
    [ontology.classes.program]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof ontology.properties.elements;
      recommends:
        | typeof ontology.properties.subtitle
        | typeof ontology.properties.category
        | typeof ontology.properties.approvedon
        | typeof ontology.properties.updatedon
        | typeof ontology.properties.retiredon
        | typeof ontology.properties.staleon;
    };
    [ontology.classes.programelement]: {
      requires: BaseProps;
      recommends: never;
    };
    [ontology.classes.heading]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof ontology.properties.headinglevel;
      recommends: never;
    };
    [ontology.classes.title]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
    [ontology.classes.paragraph]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/description';
      recommends: never;
    };
    [ontology.classes.actionitem]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
  }

  interface PropTypeMapping {
    [ontology.properties.subtitle]: string;
    [ontology.properties.category]: string;
    [ontology.properties.elements]: string[];
    [ontology.properties.approvedon]: string;
    [ontology.properties.updatedon]: string;
    [ontology.properties.retiredon]: string;
    [ontology.properties.staleon]: string;
    [ontology.properties.text]: string;
    [ontology.properties.headinglevel]: number;
  }

  interface PropSubjectToNameMapping {
    [ontology.properties.subtitle]: 'subtitle';
    [ontology.properties.category]: 'category';
    [ontology.properties.elements]: 'elements';
    [ontology.properties.approvedon]: 'approvedon';
    [ontology.properties.updatedon]: 'updatedon';
    [ontology.properties.retiredon]: 'retiredon';
    [ontology.properties.staleon]: 'staleon';
    [ontology.properties.text]: 'text';
    [ontology.properties.headinglevel]: 'headinglevel';
  }
}
