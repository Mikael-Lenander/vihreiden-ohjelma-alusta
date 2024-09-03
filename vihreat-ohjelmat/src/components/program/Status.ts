import { useDate, Resource } from '@tomic/react';
import { ontology } from '../../ontologies/ontology';

// "Traffic light" color
export enum StatusColor {
  Gray = 'gray',
  Green = 'green',
  Yellow = 'yellow',
  Red = 'red',
}

interface StatusInfoProps {
  approvedOn?: Date;
  updatedOn?: Date;
  retiredOn?: Date;
  staleOn?: Date;
}

export class StatusInfo {
  public color: StatusColor;
  public now: Date;
  public approvedOn?: Date;
  public updatedOn?: Date;
  public retiredOn?: Date;
  public staleOn?: Date;

  public constructor(
    now: Date,
    { approvedOn, updatedOn, retiredOn, staleOn }: StatusInfoProps,
  ) {
    this.now = now;
    this.approvedOn = approvedOn;
    this.updatedOn = updatedOn;
    this.retiredOn = retiredOn;
    this.staleOn = staleOn;

    if (!this.hasBeenApproved) {
      this.color = StatusColor.Gray;
    } else {
      if (this.hasBeenRetired) {
        this.color = StatusColor.Red;
      } else if (this.hasGoneStale) {
        this.color = StatusColor.Yellow;
      } else {
        this.color = StatusColor.Green;
      }
    }
  }

  public get hasBeenApproved(): boolean {
    return Boolean(this.approvedOn && this.approvedOn <= this.now);
  }

  public get hasBeenUpdated(): boolean {
    return Boolean(this.updatedOn && this.updatedOn <= this.now);
  }

  public get hasGoneStale(): boolean {
    return Boolean(this.staleOn && this.staleOn <= this.now);
  }

  public get hasBeenRetired(): boolean {
    return Boolean(this.retiredOn && this.retiredOn <= this.now);
  }

  public get isGray(): boolean {
    return this.color === StatusColor.Gray;
  }

  public get isGreen(): boolean {
    return this.color === StatusColor.Green;
  }

  public get isYellow(): boolean {
    return this.color === StatusColor.Yellow;
  }

  public get isRed(): boolean {
    return this.color === StatusColor.Red;
  }
}

export function useStatusInfo(resource: Resource): StatusInfo {
  return new StatusInfo(new Date(), {
    approvedOn: useDate(resource, ontology.properties.approvedon),
    updatedOn: useDate(resource, ontology.properties.updatedon),
    staleOn: useDate(resource, ontology.properties.staleon),
    retiredOn: useDate(resource, ontology.properties.retiredon),
  });
}
