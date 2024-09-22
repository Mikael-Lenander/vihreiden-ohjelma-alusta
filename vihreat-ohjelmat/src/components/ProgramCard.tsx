import { Link } from 'react-router-dom';
import { StatusInfo } from '../model/StatusInfo';
import { dateToString } from '../utils';
import './ProgramCard.css';

interface ProgramCardProps {
  linkPath: string;
  title?: string;
  subtitle?: string;
  status: StatusInfo;
}

export function ProgramCard({
  linkPath,
  title,
  subtitle,
  status,
}: ProgramCardProps): JSX.Element {
  const species = subtitle || title;
  const title_ = title === species ? '' : title;

  return (
    <Link to={linkPath}>
      <div className={`vo-programbadge vo-programbadge-${status.color}`}>
        <div>
          <p className='vo-programbadge-species'>{species}</p>
          <p className='vo-programbadge-title'>{title_}</p>
          <DateInfo status={status} />
          <Warnings status={status} />
        </div>
      </div>
    </Link>
  );
}

interface DateInfoProps {
  status: StatusInfo;
}

function DateInfo({ status }: DateInfoProps): JSX.Element {
  if (status.isGreen || status.isYellow) {
    return (
      <p className='vo-programbadge-date'>{dateToString(status.approvedOn)}</p>
    );
  } else if (status.isRed) {
    return (
      <p className='vo-programbadge-date'>
        {dateToString(status.approvedOn)} &mdash;{' '}
        {dateToString(status.retiredOn)}
      </p>
    );
  } else {
    return <></>;
  }
}

interface WarningsProps {
  status: StatusInfo;
}

function Warnings({ status }: WarningsProps): JSX.Element {
  let warning = '';

  if (status.isGreen) {
    return <></>;
  } else if (status.isGray) {
    warning = 'ohjelmaluonnos';
  } else if (status.isYellow) {
    warning = 'saattaa sisältää vanhentunutta sisältöä';
  } else if (status.isRed) {
    warning = 'ohjelma ei ole voimassa';
  } else {
    warning = 'voimassaolotietoja ei voitu selvittää';
  }

  return <p className='vo-programbadge-warning'>{warning}</p>;
}
