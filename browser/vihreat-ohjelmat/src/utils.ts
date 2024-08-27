export function dateToString(date?: Date): string {
  if (date) {
    return date.toLocaleString('fi-FI', {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
    });
  } else {
    return '??.??.????';
  }
}
