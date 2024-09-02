import Browse from "./Browse";
import Search from "./Search";

export function FrontPage(): JSX.Element {
  return (
    <>
      <Title />
      <Search />
      <Browse />
    </>
  );
}
export default FrontPage;

function Title(): JSX.Element {
  return <h1 id="vo-frontpage-title">Vihreät ohjelmat</h1>;
}
