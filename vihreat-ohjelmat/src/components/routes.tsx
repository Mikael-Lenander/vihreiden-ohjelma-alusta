import { Route, Routes } from "react-router-dom";
import { ViewProgram } from "./ViewProgram";
import FrontPage from "./FrontPage";

export function AppRoutes(): JSX.Element {
  return (
    <Routes>
      <Route path="/" element={<FrontPage />} />
      <Route path="ohjelmat/:pid" element={<ViewProgram />} />
    </Routes>
  );
}

export default AppRoutes;
