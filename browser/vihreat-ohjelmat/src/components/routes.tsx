import { Route, Routes } from 'react-router-dom';
import { ViewProgram } from './ViewProgram';
import SideBar from './SideBar';
import WelcomePage from './WelcomePage';
import FrontPage from './FrontPage';

export function AppRoutes(): JSX.Element {
  return (
    <Routes>
      <Route path='/' element={<FrontPage />} />
      <Route path='ohjelmat/:id' element={<ViewProgram />} />
    </Routes>
  );
  //return (
  //  <Routes>
  //    <Route path='/' element={<SideBar />}>
  //      <Route index element={<WelcomePage />} />
  //      <Route path='ohjelmat/:id' element={<ViewProgram />} />
  //    </Route>
  //  </Routes>
  //);
}

export default AppRoutes;
