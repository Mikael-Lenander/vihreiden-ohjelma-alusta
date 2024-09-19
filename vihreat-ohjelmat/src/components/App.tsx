import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { DevBanner } from './DevBanner';
import { FrontPage } from './FrontPage';
import { ViewProgram } from './ViewProgram';
import '../App.css';

function App() {
  return (
    <>
      <Router />
      <DevBanner />
    </>
  );
}

function Router() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path='/' element={<FrontPage />} />
        <Route path='ohjelmat/:pid' element={<ViewProgram />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
