import { BrowserRouter } from 'react-router-dom';
import { AppRoutes } from './routes';
import { DevBanner } from './DevBanner';
import '../App.css';

function App() {
  return (
    <>
      <DevBanner />
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </>
  );
}

export default App;
