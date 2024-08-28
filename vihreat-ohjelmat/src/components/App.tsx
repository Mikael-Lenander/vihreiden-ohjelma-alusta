import { BrowserRouter } from 'react-router-dom';
import { AppRoutes } from './routes';
import { DevBanner } from './DevBanner';
import '../App.css';

function App() {
  return (
    <>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
      <DevBanner />
    </>
  );
}

export default App;
