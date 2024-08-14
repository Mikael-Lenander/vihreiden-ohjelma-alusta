import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './components/App';
import './index.css';
import { PrimeReactProvider } from 'primereact/api';
import { Store, StoreContext } from '@tomic/react';
import 'primereact/resources/themes/saga-green/theme.css';
import { SERVER_URL } from './config';

const store = new Store({
  serverUrl: SERVER_URL,
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PrimeReactProvider>
      <StoreContext.Provider value={store}>
        <App />
      </StoreContext.Provider>
    </PrimeReactProvider>
  </React.StrictMode>,
);
