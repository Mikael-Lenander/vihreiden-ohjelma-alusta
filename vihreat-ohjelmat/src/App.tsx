import { useState } from 'react';
import { ViewProgram } from './ViewProgram';
import './App.css'

function App() {
  const [count, setCount] = useState(0);

  return <ViewProgram subject="http://localhost:9883/ohjelmat/p0" />;
}

export default App
