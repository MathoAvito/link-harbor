import React from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { LinkProvider } from './context/LinkContext';
import Dashboard from './components/Dashboard';
import './tailwind.output.css';

function App() {
  return (
    <ThemeProvider>
      <LinkProvider>
        <Dashboard />
      </LinkProvider>
    </ThemeProvider>
  );
}

export default App;