import React from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { LinkProvider } from './context/LinkContext';
import Dashboard from './components/Dashboard';
import './styles.css';

function App() {
    return (
        <ThemeProvider>
            <LinkProvider>
                <div className="min-h-screen bg-gray-50">
                    <Dashboard />
                </div>
            </LinkProvider>
        </ThemeProvider>
    );
}

export default App;