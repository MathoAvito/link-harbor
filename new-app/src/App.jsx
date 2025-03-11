// src/App.jsx
import React from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { UserProvider } from './context/UserContext';
import { LinkProvider } from './context/LinkContext';
import AppRouter from './AppRouter';
import './styles.css';

function App() {
    return (
        <ThemeProvider>
            <UserProvider>
                <LinkProvider>
                    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
                        <AppRouter />
                    </div>
                </LinkProvider>
            </UserProvider>
        </ThemeProvider>
    );
}

export default App;