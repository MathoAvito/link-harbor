// IMPORTANT: Make sure your App.jsx looks like this
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
                    <AppRouter />
                </LinkProvider>
            </UserProvider>
        </ThemeProvider>
    );
}

export default App;