// src/pages/AuthPage.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../context/UserContext';
import LoginForm from '../components/auth/LoginForm';
import RegistrationForm from '../components/auth/RegistrationForm';
import ThemeToggle from '../components/ThemeToggle';

const AuthPage = () => {
    const [isLoginMode, setIsLoginMode] = useState(true);
    const { isAuthenticated } = useUser();
    const navigate = useNavigate();

    // Redirect if already authenticated
    useEffect(() => {
        if (isAuthenticated) {
            navigate('/dashboard');
        }
    }, [isAuthenticated, navigate]);

    const handleAuthSuccess = () => {
        navigate('/dashboard');
    };

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col items-center justify-center p-4 transition-colors duration-200">
            <div className="w-full max-w-md">
                {/* App Logo/Name */}
                <div className="text-center mb-8">
                    <h1 className="text-4xl font-bold text-blue-600 dark:text-blue-500">Link Harbor</h1>
                    <p className="mt-2 text-gray-600 dark:text-gray-400">Your personal URL management dashboard</p>
                </div>

                {/* Auth Forms */}
                {isLoginMode ? (
                    <LoginForm
                        onRegisterClick={() => setIsLoginMode(false)}
                        onLoginSuccess={handleAuthSuccess}
                    />
                ) : (
                    <RegistrationForm
                        onLoginClick={() => setIsLoginMode(true)}
                        onRegisterSuccess={handleAuthSuccess}
                    />
                )}

                {/* Theme Toggle */}
                <div className="mt-8 text-center">
                    <div className="inline-flex items-center justify-center">
                        <span className="text-sm text-gray-500 dark:text-gray-400 mr-2">Toggle theme:</span>
                        <ThemeToggle />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AuthPage;