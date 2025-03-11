// src/AppRouter.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useUser } from './context/UserContext';
import RevisedDashboard from './components/RevisedDashboard';
import AuthPage from './pages/AuthPage';

// Protected route wrapper
const ProtectedRoute = ({ children }) => {
    const { isAuthenticated, isLoading } = useUser();

    // If still loading auth state, show a simple loading spinner
    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center transition-colors duration-200">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    // If not authenticated, redirect to login page
    if (!isAuthenticated) {
        return <Navigate to="/login" />;
    }

    // If authenticated, render the children
    return children;
};

const AppRouter = () => {
    return (
        <Router>
            <Routes>
                {/* Auth routes */}
                <Route path="/login" element={<AuthPage />} />
                <Route path="/register" element={<AuthPage />} />

                {/* Main Dashboard */}
                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <RevisedDashboard />
                        </ProtectedRoute>
                    }
                />

                {/* Redirect root to dashboard */}
                <Route path="/" element={<Navigate to="/dashboard" />} />

                {/* Catch all route */}
                <Route path="*" element={<Navigate to="/dashboard" />} />
            </Routes>
        </Router>
    );
};

export default AppRouter;