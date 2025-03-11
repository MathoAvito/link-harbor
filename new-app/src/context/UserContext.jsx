// src/context/UserContext.jsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { getCurrentUser, loginUser, registerUser, logoutUser, updateUserProfile } from '../services/userService';

// Create context
const UserContext = createContext();

export const UserProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    // Check if user is already logged in on mount
    useEffect(() => {
        const initializeAuth = () => {
            try {
                const currentUser = getCurrentUser();
                setUser(currentUser);
                setIsLoading(false);
            } catch (error) {
                console.error('Error initializing auth:', error);
                setError(error.message);
                setIsLoading(false);
            }
        };

        initializeAuth();
    }, []);

    // Login handler
    const login = async (credentials) => {
        setIsLoading(true);
        setError(null);

        try {
            const loggedInUser = await loginUser(credentials);
            setUser(loggedInUser);
            return loggedInUser;
        } catch (error) {
            setError(error.message);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    // Register handler
    const register = async (userData) => {
        setIsLoading(true);
        setError(null);

        try {
            const newUser = await registerUser(userData);
            // Auto login after registration
            await login({ username: userData.username, password: userData.password });
            return newUser;
        } catch (error) {
            setError(error.message);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    // Logout handler
    const logout = async () => {
        setIsLoading(true);

        try {
            await logoutUser();
            setUser(null);
        } catch (error) {
            setError(error.message);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    // Update profile handler
    const updateProfile = async (userData) => {
        setIsLoading(true);
        setError(null);

        try {
            const updatedUser = await updateUserProfile(userData);
            setUser(updatedUser);
            return updatedUser;
        } catch (error) {
            setError(error.message);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    // Context value
    const value = {
        user,
        isLoading,
        error,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        updateProfile
    };

    return (
        <UserContext.Provider value={value}>
            {children}
        </UserContext.Provider>
    );
};

// Custom hook to use the auth context
export const useUser = () => {
    const context = useContext(UserContext);

    if (context === undefined) {
        throw new Error('useUser must be used within a UserProvider');
    }

    return context;
};

export default UserContext;