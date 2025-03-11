// src/components/auth/RegistrationForm.jsx
import React, { useState } from 'react';
import { useUser } from '../../context/UserContext';

const RegistrationForm = ({ onLoginClick, onRegisterSuccess }) => {
    const { register, isLoading } = useUser();
    const [formData, setFormData] = useState({
        displayName: '',
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [error, setError] = useState('');
    const [fieldErrors, setFieldErrors] = useState({});

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        // Clear field error when user types
        if (fieldErrors[name]) {
            setFieldErrors((prev) => ({ ...prev, [name]: '' }));
        }
    };

    const validateForm = () => {
        const errors = {};

        // Display name validation
        if (!formData.displayName.trim()) {
            errors.displayName = 'Display name is required';
        }

        // Username validation
        if (!formData.username.trim()) {
            errors.username = 'Username is required';
        } else if (formData.username.length < 3) {
            errors.username = 'Username must be at least 3 characters';
        } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
            errors.username = 'Username can only contain letters, numbers, and underscores';
        }

        // Email validation
        if (!formData.email.trim()) {
            errors.email = 'Email is required';
        } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
            errors.email = 'Please enter a valid email address';
        }

        // Password validation
        if (!formData.password) {
            errors.password = 'Password is required';
        } else if (formData.password.length < 6) {
            errors.password = 'Password must be at least 6 characters';
        }

        // Confirm password validation
        if (formData.password !== formData.confirmPassword) {
            errors.confirmPassword = 'Passwords do not match';
        }

        setFieldErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validate form fields
        if (!validateForm()) {
            return;
        }

        try {
            // Extract confirm password before sending
            const { confirmPassword, ...userData } = formData;

            await register(userData);
            if (onRegisterSuccess) onRegisterSuccess();
        } catch (err) {
            setError(err.message || 'Registration failed. Please try again.');
        }
    };

    return (
        <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-6 w-full max-w-md mx-auto transition-colors duration-200">
            <div className="text-center mb-8">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white transition-colors duration-200">
                    Create Account
                </h2>
                <p className="text-gray-600 dark:text-gray-400 mt-2 transition-colors duration-200">
                    Join Link Harbor to manage your links
                </p>
            </div>

            {error && (
                <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-md transition-colors duration-200">
                    {error}
                </div>
            )}

            <form onSubmit={handleSubmit}>
                {/* Display Name */}
                <div className="mb-4">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="displayName">
                        Display Name
                    </label>
                    <input
                        type="text"
                        id="displayName"
                        name="displayName"
                        value={formData.displayName}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.displayName ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="Your full name"
                        disabled={isLoading}
                    />
                    {fieldErrors.displayName && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.displayName}</p>
                    )}
                </div>

                {/* Username */}
                <div className="mb-4">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="username">
                        Username
                    </label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.username ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="Choose a username"
                        disabled={isLoading}
                    />
                    {fieldErrors.username && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.username}</p>
                    )}
                </div>

                {/* Email */}
                <div className="mb-4">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="email">
                        Email
                    </label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.email ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="your.email@example.com"
                        disabled={isLoading}
                    />
                    {fieldErrors.email && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.email}</p>
                    )}
                </div>

                {/* Password */}
                <div className="mb-4">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="password">
                        Password
                    </label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.password ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="Create a password"
                        disabled={isLoading}
                    />
                    {fieldErrors.password && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.password}</p>
                    )}
                </div>

                {/* Confirm Password */}
                <div className="mb-6">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="confirmPassword">
                        Confirm Password
                    </label>
                    <input
                        type="password"
                        id="confirmPassword"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.confirmPassword ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="Confirm your password"
                        disabled={isLoading}
                    />
                    {fieldErrors.confirmPassword && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.confirmPassword}</p>
                    )}
                </div>

                <button
                    type="submit"
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 flex justify-center items-center"
                    disabled={isLoading}
                >
                    {isLoading ? (
                        <>
                            <span className="animate-spin mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full"></span>
                            Creating Account...
                        </>
                    ) : (
                        'Create Account'
                    )}
                </button>
            </form>

            <div className="mt-6 text-center">
                <p className="text-gray-600 dark:text-gray-400 transition-colors duration-200">
                    Already have an account?{' '}
                    <button
                        onClick={onLoginClick}
                        className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors duration-200"
                        disabled={isLoading}
                    >
                        Sign In
                    </button>
                </p>
            </div>
        </div>
    );
};

export default RegistrationForm;