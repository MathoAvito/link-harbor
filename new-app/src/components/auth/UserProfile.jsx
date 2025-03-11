// src/components/auth/UserProfile.jsx
import React, { useState } from 'react';
import { useUser } from '../../context/UserContext';

const UserProfile = ({ onClose }) => {
    const { user, updateProfile, logout, isLoading } = useUser();
    const [formData, setFormData] = useState({
        displayName: user?.displayName || '',
        email: user?.email || '',
        password: '',
        confirmPassword: '',
    });
    const [success, setSuccess] = useState('');
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

        // Email validation
        if (!formData.email.trim()) {
            errors.email = 'Email is required';
        } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
            errors.email = 'Please enter a valid email address';
        }

        // Password validation (only if user is trying to change password)
        if (formData.password) {
            if (formData.password.length < 6) {
                errors.password = 'Password must be at least 6 characters';
            }

            if (formData.password !== formData.confirmPassword) {
                errors.confirmPassword = 'Passwords do not match';
            }
        }

        setFieldErrors(errors);
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        // Validate form fields
        if (!validateForm()) {
            return;
        }

        try {
            // Only include password if it was provided
            const updateData = {
                displayName: formData.displayName,
                email: formData.email
            };

            if (formData.password) {
                updateData.password = formData.password;
            }

            await updateProfile(updateData);
            setSuccess('Profile updated successfully');

            // Clear password fields after successful update
            setFormData(prev => ({
                ...prev,
                password: '',
                confirmPassword: ''
            }));
        } catch (err) {
            setError(err.message || 'Failed to update profile. Please try again.');
        }
    };

    const handleLogout = async () => {
        try {
            await logout();
        } catch (err) {
            setError(err.message || 'Failed to logout. Please try again.');
        }
    };

    return (
        <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-6 w-full max-w-md mx-auto transition-colors duration-200">
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white transition-colors duration-200">
                    Your Profile
                </h2>
                <button
                    onClick={onClose}
                    className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors duration-200"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>

            {success && (
                <div className="mb-4 p-3 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-md transition-colors duration-200">
                    {success}
                </div>
            )}

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
                        disabled={isLoading}
                    />
                    {fieldErrors.displayName && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.displayName}</p>
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
                        disabled={isLoading}
                    />
                    {fieldErrors.email && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.email}</p>
                    )}
                </div>

                <div className="mb-4">
                    <h3 className="text-lg font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors duration-200">
                        Change Password (optional)
                    </h3>
                    <div className="h-px bg-gray-200 dark:bg-gray-700 w-full mb-4 transition-colors duration-200"></div>
                </div>

                {/* Password */}
                <div className="mb-4">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="password">
                        New Password
                    </label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.password ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        placeholder="Leave empty to keep current password"
                        disabled={isLoading}
                    />
                    {fieldErrors.password && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.password}</p>
                    )}
                </div>

                {/* Confirm Password */}
                <div className="mb-6">
                    <label className="block text-gray-700 dark:text-gray-300 font-medium mb-2 transition-colors duration-200" htmlFor="confirmPassword">
                        Confirm New Password
                    </label>
                    <input
                        type="password"
                        id="confirmPassword"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        className={`w-full px-4 py-2 border ${fieldErrors.confirmPassword ? 'border-red-500 dark:border-red-400' : 'border-gray-300 dark:border-gray-600'} rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors duration-200`}
                        disabled={isLoading}
                    />
                    {fieldErrors.confirmPassword && (
                        <p className="mt-1 text-sm text-red-600 dark:text-red-400">{fieldErrors.confirmPassword}</p>
                    )}
                </div>

                {/* Form Actions */}
                <div className="flex justify-between">
                    <button
                        type="button"
                        onClick={handleLogout}
                        className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-red-600 dark:text-red-400 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors duration-200"
                        disabled={isLoading}
                    >
                        Log Out
                    </button>

                    <div className="flex space-x-2">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-200"
                            disabled={isLoading}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-4 py-2 bg-blue-600 dark:bg-blue-700 text-white rounded-md hover:bg-blue-700 dark:hover:bg-blue-600 transition-colors duration-200 flex items-center"
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <>
                                    <span className="animate-spin mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full"></span>
                                    Saving...
                                </>
                            ) : (
                                'Save Changes'
                            )}
                        </button>
                    </div>
                </div>
            </form>
        </div>
    );
};

export default UserProfile;