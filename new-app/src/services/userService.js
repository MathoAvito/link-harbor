// src/services/userService.js
import { v4 as uuidv4 } from 'uuid';
import CryptoJS from 'crypto-js'; // You'll need to install this package

// Storage keys
const USERS_STORAGE_KEY = 'link_harbor_users';
const CURRENT_USER_KEY = 'link_harbor_current_user';

/**
 * Hash a password for storage
 * @param {string} password - The plain text password
 * @returns {string} - Hashed password
 */
const hashPassword = (password) => {
    return CryptoJS.SHA256(password).toString();
};

/**
 * Get all users from storage
 */
export const getUsers = () => {
    try {
        const usersJson = localStorage.getItem(USERS_STORAGE_KEY);
        return usersJson ? JSON.parse(usersJson) : [];
    } catch (error) {
        console.error('Error retrieving users from storage:', error);
        return [];
    }
};

/**
 * Get current logged in user
 */
export const getCurrentUser = () => {
    try {
        const userJson = localStorage.getItem(CURRENT_USER_KEY);
        return userJson ? JSON.parse(userJson) : null;
    } catch (error) {
        console.error('Error retrieving current user:', error);
        return null;
    }
};

/**
 * Register a new user
 */
export const registerUser = async (userData) => {
    try {
        // Get existing users
        const existingUsers = getUsers();

        // Check if username or email already exists
        const userExists = existingUsers.some(
            user => user.username === userData.username || user.email === userData.email
        );

        if (userExists) {
            throw new Error('Username or email already exists');
        }

        // Create new user object with ID and hashed password
        const newUser = {
            id: uuidv4(),
            username: userData.username,
            email: userData.email,
            passwordHash: hashPassword(userData.password),
            displayName: userData.displayName || userData.username,
            createdAt: new Date().toISOString(),
            settings: {
                defaultCategory: 'all',
                defaultViewMode: 'grid',
                defaultSort: 'date',
                defaultSortOrder: 'desc'
            }
        };

        // Remove plain text password before storing
        delete newUser.password;

        // Add to array and save
        const updatedUsers = [...existingUsers, newUser];
        localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(updatedUsers));

        // Return user without password hash
        const { passwordHash, ...userWithoutPassword } = newUser;
        return userWithoutPassword;
    } catch (error) {
        console.error('Error registering user:', error);
        throw error;
    }
};

/**
 * Login a user
 */
export const loginUser = async (credentials) => {
    try {
        // Get all users
        const users = getUsers();

        // Find user by username
        const user = users.find(user => user.username === credentials.username);

        if (!user) {
            throw new Error('Invalid username or password');
        }

        // Check password
        const hashedPassword = hashPassword(credentials.password);

        if (user.passwordHash !== hashedPassword) {
            throw new Error('Invalid username or password');
        }

        // Create session user object (without password hash)
        const { passwordHash, ...userWithoutPassword } = user;
        const sessionUser = {
            ...userWithoutPassword,
            lastLogin: new Date().toISOString()
        };

        // Save current user to localStorage
        localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(sessionUser));

        return sessionUser;
    } catch (error) {
        console.error('Error logging in:', error);
        throw error;
    }
};

/**
 * Logout current user
 */
export const logoutUser = () => {
    try {
        localStorage.removeItem(CURRENT_USER_KEY);
        return true;
    } catch (error) {
        console.error('Error logging out:', error);
        throw error;
    }
};

/**
 * Update user profile
 */
export const updateUserProfile = async (userData) => {
    try {
        // Get current user and all users
        const currentUser = getCurrentUser();
        const users = getUsers();

        if (!currentUser) {
            throw new Error('No user is currently logged in');
        }

        // Find user index
        const userIndex = users.findIndex(user => user.id === currentUser.id);

        if (userIndex === -1) {
            throw new Error('User not found');
        }

        // Update user data
        const updatedUser = {
            ...users[userIndex],
            displayName: userData.displayName || users[userIndex].displayName,
            email: userData.email || users[userIndex].email,
            settings: {
                ...users[userIndex].settings,
                ...userData.settings
            },
            updatedAt: new Date().toISOString()
        };

        // Update password if provided
        if (userData.password) {
            updatedUser.passwordHash = hashPassword(userData.password);
        }

        // Update users array
        const updatedUsers = [...users];
        updatedUsers[userIndex] = updatedUser;

        // Save to localStorage
        localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(updatedUsers));

        // Update current user
        const { passwordHash, ...userWithoutPassword } = updatedUser;
        localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(userWithoutPassword));

        return userWithoutPassword;
    } catch (error) {
        console.error('Error updating user profile:', error);
        throw error;
    }
};