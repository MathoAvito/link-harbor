// src/services/linkService.js
import { v4 as uuidv4 } from 'uuid';
import { getCurrentUser } from './userService';

/**
 * Get storage key for current user
 * @returns {string} - Storage key for current user's links
 */
const getUserLinksKey = () => {
    const currentUser = getCurrentUser();
    return currentUser ? `link_harbor_links_${currentUser.id}` : 'link_harbor_links_guest';
};

/**
 * Get all links from storage for current user
 */
export const getLinks = async () => {
    try {
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 300));

        const linksKey = getUserLinksKey();
        const linksJson = localStorage.getItem(linksKey);
        return linksJson ? JSON.parse(linksJson) : [];
    } catch (error) {
        console.error('Error retrieving links from storage:', error);
        return [];
    }
};

/**
 * Save a new link
 */
export const saveLink = async (linkData) => {
    try {
        // Get existing links
        const existingLinks = await getLinks();

        // Create new link object with ID
        const newLink = {
            ...linkData,
            id: uuidv4(),
            date: linkData.date || new Date().toISOString(),
            clicks: linkData.clicks || 0,
            favorite: linkData.favorite || false,
        };

        // Add to array and save
        const updatedLinks = [...existingLinks, newLink];
        localStorage.setItem(getUserLinksKey(), JSON.stringify(updatedLinks));

        return newLink;
    } catch (error) {
        console.error('Error saving link:', error);
        throw error;
    }
};

/**
 * Update an existing link
 */
export const updateLink = async (linkData) => {
    try {
        if (!linkData.id) {
            throw new Error('Link ID is required for updates');
        }

        // Get existing links
        const existingLinks = await getLinks();

        // Find the link to update
        const linkIndex = existingLinks.findIndex(link => link.id === linkData.id);

        if (linkIndex === -1) {
            throw new Error(`Link with ID ${linkData.id} not found`);
        }

        // Update the link
        const updatedLinks = [...existingLinks];
        updatedLinks[linkIndex] = {
            ...existingLinks[linkIndex],
            ...linkData,
            lastUpdated: new Date().toISOString()
        };

        // Save changes
        localStorage.setItem(getUserLinksKey(), JSON.stringify(updatedLinks));

        return updatedLinks[linkIndex];
    } catch (error) {
        console.error('Error updating link:', error);
        throw error;
    }
};

/**
 * Delete a link by ID
 */
export const deleteLink = async (id) => {
    try {
        // Get existing links
        const existingLinks = await getLinks();

        // Filter out the link to delete
        const updatedLinks = existingLinks.filter(link => link.id !== id);

        // Save changes
        localStorage.setItem(getUserLinksKey(), JSON.stringify(updatedLinks));

        return true;
    } catch (error) {
        console.error('Error deleting link:', error);
        throw error;
    }
};

/**
 * Increment click count for a link
 */
export const incrementClickCount = async (id) => {
    try {
        // Get existing links
        const existingLinks = await getLinks();

        // Find the link to update
        const linkIndex = existingLinks.findIndex(link => link.id === id);

        if (linkIndex === -1) {
            throw new Error(`Link with ID ${id} not found`);
        }

        // Increment click count
        const updatedLinks = [...existingLinks];
        updatedLinks[linkIndex] = {
            ...existingLinks[linkIndex],
            clicks: (existingLinks[linkIndex].clicks || 0) + 1,
            lastClicked: new Date().toISOString()
        };

        // Save changes
        localStorage.setItem(getUserLinksKey(), JSON.stringify(updatedLinks));

        return updatedLinks[linkIndex];
    } catch (error) {
        console.error('Error incrementing click count:', error);
        throw error;
    }
};

/**
 * Export links to JSON file
 */
export const exportLinks = async () => {
    try {
        const links = await getLinks();
        const dataStr = JSON.stringify(links, null, 2);
        const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;

        const exportFileDefaultName = `link_harbor_export_${new Date().toISOString().slice(0, 10)}.json`;

        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();

        return true;
    } catch (error) {
        console.error('Error exporting links:', error);
        throw error;
    }
};

/**
 * Import links from JSON file
 */
export const importLinks = async (jsonData) => {
    try {
        if (!Array.isArray(jsonData)) {
            throw new Error('Invalid import data: Expected an array of links');
        }

        // Validate imported data
        const validLinks = jsonData.filter(link =>
            link && typeof link === 'object' && link.url && link.name
        ).map(link => ({
            ...link,
            id: link.id || uuidv4(), // Ensure all links have an ID
            date: link.date || new Date().toISOString()
        }));

        if (validLinks.length === 0) {
            throw new Error('No valid links found in import data');
        }

        // Get existing links
        const existingLinks = await getLinks();

        // Merge links, avoiding duplicates by URL
        const existingUrls = new Set(existingLinks.map(link => link.url));
        const newLinks = validLinks.filter(link => !existingUrls.has(link.url));

        const mergedLinks = [...existingLinks, ...newLinks];

        // Save changes
        localStorage.setItem(getUserLinksKey(), JSON.stringify(mergedLinks));

        return {
            imported: newLinks.length,
            total: mergedLinks.length
        };
    } catch (error) {
        console.error('Error importing links:', error);
        throw error;
    }
};