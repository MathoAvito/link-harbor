// src/context/LinkContext.jsx
import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { useUser } from './UserContext';
import * as linkService from '../services/linkService';

// Create context
const LinkContext = createContext();

export const LinkProvider = ({ children }) => {
    const [links, setLinks] = useState([]);
    const [categories, setCategories] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const { user } = useUser();

    // Load links when component mounts or user changes
    const fetchLinks = useCallback(async () => {
        setIsLoading(true);
        try {
            const fetchedLinks = await linkService.getLinks();
            setLinks(fetchedLinks);

            // Extract unique categories
            const uniqueCategories = [...new Set(fetchedLinks
                .map(link => link.category)
                .filter(category => category && category !== 'Uncategorized')
            )];
            setCategories(uniqueCategories);

            setError(null);
        } catch (err) {
            console.error('Error fetching links:', err);
            setError('Failed to load links. Please try again.');
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Fetch links when component mounts or user changes
    useEffect(() => {
        fetchLinks();
    }, [fetchLinks, user]);

    // Add new link
    const addLink = async (linkData) => {
        try {
            const newLink = await linkService.saveLink(linkData);

            // Update state with new link
            setLinks(prevLinks => [...prevLinks, newLink]);

            // Update categories if needed
            if (linkData.category && !categories.includes(linkData.category) && linkData.category !== 'Uncategorized') {
                setCategories(prevCategories => [...prevCategories, linkData.category]);
            }

            return newLink;
        } catch (err) {
            console.error('Error adding link:', err);
            setError('Failed to add link. Please try again.');
            throw err;
        }
    };

    // Edit existing link
    const editLink = async (linkData) => {
        try {
            const updatedLink = await linkService.updateLink(linkData);

            // Update state with edited link
            setLinks(prevLinks =>
                prevLinks.map(link =>
                    link.id === linkData.id ? updatedLink : link
                )
            );

            // Update categories if needed
            if (linkData.category && !categories.includes(linkData.category) && linkData.category !== 'Uncategorized') {
                setCategories(prevCategories => [...prevCategories, linkData.category]);
            }

            return updatedLink;
        } catch (err) {
            console.error('Error editing link:', err);
            setError('Failed to update link. Please try again.');
            throw err;
        }
    };

    // Remove link
    const removeLink = async (id) => {
        try {
            await linkService.deleteLink(id);

            // Update state by filtering out removed link
            setLinks(prevLinks => prevLinks.filter(link => link.id !== id));

            // Recalculate categories
            const remainingLinks = links.filter(link => link.id !== id);
            const remainingCategories = [...new Set(remainingLinks
                .map(link => link.category)
                .filter(category => category && category !== 'Uncategorized')
            )];
            setCategories(remainingCategories);

            return true;
        } catch (err) {
            console.error('Error removing link:', err);
            setError('Failed to delete link. Please try again.');
            throw err;
        }
    };

    // Toggle favorite status
    const toggleFavorite = async (id) => {
        try {
            // Find the link
            const link = links.find(link => link.id === id);
            if (!link) throw new Error(`Link with ID ${id} not found`);

            // Toggle favorite status
            const updatedLink = {
                ...link,
                favorite: !link.favorite
            };

            // Update the link
            await linkService.updateLink(updatedLink);

            // Update state
            setLinks(prevLinks =>
                prevLinks.map(link =>
                    link.id === id ? { ...link, favorite: !link.favorite } : link
                )
            );

            return updatedLink;
        } catch (err) {
            console.error('Error toggling favorite:', err);
            setError('Failed to update favorite status. Please try again.');
            throw err;
        }
    };

    // Track link click
    const trackLinkClick = async (id) => {
        try {
            // Call service to increment click count
            const updatedLink = await linkService.incrementClickCount(id);

            // Update state
            setLinks(prevLinks =>
                prevLinks.map(link =>
                    link.id === id ? updatedLink : link
                )
            );

            return updatedLink;
        } catch (err) {
            console.error('Error tracking link click:', err);
            // Don't set user-visible error for click tracking
            return false;
        }
    };

    // Context value
    const value = {
        links,
        categories,
        isLoading,
        error,
        addLink,
        editLink,
        removeLink,
        toggleFavorite,
        trackLinkClick,
        refreshLinks: fetchLinks
    };

    return (
        <LinkContext.Provider value={value}>
            {children}
        </LinkContext.Provider>
    );
};

// Custom hook to use the link context
export const useLinks = () => {
    const context = useContext(LinkContext);

    if (context === undefined) {
        throw new Error('useLinks must be used within a LinkProvider');
    }

    return context;
};

export default LinkContext;