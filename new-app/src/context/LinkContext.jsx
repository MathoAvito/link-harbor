// src/context/LinkContext.jsx
import React, { createContext, useState, useEffect, useContext } from 'react';
import { v4 as uuidv4 } from 'uuid';

const LinkContext = createContext();

export const LinkProvider = ({ children }) => {
    const [links, setLinks] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [categories, setCategories] = useState([]);

    // Load links from localStorage on mount
    useEffect(() => {
        const loadLinks = () => {
            setIsLoading(true);
            try {
                const storedLinks = localStorage.getItem('links');
                const linksData = storedLinks ? JSON.parse(storedLinks) : [];

                setLinks(linksData);

                // Extract unique categories
                const uniqueCategories = [...new Set(linksData
                    .map(link => link.category)
                    .filter(Boolean)
                )];

                setCategories(uniqueCategories);
            } catch (error) {
                console.error('Error loading links:', error);
            } finally {
                setIsLoading(false);
            }
        };

        loadLinks();
    }, []);

    // Save links to localStorage whenever they change
    useEffect(() => {
        localStorage.setItem('links', JSON.stringify(links));
    }, [links]);

    // Add a new link
    const addLink = async (linkData) => {
        try {
            // Create a new link with ID
            const newLink = {
                ...linkData,
                id: uuidv4()
            };

            // Update state
            setLinks(prevLinks => [...prevLinks, newLink]);

            // Update categories if needed
            if (linkData.category && !categories.includes(linkData.category)) {
                setCategories(prev => [...prev, linkData.category]);
            }

            return newLink;
        } catch (error) {
            console.error('Error adding link:', error);
            throw error;
        }
    };

    // Update a link
    const editLink = async (linkData) => {
        if (!linkData.id) {
            throw new Error('Link ID is required for updates');
        }

        try {
            // Update links state
            setLinks(prevLinks =>
                prevLinks.map(link => link.id === linkData.id ? { ...link, ...linkData } : link)
            );

            // Update categories if needed
            if (linkData.category && !categories.includes(linkData.category)) {
                setCategories(prev => [...prev, linkData.category]);
            }

            return linkData;
        } catch (error) {
            console.error('Error updating link:', error);
            throw error;
        }
    };

    // Delete a link
    const removeLink = async (id) => {
        try {
            setLinks(prevLinks => prevLinks.filter(link => link.id !== id));
            return true;
        } catch (error) {
            console.error('Error deleting link:', error);
            throw error;
        }
    };

    // Toggle favorite status
    const toggleFavorite = async (id) => {
        try {
            setLinks(prevLinks =>
                prevLinks.map(link =>
                    link.id === id ? { ...link, favorite: !link.favorite } : link
                )
            );

            // Return the updated link
            return links.find(link => link.id === id);
        } catch (error) {
            console.error('Error toggling favorite:', error);
            throw error;
        }
    };

    // Track link clicks
    const trackLinkClick = async (id) => {
        try {
            setLinks(prevLinks =>
                prevLinks.map(link =>
                    link.id === id ?
                        { ...link, clicks: (link.clicks || 0) + 1, lastClicked: new Date().toISOString() } :
                        link
                )
            );

            // Return the updated link
            return links.find(link => link.id === id);
        } catch (error) {
            console.error('Error tracking click:', error);
            throw error;
        }
    };

    // Additional utility functions
    const exportLinks = () => {
        try {
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

    const importLinks = (jsonData) => {
        try {
            if (!Array.isArray(jsonData)) {
                throw new Error('Invalid import data: Expected an array of links');
            }

            // Validate each link
            const validLinks = jsonData.filter(link =>
                link && typeof link === 'object' && link.url && link.name
            ).map(link => ({
                ...link,
                id: link.id || uuidv4()
            }));

            if (validLinks.length === 0) {
                throw new Error('No valid links found in import data');
            }

            // Merge with existing links, avoiding duplicates by URL
            const existingUrls = new Set(links.map(link => link.url));
            const newLinks = validLinks.filter(link => !existingUrls.has(link.url));

            setLinks(prev => [...prev, ...newLinks]);

            // Update categories
            const newCategories = [...new Set(validLinks
                .map(link => link.category)
                .filter(Boolean)
                .filter(cat => !categories.includes(cat))
            )];

            if (newCategories.length > 0) {
                setCategories(prev => [...prev, ...newCategories]);
            }

            return {
                imported: newLinks.length,
                total: links.length + newLinks.length
            };
        } catch (error) {
            console.error('Error importing links:', error);
            throw error;
        }
    };

    return (
        <LinkContext.Provider value={{
            links,
            categories,
            isLoading,
            addLink,
            editLink,
            removeLink,
            toggleFavorite,
            trackLinkClick,
            exportLinks,
            importLinks
        }}>
            {children}
        </LinkContext.Provider>
    );
};

export const useLinks = () => useContext(LinkContext);