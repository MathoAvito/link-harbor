import React, { createContext, useState, useEffect, useContext } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { getLinks, saveLink, updateLink, deleteLink, incrementClickCount } from '../services/linkService';

const LinkContext = createContext();

export const LinkProvider = ({ children }) => {
  const [links, setLinks] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [categories, setCategories] = useState([]);

  // Load links on mount
  useEffect(() => {
    const fetchLinks = async () => {
      setIsLoading(true);
      try {
        const data = await getLinks();
        setLinks(data);
        
        // Extract categories
        const uniqueCategories = [...new Set(data.map(link => link.category).filter(Boolean))];
        setCategories(uniqueCategories);
      } catch (error) {
        console.error('Error fetching links:', error);
      } finally {
        setIsLoading(false);
      }
    };
    
    fetchLinks();
  }, []);

  // Add a link
  const addLink = async (linkData) => {
    try {
      const newLink = await saveLink(linkData);
      setLinks(prevLinks => [...prevLinks, newLink]);
      
      // Update categories if needed
      if (linkData.category && !categories.includes(linkData.category)) {
        setCategories(prevCategories => [...prevCategories, linkData.category]);
      }
      
      return newLink;
    } catch (error) {
      console.error('Error adding link:', error);
      throw error;
    }
  };

  // Update a link
  const editLink = async (linkData) => {
    try {
      const updatedLink = await updateLink(linkData);
      setLinks(prevLinks => 
        prevLinks.map(link => link.id === updatedLink.id ? updatedLink : link)
      );
      
      // Update categories if needed
      if (linkData.category && !categories.includes(linkData.category)) {
        setCategories(prevCategories => [...prevCategories, linkData.category]);
      }
      
      return updatedLink;
    } catch (error) {
      console.error('Error updating link:', error);
      throw error;
    }
  };

  // Remove a link
  const removeLink = async (id) => {
    try {
      await deleteLink(id);
      setLinks(prevLinks => prevLinks.filter(link => link.id !== id));
      return true;
    } catch (error) {
      console.error('Error deleting link:', error);
      throw error;
    }
  };

  // Track link click
  const trackLinkClick = async (id) => {
    try {
      const updatedLink = await incrementClickCount(id);
      setLinks(prevLinks => 
        prevLinks.map(link => link.id === updatedLink.id ? updatedLink : link)
      );
      return updatedLink;
    } catch (error) {
      console.error('Error tracking link click:', error);
      // Don't throw here to avoid interrupting user flow
      return null;
    }
  };

  // Toggle favorite status
  const toggleFavorite = async (id) => {
    const link = links.find(link => link.id === id);
    if (!link) return null;
    
    try {
      const updatedLink = await updateLink({
        ...link,
        favorite: !link.favorite
      });
      
      setLinks(prevLinks => 
        prevLinks.map(link => link.id === updatedLink.id ? updatedLink : link)
      );
      
      return updatedLink;
    } catch (error) {
      console.error('Error toggling favorite:', error);
      throw error;
    }
  };

  // Filter links
  const filterLinks = (query, category) => {
    if (!query && !category) return links;
    
    return links.filter(link => {
      const matchesQuery = !query || 
        link.name.toLowerCase().includes(query.toLowerCase()) ||
        link.url.toLowerCase().includes(query.toLowerCase()) ||
        (link.description && link.description.toLowerCase().includes(query.toLowerCase()));
      
      const matchesCategory = !category || link.category === category;
      
      return matchesQuery && matchesCategory;
    });
  };

  return (
    <LinkContext.Provider value={{
      links,
      categories,
      isLoading,
      addLink,
      editLink,
      removeLink,
      trackLinkClick,
      toggleFavorite,
      filterLinks
    }}>
      {children}
    </LinkContext.Provider>
  );
};

export const useLinks = () => useContext(LinkContext);