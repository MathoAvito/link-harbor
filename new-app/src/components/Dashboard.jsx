// src/components/Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { FiPlus, FiRefreshCw, FiAlertCircle } from 'react-icons/fi';
import { useLinks } from '../context/LinkContext';
import LinkCard from './LinkCard';
import LinkForm from './LinkForm';
import Sidebar from './Sidebar';
import SearchBar from './SearchBar';
import { useDebounce } from '../hooks/useDebounce';

const Dashboard = () => {
const { links, isLoading, addLink, editLink, removeLink, toggleFavorite, trackLinkClick } = useLinks();

  
  // State for filtered links
  const [filteredLinks, setFilteredLinks] = useState([]);
  
  // UI state
  const [isAdding, setIsAdding] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [currentLink, setCurrentLink] = useState(null);
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('grid');
  const [sortBy, setSortBy] = useState('date');
  const [sortOrder, setSortOrder] = useState('desc');
  
  // Filter and sort links when dependencies change
  useEffect(() => {
    // Get the appropriate links based on category
    let categoryLinks;
    if (activeCategory === 'all') {
      categoryLinks = [...links];
    } else if (activeCategory === 'favorites') {
      categoryLinks = links.filter(link => link.favorite);
    } else {
      categoryLinks = links.filter(link => link.category === activeCategory);
    }
    
    // Apply search filter
    let result = categoryLinks;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(link => 
        link.name.toLowerCase().includes(query) || 
        link.url.toLowerCase().includes(query) ||
        (link.description && link.description.toLowerCase().includes(query))
      );
    }
    
    // Apply sorting
    result.sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'clicks':
          comparison = (a.clicks || 0) - (b.clicks || 0);
          break;
        case 'date':
        default:
          comparison = new Date(a.date) - new Date(b.date);
          break;
      }
      
      return sortOrder === 'asc' ? comparison : -comparison;
    });
    
    setFilteredLinks(result);
  }, [links, activeCategory, searchQuery, sortBy, sortOrder]);
  
  // Handle add link
  const handleAddLink = async (linkData) => {
    try {
      await addLink(linkData);
      setIsAdding(false);
    } catch (error) {
      console.error('Error adding link:', error);
      // Could add toast notification here
    }
  };
  
  // Handle edit link
  const handleEditLink = (link) => {
    setCurrentLink(link);
    setIsEditing(true);
  };
  
  // Handle update link
  const handleUpdateLink = async (linkData) => {
    try {
      await editLink({ ...linkData, id: currentLink.id });
      setIsEditing(false);
      setCurrentLink(null);
    } catch (error) {
      console.error('Error updating link:', error);
    }
  };
  
  // Handle delete link
  const handleDeleteLink = async (id) => {
    if (window.confirm('Are you sure you want to delete this link?')) {
      try {
        await removeLink(id);
      } catch (error) {
        console.error('Error deleting link:', error);
      }
    }
  };
  
  // Handle link click
  const handleLinkClick = async (id) => {
    await trackLinkClick(id);
  };
  
  // Handle toggle favorite
  const handleToggleFavorite = async (id) => {
    await toggleFavorite(id);
  };
  
  // Handle search
  const handleSearch = (query) => {
    setSearchQuery(query);
  };
  
  // Handle sort change
  const handleSortChange = (newSortBy, newSortOrder) => {
    setSortBy(newSortBy);
    setSortOrder(newSortOrder);
  };
  
  // If in form mode, show the appropriate form
  if (isAdding) {
    return <LinkForm onAddLink={handleAddLink} onCancel={() => setIsAdding(false)} />;
  }
  
  if (isEditing && currentLink) {
    return (
      <LinkForm 
        onAddLink={handleUpdateLink} 
        onCancel={() => {
          setIsEditing(false);
          setCurrentLink(null);
        }} 
        initialData={currentLink}
      />
    );
  }
  
  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <Sidebar 
        activeCategory={activeCategory} 
        onCategoryChange={setActiveCategory}
        onAddLink={() => setIsAdding(true)}
      />
      
      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Search bar */}
        <SearchBar 
          onSearch={handleSearch}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={handleSortChange}
        />
        
        {/* Main content area */}
        <main className="flex-1 overflow-y-auto p-4">
          {/* Header with category name and count */}
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold text-gray-800 dark:text-white">
              {activeCategory === 'all' 
                ? 'All Links' 
                : activeCategory === 'favorites'
                  ? 'Favorite Links'
                  : `${activeCategory} Links`}
            </h2>
            
            <button 
              onClick={() => setIsAdding(true)}
              className="md:hidden btn btn-primary flex items-center"
            >
              <FiPlus className="mr-1" size={16} />
              Add
            </button>
          </div>
          
          {/* Loading state */}
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="animate-spin w-10 h-10 border-4 border-primary-500 border-t-transparent rounded-full"></div>
              <p className="mt-4 text-gray-600 dark:text-gray-400">Loading your links...</p>
            </div>
          ) : filteredLinks.length === 0 ? (
            // Empty state
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-full mb-4">
                <FiAlertCircle size={40} className="text-gray-500" />
              </div>
              
              <h3 className="text-xl font-medium text-gray-700 dark:text-gray-300 mb-2">
                {links.length === 0
                  ? "You haven't added any links yet"
                  : searchQuery
                    ? "No links match your search"
                    : `No links in ${activeCategory === 'favorites' ? 'favorites' : activeCategory}`}
              </h3>
              
              <p className="text-gray-500 dark:text-gray-400 max-w-md mb-6">
                {links.length === 0
                  ? "Start building your collection by adding your first link."
                  : searchQuery
                    ? "Try adjusting your search terms or clear the search."
                    : activeCategory === 'favorites'
                      ? "Mark links as favorites by clicking the star icon."
                      : "Try selecting a different category or add a new link."}
              </p>
              
              {links.length === 0 && (
                <button
                  onClick={() => setIsAdding(true)}
                  className="btn btn-primary flex items-center"
                >
                  <FiPlus className="mr-2" size={18} />
                  Add Your First Link
                </button>
              )}
            </div>
          ) : (
            // Links grid/list
            <div className={`grid gap-4 ${
              viewMode === 'grid' 
                ? 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
                : 'grid-cols-1'
            }`}>
              {filteredLinks.map(link => (
                <LinkCard
                  key={link.id}
                  link={link}
                  viewMode={viewMode}
                  onDelete={handleDeleteLink}
                  onEdit={handleEditLink}
                  onClick={() => handleLinkClick(link.id)}
                  onToggleFavorite={() => handleToggleFavorite(link.id)}
                />
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Dashboard;