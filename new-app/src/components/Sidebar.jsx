// src/components/Sidebar.jsx
import React from 'react';
import { FiHome, FiFolder, FiBookmark, FiStar, FiSettings, FiPlus } from 'react-icons/fi';
import { useLinks } from '../context/LinkContext';
import ThemeToggle from './ThemeToggle';

const Sidebar = ({ activeCategory, onCategoryChange, onAddLink }) => {
  const { categories, links } = useLinks();
  
  // Count links by category
  const getCategoryCount = (category) => {
    if (category === 'all') {
      return links.length;
    } else if (category === 'favorites') {
      return links.filter(link => link.favorite).length;
    } else {
      return links.filter(link => link.category === category).length;
    }
  };
  
  return (
    <div className="h-screen bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 w-64 flex flex-col">
      {/* Logo/header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h1 className="text-xl font-bold text-primary-600 dark:text-primary-400">Link Harbor</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">Your personal link dashboard</p>
      </div>
      
      {/* Add Button */}
      <div className="p-4">
        <button 
          onClick={onAddLink} 
          className="btn btn-primary w-full flex items-center justify-center gap-2"
        >
          <FiPlus size={16} />
          <span>Add New Link</span>
        </button>
      </div>
      
      {/* Navigation */}
      <nav className="flex-grow overflow-y-auto p-2">
        <div className="mb-1 px-3 py-2 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">
          Browse
        </div>
        
        <button
          className={`flex items-center w-full px-3 py-2 rounded-md transition-colors ${
            activeCategory === 'all' 
              ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400' 
              : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/30'
          }`}
          onClick={() => onCategoryChange('all')}
        >
          <FiHome className="mr-3" size={18} />
          <span>All Links</span>
          <span className="ml-auto bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 text-xs px-2 py-1 rounded-full">
            {getCategoryCount('all')}
          </span>
        </button>
        
        <button
          className={`flex items-center w-full px-3 py-2 rounded-md transition-colors ${
            activeCategory === 'favorites' 
              ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400' 
              : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/30'
          }`}
          onClick={() => onCategoryChange('favorites')}
        >
          <FiStar className="mr-3" size={18} />
          <span>Favorites</span>
          <span className="ml-auto bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 text-xs px-2 py-1 rounded-full">
            {getCategoryCount('favorites')}
          </span>
        </button>
        
        {/* Categories */}
        {categories.length > 0 && (
          <>
            <div className="mt-4 mb-1 px-3 py-2 text-xs font-medium text-gray-600 dark:text-gray-400 uppercase">
              Categories
            </div>
            
            {categories.map(category => (
              <button
                key={category}
                className={`flex items-center w-full px-3 py-2 rounded-md transition-colors ${
                  activeCategory === category 
                    ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-400' 
                    : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700/30'
                }`}
                onClick={() => onCategoryChange(category)}
              >
                <FiFolder className="mr-3" size={18} />
                <span className="truncate">{category}</span>
                <span className="ml-auto bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 text-xs px-2 py-1 rounded-full">
                  {getCategoryCount(category)}
                </span>
              </button>
            ))}
          </>
        )}
      </nav>
      
      {/* Footer */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <ThemeToggle />
        <button className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300">
          <FiSettings size={18} />
        </button>
      </div>
    </div>
  );
};

export default Sidebar;