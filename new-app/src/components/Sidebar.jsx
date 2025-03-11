// src/components/Sidebar.jsx
import React from 'react';
import { useLinks } from '../context/LinkContext';

const Sidebar = ({ activeCategory, onCategoryChange, onAddLink }) => {
  const { links, categories } = useLinks();
  
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
    <div className="w-64 bg-gray-900 text-white h-screen flex flex-col">
      {/* Logo/header */}
      <div className="p-4">
        <h1 className="text-xl font-bold">Link Harbor</h1>
        <p className="text-sm text-gray-400">Your personal link dashboard</p>
      </div>
      
      {/* Add Button */}
      <div className="p-4">
        <button 
          onClick={onAddLink} 
          className="flex items-center w-full p-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md"
        >
          <span className="mr-2">+</span>
          <span>Add New Link</span>
        </button>
      </div>
      
      {/* Navigation */}
      <div className="flex-grow overflow-y-auto p-4">
        <div className="uppercase text-xs font-semibold text-gray-500 mb-2">BROWSE</div>
        
        <button
          className={`flex items-center w-full p-2 rounded-md mb-1 ${
            activeCategory === 'all' ? 'bg-gray-700' : 'hover:bg-gray-800'
          }`}
          onClick={() => onCategoryChange('all')}
        >
          <span className="mr-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z" />
            </svg>
          </span>
          <span>All Links</span>
          <span className="ml-auto bg-gray-800 px-2 py-1 rounded-full text-xs">
            {getCategoryCount('all')}
          </span>
        </button>
        
        <button
          className={`flex items-center w-full p-2 rounded-md mb-1 ${
            activeCategory === 'favorites' ? 'bg-gray-700' : 'hover:bg-gray-800'
          }`}
          onClick={() => onCategoryChange('favorites')}
        >
          <span className="mr-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
            </svg>
          </span>
          <span>Favorites</span>
          <span className="ml-auto bg-gray-800 px-2 py-1 rounded-full text-xs">
            {getCategoryCount('favorites')}
          </span>
        </button>
        
        {/* Categories */}
        {categories.length > 0 && (
          <>
            <div className="uppercase text-xs font-semibold text-gray-500 mt-4 mb-2">CATEGORIES</div>
            
            {categories.map(category => (
              <button
                key={category}
                className={`flex items-center w-full p-2 rounded-md mb-1 ${
                  activeCategory === category ? 'bg-gray-700' : 'hover:bg-gray-800'
                }`}
                onClick={() => onCategoryChange(category)}
              >
                <span className="mr-2">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                  </svg>
                </span>
                <span className="truncate">{category}</span>
                <span className="ml-auto bg-gray-800 px-2 py-1 rounded-full text-xs">
                  {getCategoryCount(category)}
                </span>
              </button>
            ))}
          </>
        )}
      </div>
    </div>
  );
};

export default Sidebar;