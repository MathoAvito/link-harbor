// src/components/SearchBar.jsx
import React, { useState } from 'react';
import { FiSearch, FiX, FiFilter, FiGrid, FiList, FiArrowUp, FiArrowDown } from 'react-icons/fi';
import { useDebounce } from '../hooks/useDebounce';

const SearchBar = ({ 
  onSearch, 
  viewMode, 
  onViewModeChange, 
  sortBy, 
  sortOrder, 
  onSortChange 
}) => {
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 300);
  
  // Apply debounced search
  React.useEffect(() => {
    onSearch(debouncedQuery);
  }, [debouncedQuery, onSearch]);
  
  const handleClearSearch = () => {
    setQuery('');
    onSearch('');
  };

  return (
    <div className="sticky top-0 z-10 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 py-3 px-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        {/* Search input */}
        <div className="relative flex-grow max-w-2xl">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <FiSearch className="text-gray-400" size={18} />
          </div>
          
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search links..."
            className="input pl-10 pr-10"
          />
          
          {query && (
            <button
              onClick={handleClearSearch}
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
            >
              <FiX className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" size={18} />
            </button>
          )}
        </div>
        
        {/* Controls (View mode, Sort) */}
        <div className="flex items-center gap-2">
          {/* View mode toggle */}
          <div className="flex border border-gray-300 dark:border-gray-600 rounded-md overflow-hidden">
            <button
              onClick={() => onViewModeChange('grid')}
              className={`p-2 ${
                viewMode === 'grid' 
                  ? 'bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="Grid view"
            >
              <FiGrid size={18} />
            </button>
            <button
              onClick={() => onViewModeChange('list')}
              className={`p-2 ${
                viewMode === 'list' 
                  ? 'bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-400' 
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="List view"
            >
              <FiList size={18} />
            </button>
          </div>
          
          {/* Sort controls */}
          <div className="flex">
            <select
              value={sortBy}
              onChange={(e) => onSortChange(e.target.value, sortOrder)}
              className="input py-2 border-r-0 rounded-r-none"
            >
              <option value="date">Date Added</option>
              <option value="name">Name</option>
              <option value="clicks">Clicks</option>
            </select>
            
            <button
              onClick={() => onSortChange(sortBy, sortOrder === 'asc' ? 'desc' : 'asc')}
              className="px-3 py-2 border border-l-0 border-gray-300 dark:border-gray-600 rounded-l-none rounded-md bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
              title={sortOrder === 'asc' ? 'Ascending' : 'Descending'}
            >
              {sortOrder === 'asc' ? (
                <FiArrowUp className="text-gray-600 dark:text-gray-400" />
              ) : (
                <FiArrowDown className="text-gray-600 dark:text-gray-400" />
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SearchBar;