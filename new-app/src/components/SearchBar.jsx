// src/components/SearchBar.jsx
import React from 'react';

const SearchBar = ({
    onSearch,
    viewMode,
    onViewModeChange,
    sortBy,
    sortOrder,
    onSortChange
}) => {
    return (
        <div className="bg-white border-b border-gray-200 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between">
            {/* Search input */}
            <div className="relative w-full sm:w-auto mb-2 sm:mb-0 sm:mr-4">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </div>
                <input
                    type="text"
                    placeholder="Search links..."
                    className="pl-10 pr-4 py-2 w-full sm:w-64 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    onChange={(e) => onSearch(e.target.value)}
                />
            </div>

            {/* Controls */}
            <div className="flex items-center space-x-2 w-full sm:w-auto justify-between sm:justify-start">
                {/* View toggle */}
                <div className="flex border border-gray-300 rounded-md overflow-hidden">
                    <button
                        onClick={() => onViewModeChange('grid')}
                        className={`p-2 ${viewMode === 'grid' ? 'bg-gray-100 text-gray-800' : 'text-gray-500'}`}
                        title="Grid view"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                        </svg>
                    </button>
                    <button
                        onClick={() => onViewModeChange('list')}
                        className={`p-2 ${viewMode === 'list' ? 'bg-gray-100 text-gray-800' : 'text-gray-500'}`}
                        title="List view"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                        </svg>
                    </button>
                </div>

                {/* Sort controls */}
                <div className="flex">
                    <select
                        value={sortBy}
                        onChange={(e) => onSortChange(e.target.value, sortOrder)}
                        className="border border-gray-300 rounded-l-md py-2 pl-3 pr-8 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                    >
                        <option value="date">Date Added</option>
                        <option value="name">Name</option>
                        <option value="clicks">Clicks</option>
                    </select>

                    <button
                        onClick={() => onSortChange(sortBy, sortOrder === 'asc' ? 'desc' : 'asc')}
                        className="border border-gray-300 border-l-0 rounded-r-md px-3 py-2"
                        title={sortOrder === 'asc' ? 'Ascending' : 'Descending'}
                    >
                        {sortOrder === 'asc' ? (
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
                            </svg>
                        ) : (
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
                            </svg>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default SearchBar;