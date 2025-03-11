// src/components/RevisedDashboard.jsx
import React, { useState } from 'react';
import { useLinks } from '../context/LinkContext';
import { useUser } from '../context/UserContext';
import LinkCard from './LinkCard';
import LinkForm from './LinkForm';
import ThemeToggle from './ThemeToggle';
import SearchBar from './SearchBar';

const RevisedDashboard = () => {
    const { user, logout } = useUser();
    const { links, isLoading, addLink, editLink, removeLink, toggleFavorite, trackLinkClick, categories } = useLinks();

    // State for UI elements
    const [isAdding, setIsAdding] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [currentLink, setCurrentLink] = useState(null);
    const [activeCategory, setActiveCategory] = useState('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [viewMode, setViewMode] = useState('grid');
    const [sortBy, setSortBy] = useState('date');
    const [sortOrder, setSortOrder] = useState('desc');

    // Get user initials for avatar
    const getUserInitials = () => {
        if (!user || !user.displayName) return '?';

        const names = user.displayName.split(' ');
        if (names.length === 1) return names[0].charAt(0).toUpperCase();

        return `${names[0].charAt(0)}${names[names.length - 1].charAt(0)}`.toUpperCase();
    };

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

    // Get filtered links based on category and search query
    const getFilteredLinks = () => {
        // Filter by category first
        let result = [...links];

        if (activeCategory === 'favorites') {
            result = result.filter(link => link.favorite);
        } else if (activeCategory !== 'all') {
            result = result.filter(link => link.category === activeCategory);
        }

        // Then apply search filter
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

        return result;
    };

    // Event handlers
    const handleAddLink = async (linkData) => {
        await addLink(linkData);
        setIsAdding(false);
    };

    const handleEditLink = (link) => {
        setCurrentLink(link);
        setIsEditing(true);
    };

    const handleUpdateLink = async (linkData) => {
        await editLink({ ...linkData, id: currentLink.id });
        setIsEditing(false);
        setCurrentLink(null);
    };

    // If in form mode, show forms
    if (isAdding) {
        return <LinkForm onSave={handleAddLink} onCancel={() => setIsAdding(false)} />;
    }

    if (isEditing && currentLink) {
        return <LinkForm
            onSave={handleUpdateLink}
            onCancel={() => {
                setIsEditing(false);
                setCurrentLink(null);
            }}
            initialData={currentLink}
        />;
    }

    // Get filtered links
    const filteredLinks = getFilteredLinks();

    return (
        <div className="flex h-screen overflow-hidden">
            {/* Sidebar */}
            <div className="w-64 bg-gray-900 text-white h-screen flex flex-col transition-colors duration-200 dark:bg-gray-950">
                {/* User info */}
                <div className="p-4 border-b border-gray-800">
                    <div className="flex items-center">
                        <div className="w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center text-white font-medium">
                            {getUserInitials()}
                        </div>
                        <div className="ml-3 overflow-hidden">
                            <p className="text-sm font-medium text-white truncate">
                                {user?.displayName || 'Guest User'}
                            </p>
                            <p className="text-xs text-gray-400 truncate">
                                {user?.email || 'Sign in to sync links'}
                            </p>
                        </div>
                    </div>
                </div>

                {/* Logo/header */}
                <div className="p-4">
                    <h1 className="text-xl font-bold">Link Harbor</h1>
                    <p className="text-sm text-gray-400">Your personal link dashboard</p>
                </div>

                {/* Add Button */}
                <div className="p-4">
                    <button
                        onClick={() => setIsAdding(true)}
                        className="flex items-center w-full p-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800 text-white rounded-md transition-colors"
                    >
                        <span className="mr-2">+</span>
                        <span>Add New Link</span>
                    </button>
                </div>

                {/* Navigation */}
                <div className="flex-grow overflow-y-auto p-4">
                    <div className="uppercase text-xs font-semibold text-gray-500 mb-2">BROWSE</div>

                    <button
                        className={`flex items-center w-full p-2 rounded-md mb-1 transition-colors ${activeCategory === 'all'
                            ? 'bg-gray-700 dark:bg-gray-800'
                            : 'hover:bg-gray-800 dark:hover:bg-gray-800/60'
                            }`}
                        onClick={() => setActiveCategory('all')}
                    >
                        <span className="mr-2">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z" />
                            </svg>
                        </span>
                        <span>All Links</span>
                        <span className="ml-auto bg-gray-800 dark:bg-gray-700 px-2 py-1 rounded-full text-xs">
                            {getCategoryCount('all')}
                        </span>
                    </button>

                    <button
                        className={`flex items-center w-full p-2 rounded-md mb-1 transition-colors ${activeCategory === 'favorites'
                            ? 'bg-gray-700 dark:bg-gray-800'
                            : 'hover:bg-gray-800 dark:hover:bg-gray-800/60'
                            }`}
                        onClick={() => setActiveCategory('favorites')}
                    >
                        <span className="mr-2">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                            </svg>
                        </span>
                        <span>Favorites</span>
                        <span className="ml-auto bg-gray-800 dark:bg-gray-700 px-2 py-1 rounded-full text-xs">
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
                                    className={`flex items-center w-full p-2 rounded-md mb-1 transition-colors ${activeCategory === category
                                        ? 'bg-gray-700 dark:bg-gray-800'
                                        : 'hover:bg-gray-800 dark:hover:bg-gray-800/60'
                                        }`}
                                    onClick={() => setActiveCategory(category)}
                                >
                                    <span className="mr-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                            <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                                        </svg>
                                    </span>
                                    <span className="truncate">{category}</span>
                                    <span className="ml-auto bg-gray-800 dark:bg-gray-700 px-2 py-1 rounded-full text-xs">
                                        {getCategoryCount(category)}
                                    </span>
                                </button>
                            ))}
                        </>
                    )}
                </div>

                {/* Theme toggle in footer */}
                <div className="mt-auto border-t border-gray-700 dark:border-gray-800 p-4 flex items-center justify-between">
                    <ThemeToggle />
                    <button
                        onClick={logout}
                        className="text-sm text-gray-400 hover:text-gray-300 transition-colors"
                    >
                        Logout
                    </button>
                </div>
            </div>

            {/* Main content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {/* Search bar */}
                <SearchBar
                    onSearch={setSearchQuery}
                    viewMode={viewMode}
                    onViewModeChange={setViewMode}
                    sortBy={sortBy}
                    sortOrder={sortOrder}
                    onSortChange={(newSortBy, newSortOrder) => {
                        setSortBy(newSortBy);
                        setSortOrder(newSortOrder || sortOrder);
                    }}
                />

                {/* Main content area */}
                <main className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-gray-900">
                    <div className="max-w-7xl mx-auto">
                        {/* Header with category name */}
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
                                className="md:hidden bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg flex items-center"
                            >
                                <span className="mr-1">+</span>
                                Add
                            </button>
                        </div>

                        {/* Link grid/list */}
                        {isLoading ? (
                            <div className="flex justify-center items-center py-12">
                                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                            </div>
                        ) : filteredLinks.length === 0 ? (
                            <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                                <div className="inline-flex items-center justify-center w-16 h-16 bg-gray-100 dark:bg-gray-700 rounded-full mb-4">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-gray-400 dark:text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <h3 className="text-xl font-medium text-gray-700 dark:text-gray-300 mb-2">
                                    {links.length === 0
                                        ? "You haven't added any links yet"
                                        : searchQuery
                                            ? "No links match your search"
                                            : `No links in ${activeCategory === 'favorites' ? 'favorites' : activeCategory}`}
                                </h3>
                                <p className="text-gray-500 dark:text-gray-400 max-w-md mx-auto mb-6">
                                    {links.length === 0
                                        ? "Start building your collection by adding your first link."
                                        : searchQuery
                                            ? "Try adjusting your search terms or clear the search."
                                            : activeCategory === 'favorites'
                                                ? "Mark links as favorites by clicking the star icon."
                                                : "Try selecting a different category or add a new link with that category."}
                                </p>
                                {links.length === 0 && (
                                    <button
                                        onClick={() => setIsAdding(true)}
                                        className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded-lg inline-flex items-center"
                                    >
                                        <span className="mr-2">+</span>
                                        Add Your First Link
                                    </button>
                                )}
                            </div>
                        ) : (
                            <div className={`grid gap-6 ${viewMode === 'grid'
                                ? 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
                                : 'grid-cols-1'
                                }`}>
                                {filteredLinks.map(link => (
                                    <LinkCard
                                        key={link.id}
                                        link={link}
                                        viewMode={viewMode}
                                        onDelete={() => removeLink(link.id)}
                                        onEdit={() => handleEditLink(link)}
                                        onClick={() => trackLinkClick(link.id)}
                                        onToggleFavorite={() => toggleFavorite(link.id)}
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default RevisedDashboard;