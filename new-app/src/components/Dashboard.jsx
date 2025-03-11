// src/components/Dashboard.jsx
import React, { useState } from 'react';
import { useLinks } from '../context/LinkContext';
import Sidebar from './Sidebar';
import SearchBar from './SearchBar';
import LinkCard from './LinkCard';
import LinkForm from './LinkForm';

const Dashboard = () => {
    const { links, isLoading, addLink, editLink, removeLink, toggleFavorite, trackLinkClick } = useLinks();

    // State for UI elements
    const [isAdding, setIsAdding] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [currentLink, setCurrentLink] = useState(null);
    const [activeCategory, setActiveCategory] = useState('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [viewMode, setViewMode] = useState('grid');
    const [sortBy, setSortBy] = useState('date');
    const [sortOrder, setSortOrder] = useState('desc');

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
            <Sidebar
                activeCategory={activeCategory}
                onCategoryChange={setActiveCategory}
                onAddLink={() => setIsAdding(true)}
            />

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
                        setSortOrder(newSortOrder);
                    }}
                />

                {/* Main content area */}
                <main className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-gray-900">
                    <div className="max-w-7xl mx-auto">
                        {/* Header with category name */}
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-2xl font-semibold text-gray-800">
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
                            <div className="text-center py-12 bg-white rounded-lg shadow-sm">
                                <div className="inline-flex items-center justify-center w-16 h-16 bg-gray-100 rounded-full mb-4">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <h3 className="text-xl font-medium text-gray-700 mb-2">
                                    {links.length === 0
                                        ? "You haven't added any links yet"
                                        : searchQuery
                                            ? "No links match your search"
                                            : `No links in ${activeCategory === 'favorites' ? 'favorites' : activeCategory}`}
                                </h3>
                                <p className="text-gray-500 max-w-md mx-auto mb-6">
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

export default Dashboard;