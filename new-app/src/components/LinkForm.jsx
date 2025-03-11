// src/components/LinkForm.jsx
import React, { useState, useEffect } from 'react';

const LinkForm = ({ onSave, onCancel, initialData }) => {
    const [url, setUrl] = useState(initialData?.url || '');
    const [name, setName] = useState(initialData?.name || '');
    const [description, setDescription] = useState(initialData?.description || '');
    const [category, setCategory] = useState(initialData?.category || '');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [customCategory, setCustomCategory] = useState('');

    // Predefined categories - you can load these from your context
    const categories = ['Work', 'Personal', 'Education', 'Entertainment', 'Social Media', 'Tools', 'Other'];

    const validateUrl = (inputUrl) => {
        try {
            new URL(inputUrl);
            return true;
        } catch (e) {
            return false;
        }
    };


    const handleSubmit = (e) => {
        e.preventDefault();

        // Basic validation - just check if URL field is not empty
        if (!url.trim()) {
            setError('URL is required');
            return;
        }

        if (!name.trim()) {
            setError('Name is required');
            return;
        }

        // Add http:// prefix if missing
        let formattedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            formattedUrl = 'http://' + url;
        }

        // Create link data object
        const linkData = {
            url: formattedUrl,
            name,
            description,
            category: category === 'custom' ? customCategory : category,
            date: initialData?.date || new Date().toISOString(),
            clicks: initialData?.clicks || 0,
            favorite: initialData?.favorite || false
        };

        // Save the link
        onSave(linkData);
    };

    // Fetch metadata on URL change
    useEffect(() => {
        if (!url || initialData) return;

        let formattedUrl = url;
        // Try to format the URL for metadata fetching
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            formattedUrl = 'http://' + url;
        }

        // Only proceed if the URL is valid after formatting
        if (!validateUrl(formattedUrl)) return;

        // Fetch metadata
        const fetchMetadata = async () => {
            // ...rest of the function
        };

        const timer = setTimeout(fetchMetadata, 500);
        return () => clearTimeout(timer);
    }, [url, name, initialData]);


    return (
        <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-xl">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-bold text-gray-800">
                        {initialData ? 'Edit Link' : 'Add New Link'}
                    </h2>
                    <button
                        onClick={onCancel}
                        className="text-gray-500 hover:text-gray-700"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {error && (
                    <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    {/* URL Input */}
                    <div className="mb-4">
                        <label className="block text-gray-700 font-medium mb-2" htmlFor="url">
                            URL
                        </label>
                        <div className="relative">
                            <input
                                type="text"
                                id="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://example.com"
                                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required
                            />
                            {isLoading && (
                                <div className="absolute right-3 top-2">
                                    <div className="animate-spin w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Name Input */}
                    <div className="mb-4">
                        <label className="block text-gray-700 font-medium mb-2" htmlFor="name">
                            Name
                        </label>
                        <input
                            type="text"
                            id="name"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="My Awesome Link"
                            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required
                        />
                    </div>

                    {/* Description Input */}
                    <div className="mb-4">
                        <label className="block text-gray-700 font-medium mb-2" htmlFor="description">
                            Description (optional)
                        </label>
                        <textarea
                            id="description"
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            placeholder="Brief description of this link"
                            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 h-24"
                        />
                    </div>

                    {/* Category Input */}
                    <div className="mb-6">
                        <label className="block text-gray-700 font-medium mb-2" htmlFor="category">
                            Category
                        </label>
                        <select
                            id="category"
                            value={category}
                            onChange={(e) => setCategory(e.target.value)}
                            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                            <option value="">Select a category</option>
                            {categories.map((cat) => (
                                <option key={cat} value={cat}>{cat}</option>
                            ))}
                            <option value="custom">+ Add Custom Category</option>
                        </select>

                        {category === 'custom' && (
                            <input
                                type="text"
                                value={customCategory}
                                onChange={(e) => setCustomCategory(e.target.value)}
                                placeholder="Enter custom category"
                                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 mt-2"
                                required
                            />
                        )}
                    </div>

                    {/* Form Actions */}
                    <div className="flex justify-end space-x-2">
                        <button
                            type="button"
                            onClick={onCancel}
                            className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                        >
                            {initialData ? 'Update Link' : 'Save Link'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default LinkForm;