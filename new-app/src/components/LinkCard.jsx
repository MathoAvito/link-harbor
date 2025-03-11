// src/components/LinkCard.jsx
import React, { useState } from 'react';
import { format } from 'date-fns';

const LinkCard = ({ link, viewMode, onDelete, onEdit, onClick, onToggleFavorite }) => {
    const [isHovered, setIsHovered] = useState(false);

    const formatDate = (dateString) => {
        try {
            return format(new Date(dateString), 'MMM d, yyyy');
        } catch (e) {
            return dateString;
        }
    };

    const getDomainFromUrl = (url) => {
        try {
            const domain = new URL(url).hostname;
            return domain.replace('www.', '');
        } catch (e) {
            return url;
        }
    };

    // Grid view card
    if (viewMode === 'grid') {
        return (
            <div
                className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition-shadow cursor-pointer"
                onClick={onClick}
                onMouseEnter={() => setIsHovered(true)}
                onMouseLeave={() => setIsHovered(false)}
            >
                {/* Card image/header */}
                <div className="h-32 bg-gradient-to-r from-blue-500 to-purple-600 flex items-center justify-center">
                    <span className="text-white text-2xl font-bold">{link.name.charAt(0).toUpperCase()}</span>
                </div>

                {/* Card content */}
                <div className="p-4">
                    <div className="flex items-center mb-2">
                        {/* Favicon placeholder */}
                        <div className="w-4 h-4 bg-gray-200 rounded-full mr-2"></div>
                        <h3 className="font-medium text-gray-900 truncate">{link.name}</h3>

                        {/* Favorite indicator */}
                        {link.favorite && (
                            <button
                                className="ml-auto text-yellow-500"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    onToggleFavorite();
                                }}
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                                </svg>
                            </button>
                        )}
                    </div>

                    {/* Description */}
                    {link.description && (
                        <p className="text-sm text-gray-600 mb-3 line-clamp-2">{link.description}</p>
                    )}

                    {/* URL */}
                    <div className="text-xs text-gray-500 mb-3">{getDomainFromUrl(link.url)}</div>

                    {/* Metadata */}
                    <div className="flex items-center text-xs text-gray-500">
                        {link.date && (
                            <span className="mr-3">{formatDate(link.date)}</span>
                        )}

                        {typeof link.clicks === 'number' && (
                            <span>{link.clicks} click{link.clicks !== 1 ? 's' : ''}</span>
                        )}
                    </div>

                    {/* Actions */}
                    <div className={`flex justify-end mt-3 space-x-2 ${isHovered ? 'opacity-100' : 'opacity-0'} transition-opacity`}>
                        <button
                            className="p-1 text-gray-500 hover:text-blue-600 rounded-full"
                            onClick={(e) => {
                                e.stopPropagation();
                                onToggleFavorite();
                            }}
                            title={link.favorite ? "Remove from favorites" : "Add to favorites"}
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" className={`h-5 w-5 ${link.favorite ? 'text-yellow-500 fill-current' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                            </svg>
                        </button>

                        <button
                            className="p-1 text-gray-500 hover:text-blue-600 rounded-full"
                            onClick={(e) => {
                                e.stopPropagation();
                                onEdit();
                            }}
                            title="Edit link"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                        </button>

                        <button
                            className="p-1 text-gray-500 hover:text-red-600 rounded-full"
                            onClick={(e) => {
                                e.stopPropagation();
                                onDelete();
                            }}
                            title="Delete link"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    // List view
    return (
        <div
            className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition-shadow cursor-pointer flex"
            onClick={onClick}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
        >
            {/* Left color bar / icon */}
            <div className="w-16 bg-gradient-to-b from-blue-500 to-purple-600 flex items-center justify-center">
                <span className="text-white text-xl font-bold">{link.name.charAt(0).toUpperCase()}</span>
            </div>

            {/* Content */}
            <div className="flex-grow p-4 pr-16 relative">
                <div className="flex items-center mb-1">
                    <h3 className="font-medium text-gray-900">{link.name}</h3>

                    {/* Favorite indicator */}
                    {link.favorite && (
                        <span className="ml-2 text-yellow-500">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                            </svg>
                        </span>
                    )}
                </div>

                {link.description && (
                    <p className="text-sm text-gray-600 mb-2 line-clamp-1">{link.description}</p>
                )}

                <div className="flex items-center text-xs text-gray-500">
                    <span className="mr-3">{getDomainFromUrl(link.url)}</span>

                    {link.category && (
                        <span className="mr-3 bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full">
                            {link.category}
                        </span>
                    )}

                    {link.date && (
                        <span className="mr-3">{formatDate(link.date)}</span>
                    )}

                    {typeof link.clicks === 'number' && (
                        <span>{link.clicks} click{link.clicks !== 1 ? 's' : ''}</span>
                    )}
                </div>

                {/* Actions (absolute positioned) */}
                <div className={`absolute right-4 top-1/2 transform -translate-y-1/2 flex space-x-1 ${isHovered ? 'opacity-100' : 'opacity-0'
                    } transition-opacity`}>
                    <button
                        className="p-1 text-gray-500 hover:text-blue-600 rounded-full"
                        onClick={(e) => {
                            e.stopPropagation();
                            onToggleFavorite();
                        }}
                        title={link.favorite ? "Remove from favorites" : "Add to favorites"}
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className={`h-5 w-5 ${link.favorite ? 'text-yellow-500 fill-current' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                        </svg>
                    </button>

                    <button
                        className="p-1 text-gray-500 hover:text-blue-600 rounded-full"
                        onClick={(e) => {
                            e.stopPropagation();
                            onEdit();
                        }}
                        title="Edit link"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                    </button>

                    <button
                        className="p-1 text-gray-500 hover:text-red-600 rounded-full"
                        onClick={(e) => {
                            e.stopPropagation();
                            onDelete();
                        }}
                        title="Delete link"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LinkCard;