// src/components/LinkCard.jsx
import React, { useState } from 'react';
import { FiExternalLink, FiTrash2, FiEdit2, FiStar, FiFolder, FiCopy, FiMoreVertical } from 'react-icons/fi';
import { format } from 'date-fns';
import { useOutsideClick } from '../hooks/useOutsideClick';

const LinkCard = ({ link, viewMode = 'grid', onDelete, onEdit, onClick, onToggleFavorite }) => {
  const [isHovered, setIsHovered] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  
  // Close menu when clicking outside
  const menuRef = useOutsideClick(() => {
    setIsMenuOpen(false);
  });
  
  const handleClick = (e) => {
    // Don't open the link if clicking on action buttons
    if (e.target.closest('.card-actions') || e.target.closest('.card-menu')) {
      return;
    }
    
    // Open the link
    window.open(link.url, '_blank', 'noopener,noreferrer');
    
    // Track click
    onClick();
  };
  
  const handleCopyToClipboard = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(link.url);
    
    // Could add toast notification here
    alert('Link copied to clipboard');
    
    setIsMenuOpen(false);
  };
  
  const handleDelete = (e) => {
    e.stopPropagation();
    onDelete(link.id);
    setIsMenuOpen(false);
  };
  
  const handleEdit = (e) => {
    e.stopPropagation();
    onEdit(link);
    setIsMenuOpen(false);
  };
  
  const handleToggleFavorite = (e) => {
    e.stopPropagation();
    onToggleFavorite(link.id);
    setIsMenuOpen(false);
  };
  
  const getDomainFromUrl = (url) => {
    try {
      const domain = new URL(url).hostname;
      return domain.replace('www.', '');
    } catch (e) {
      return url;
    }
  };
  
  const formatDate = (dateString) => {
    try {
      return format(new Date(dateString), 'MMM d, yyyy');
    } catch (e) {
      return dateString;
    }
  };
  
  // Grid view card
  if (viewMode === 'grid') {
    return (
      <div 
        className="card cursor-pointer animate-fade-in"
        onClick={handleClick}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => {
          setIsHovered(false);
          setIsMenuOpen(false);
        }}
      >
        {/* Favorite indicator */}
        {link.favorite && (
          <div className="absolute top-2 right-2 z-10">
            <FiStar className="text-yellow-500 fill-yellow-500" size={16} />
          </div>
        )}
        
        {/* Link preview image */}
        {link.preview?.image ? (
          <div className="h-40 overflow-hidden">
            <img 
              src={link.preview.image} 
              alt="" 
              className="w-full h-full object-cover"
              onError={(e) => {
                e.target.onerror = null;
                e.target.style.display = 'none';
              }}
            />
          </div>
        ) : (
          <div className="h-32 bg-gradient-to-r from-gray-100 to-gray-200 dark:from-gray-700 dark:to-gray-800 flex items-center justify-center">
            <div className="text-3xl font-bold text-gray-300 dark:text-gray-600">
              {link.name.charAt(0).toUpperCase()}
            </div>
          </div>
        )}
        
        <div className="p-4">
          {/* Title and favicon */}
          <div className="flex items-center mb-2">
            {link.preview?.favicon && (
              <img src={link.preview.favicon} alt="" className="w-4 h-4 mr-2" />
            )}
            <h3 className="font-medium text-gray-900 dark:text-white truncate">{link.name}</h3>
          </div>
          
          {/* Description */}
          {link.description && (
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3 line-clamp-2">
              {link.description}
            </p>
          )}
          
          {/* URL */}
          <div className="flex items-center text-xs text-gray-500 dark:text-gray-500 mb-3">
            <FiExternalLink size={12} className="mr-1" />
            <span className="truncate">{getDomainFromUrl(link.url)}</span>
          </div>
          
          {/* Categories & metadata */}
          <div className="flex flex-wrap gap-1 mb-2">
            {link.category && (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300">
                <FiFolder size={10} className="mr-1" />
                {link.category}
              </span>
            )}
            
            {link.date && (
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {formatDate(link.date)}
              </span>
            )}
          </div>
          
          {/* Actions */}
          <div 
            className={`card-actions flex justify-between items-center transition-opacity duration-200 ${
              isHovered ? 'opacity-100' : 'opacity-0'
            }`}
          >
            <div className="text-xs text-gray-500 dark:text-gray-400">
              {typeof link.clicks === 'number' && (
                <span>{link.clicks} click{link.clicks !== 1 ? 's' : ''}</span>
              )}
            </div>
            
            <div className="flex space-x-1">
              <button
                onClick={handleToggleFavorite}
                className="p-1 text-gray-500 hover:text-yellow-500 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                title={link.favorite ? "Remove from favorites" : "Add to favorites"}
              >
                <FiStar className={link.favorite ? "fill-yellow-500 text-yellow-500" : ""} size={16} />
              </button>
              
              <button
                onClick={handleEdit}
                className="p-1 text-gray-500 hover:text-primary-500 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                title="Edit link"
              >
                <FiEdit2 size={16} />
              </button>
              
              <button
                onClick={handleCopyToClipboard}
                className="p-1 text-gray-500 hover:text-primary-500 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                title="Copy URL"
              >
                <FiCopy size={16} />
              </button>
              
              <button
                onClick={handleDelete}
                className="p-1 text-gray-500 hover:text-red-500 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                title="Delete link"
              >
                <FiTrash2 size={16} />
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  // List view card
  return (
    <div 
      className="card cursor-pointer animate-fade-in flex"
      onClick={handleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => {
        setIsHovered(false);
        setIsMenuOpen(false);
      }}
    >
      {/* Link thumbnail/icon */}
      <div className="w-16 h-16 flex-shrink-0 m-4">
        {link.preview?.image ? (
          <img 
            src={link.preview.image} 
            alt="" 
            className="w-full h-full object-cover rounded"
            onError={(e) => {
              e.target.onerror = null;
              e.target.style.display = 'none';
            }}
          />
        ) : (
          <div className="w-full h-full rounded bg-gradient-to-r from-gray-100 to-gray-200 dark:from-gray-700 dark:to-gray-800 flex items-center justify-center">
            <div className="text-xl font-bold text-gray-300 dark:text-gray-600">
              {link.name.charAt(0).toUpperCase()}
            </div>
          </div>
        )}
      </div>
      
      {/* Content */}
      <div className="flex-grow p-4 pr-16 relative">
        {/* Favorite indicator */}
        {link.favorite && (
          <div className="absolute top-4 right-4">
            <FiStar className="text-yellow-500 fill-yellow-500" size={16} />
          </div>
        )}
        
        {/* Title and favicon */}
        <div className="flex items-center mb-1">
          {link.preview?.favicon && (
            <img src={link.preview.favicon} alt="" className="w-4 h-4 mr-2" />
          )}
          <h3 className="font-medium text-gray-900 dark:text-white truncate">{link.name}</h3>
        </div>
        
        {/* Description */}
        {link.description && (
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2 line-clamp-1">
            {link.description}
          </p>
        )}
        
        {/* Metadata */}
        <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
          <span className="flex items-center mr-3">
            <FiExternalLink size={12} className="mr-1" />
            {getDomainFromUrl(link.url)}
          </span>
          
          {link.category && (
            <span className="flex items-center mr-3">
              <FiFolder size={12} className="mr-1" />
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
        
        {/* Actions menu */}
        <div 
          className={`card-actions absolute right-4 top-1/2 transform -translate-y-1/2 transition-opacity duration-200 ${
            isHovered ? 'opacity-100' : 'opacity-0'
          }`}
        >
          <div className="relative" ref={menuRef}>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsMenuOpen(!isMenuOpen);
              }}
              className="p-2 text-gray-500 hover:text-primary-500 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              <FiMoreVertical size={18} />
            </button>
            
            {isMenuOpen && (
              <div className="card-menu absolute right-0 mt-1 w-40 py-1 bg-white dark:bg-gray-800 rounded-md shadow-lg z-20 animate-fade-in">
                <button
                  onClick={handleToggleFavorite}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                >
                  <FiStar className={`mr-2 ${link.favorite ? "fill-yellow-500 text-yellow-500" : ""}`} size={14} />
                  {link.favorite ? "Remove favorite" : "Add to favorites"}
                </button>
                <button
                  onClick={handleEdit}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                >
                  <FiEdit2 className="mr-2" size={14} />
                  Edit
                </button>
                <button
                  onClick={handleCopyToClipboard}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                >
                  <FiCopy className="mr-2" size={14} />
                  Copy URL
                </button>
                <button
                  onClick={handleDelete}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center text-red-500"
                >
                  <FiTrash2 className="mr-2" size={14} />
                  Delete
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LinkCard;