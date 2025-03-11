import React, { useState, useEffect } from 'react';
import { IoArrowBackOutline } from 'react-icons/io5';
import { FiExternalLink } from 'react-icons/fi';
import { extractMetadata } from '../utils/metadataExtractor';

const LinkForm = ({ onAddLink, onCancel }) => {
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState(null);
  
  // Categories could be dynamically loaded from backend
  const categories = ['Work', 'Personal', 'Education', 'Entertainment', 'Tools', 'Other'];
  
  const validateUrl = (inputUrl) => {
    try {
      new URL(inputUrl);
      return true;
    } catch (e) {
      return false;
    }
  };
  
  const fetchMetadata = async (inputUrl) => {
    if (!validateUrl(inputUrl)) {
      setError('Please enter a valid URL');
      return;
    }
    
    setIsLoading(true);
    setError('');
    
    try {
      const metadata = await extractMetadata(inputUrl);
      if (metadata) {
        // Auto-fill name and description if available
        setName(metadata.title || '');
        setDescription(metadata.description || '');
        setPreview({
          title: metadata.title,
          description: metadata.description,
          image: metadata.image,
          favicon: metadata.favicon
        });
      }
    } catch (error) {
      console.error('Error fetching metadata:', error);
      setError('Could not fetch website information');
    } finally {
      setIsLoading(false);
    }
  };
  
  useEffect(() => {
    // Debounce the URL input to avoid too many API calls
    const timeoutId = setTimeout(() => {
      if (url && validateUrl(url)) {
        fetchMetadata(url);
      }
    }, 800);
    
    return () => clearTimeout(timeoutId);
  }, [url]);
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!validateUrl(url)) {
      setError('Please enter a valid URL');
      return;
    }
    
    if (!name.trim()) {
      setError('Please provide a name for the link');
      return;
    }
    
    onAddLink({
      url,
      name,
      description,
      category: category || 'Other',
      date: new Date().toISOString(),
      clicks: 0,
      preview: preview
    });
    
    // Reset form
    setUrl('');
    setName('');
    setDescription('');
    setCategory('');
    setPreview(null);
  };
  
  return (
    <div className="p-6 bg-white rounded-lg shadow-md w-full max-w-xl mx-auto">
      <div className="flex items-center mb-6">
        <button 
          onClick={onCancel}
          className="mr-3 text-gray-500 hover:text-gray-700 transition-colors"
        >
          <IoArrowBackOutline size={24} />
        </button>
        <h2 className="text-2xl font-bold text-gray-800">Add New Link</h2>
      </div>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
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
        
        {preview && (
          <div className="mb-4 p-3 bg-gray-50 rounded-md border border-gray-200">
            <div className="flex items-start">
              {preview.image && (
                <img 
                  src={preview.image} 
                  alt="Link preview" 
                  className="w-16 h-16 object-cover rounded mr-3"
                  onError={(e) => e.target.style.display = 'none'}
                />
              )}
              <div>
                <h3 className="font-medium">{preview.title}</h3>
                <p className="text-sm text-gray-600 line-clamp-2">{preview.description}</p>
                <a 
                  href={url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 flex items-center mt-1"
                >
                  {url.replace(/^https?:\/\//, '').split('/')[0]}
                  <FiExternalLink className="ml-1" size={12} />
                </a>
              </div>
            </div>
          </div>
        )}
        
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
          </select>
        </div>
        
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-gray-700 mr-2 rounded-md hover:bg-gray-100 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Save Link
          </button>
        </div>
      </form>
    </div>
  );
};

export default LinkForm;