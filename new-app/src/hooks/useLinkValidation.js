import { useState, useEffect } from 'react';

/**
 * Hook for validating URLs
 * @param {string} url - URL to validate
 * @returns {Object} - Validation state
 */
export const useLinkValidation = (url) => {
  const [state, setState] = useState({
    isValidating: false,
    isValid: false,
    error: null
  });

  useEffect(() => {
    if (!url) {
      setState({ isValidating: false, isValid: false, error: null });
      return;
    }

    let isActive = true;
    setState({ isValidating: true, isValid: false, error: null });

    const validateUrl = () => {
      try {
        // Basic URL validation
        new URL(url);
        
        // Check if URL has a valid protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
          throw new Error('URL must start with http:// or https://');
        }
        
        if (isActive) {
          setState({ isValidating: false, isValid: true, error: null });
        }
      } catch (error) {
        if (isActive) {
          setState({ 
            isValidating: false, 
            isValid: false, 
            error: error.message || 'Invalid URL format'
          });
        }
      }
    };

    // Debounce validation
    const timeout = setTimeout(validateUrl, 500);

    return () => {
      isActive = false;
      clearTimeout(timeout);
    };
  }, [url]);

  return state;
};