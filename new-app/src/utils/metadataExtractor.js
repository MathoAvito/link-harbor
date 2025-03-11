// This would ideally be implemented with a backend service 
// but here's a frontend implementation using a proxy to avoid CORS issues
export const extractMetadata = async (url) => {
    try {
      // Use a proxy service to avoid CORS issues
      // In production, you'd want to implement this in your backend
      const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
      
      const response = await fetch(proxyUrl);
      const data = await response.json();
      
      if (!data.contents) {
        throw new Error('Failed to fetch page content');
      }
      
      // Create a DOM parser
      const parser = new DOMParser();
      const doc = parser.parseFromString(data.contents, 'text/html');
      
      // Extract metadata
      const metadata = {
        title: getMetaValue(doc, 'title') || doc.title,
        description: getMetaValue(doc, 'description') || '',
        image: getMetaValue(doc, 'og:image') || getFirstImage(doc),
        favicon: getFavicon(doc, url)
      };
      
      return metadata;
    } catch (error) {
      console.error('Error extracting metadata:', error);
      return null;
    }
  };
  
  // Helper functions
  const getMetaValue = (doc, name) => {
    // Try various meta tag formats
    const selectors = [
      `meta[name="${name}"]`,
      `meta[property="og:${name}"]`,
      `meta[property="twitter:${name}"]`
    ];
    
    for (const selector of selectors) {
      const meta = doc.querySelector(selector);
      if (meta && meta.getAttribute('content')) {
        return meta.getAttribute('content');
      }
    }
    
    return null;
  };
  
  const getFirstImage = (doc) => {
    const img = doc.querySelector('img');
    return img ? img.src : null;
  };
  
  const getFavicon = (doc, baseUrl) => {
    const parsedUrl = new URL(baseUrl);
    const domain = `${parsedUrl.protocol}//${parsedUrl.hostname}`;
    
    // Try to find favicon link
    const faviconLink = doc.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
    
    if (faviconLink && faviconLink.href) {
      // Handle relative URLs
      if (faviconLink.href.startsWith('/')) {
        return `${domain}${faviconLink.href}`;
      }
      return faviconLink.href;
    }
    
    // Fallback to default favicon location
    return `${domain}/favicon.ico`;
  };