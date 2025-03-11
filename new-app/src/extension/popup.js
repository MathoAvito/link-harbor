document.addEventListener('DOMContentLoaded', function() {
    const nameInput = document.getElementById('name');
    const descriptionInput = document.getElementById('description');
    const categorySelect = document.getElementById('category');
    const saveButton = document.getElementById('save');
    const statusDiv = document.getElementById('status');
    
    // Get current tab info
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const currentTab = tabs[0];
      
      // Prepopulate fields
      nameInput.value = currentTab.title || '';
      
      // Get previously used categories from storage
      chrome.storage.local.get(['linkHarborCategories'], function(result) {
        if (result.linkHarborCategories && Array.isArray(result.linkHarborCategories)) {
          // Populate category dropdown with saved categories
          const categories = result.linkHarborCategories;
          const currentOptions = Array.from(categorySelect.options).map(opt => opt.value);
          
          categories.forEach(category => {
            if (!currentOptions.includes(category) && category) {
              const option = document.createElement('option');
              option.value = category;
              option.textContent = category;
              categorySelect.appendChild(option);
            }
          });
        }
      });
    });
    
    saveButton.addEventListener('click', function() {
      const name = nameInput.value.trim();
      if (!name) {
        showStatus('Please enter a name for the link', 'error');
        return;
      }
      
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        
        const linkData = {
          url: currentTab.url,
          name: name,
          description: descriptionInput.value.trim(),
          category: categorySelect.value,
          date: new Date().toISOString(),
          favorite: false,
          clicks: 0,
          source: 'extension'
        };
        
        // Save category for future use
        if (linkData.category) {
          chrome.storage.local.get(['linkHarborCategories'], function(result) {
            const categories = result.linkHarborCategories || [];
            if (!categories.includes(linkData.category)) {
              categories.push(linkData.category);
              chrome.storage.local.set({ linkHarborCategories: categories });
            }
          });
        }
        
        // Save link to storage
        chrome.storage.local.get(['linkHarborLinks'], function(result) {
          const links = result.linkHarborLinks || [];
          
          // Generate an ID
          linkData.id = generateUUID();
          
          links.push(linkData);
          chrome.storage.local.set({ linkHarborLinks: links }, function() {
            showStatus('Link saved successfully!', 'success');
            
            // Clear form
            nameInput.value = '';
            descriptionInput.value = '';
            categorySelect.value = '';
            
            // Close popup after delay
            setTimeout(function() {
              window.close();
            }, 1500);
          });
        });
      });
    });
    
    function showStatus(message, type) {
      statusDiv.textContent = message;
      statusDiv.className = 'status ' + type;
      statusDiv.style.display = 'block';
    }
    
    function generateUUID() {
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    }
  });
  