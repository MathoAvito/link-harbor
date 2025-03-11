chrome.runtime.onInstalled.addListener(function() {
    // Create context menu item
    chrome.contextMenus.create({
      id: "saveLinkHarbor",
      title: "Save to Link Harbor",
      contexts: ["link", "page"]
    });
  });
  
  // Handle context menu clicks
  chrome.contextMenus.onClicked.addListener(function(info, tab) {
    if (info.menuItemId === "saveLinkHarbor") {
      const url = info.linkUrl || info.pageUrl;
      const title = tab.title;
      
      // Save basic info and open popup for editing
      chrome.storage.local.set({ 
        linkHarborDraft: { 
          url: url, 
          name: title 
        } 
      }, function() {
        chrome.action.openPopup();
      });
    }
  });
  
  // Handle messages from content script
  chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "exportLinks") {
      // Export links to web app
      chrome.storage.local.get(['linkHarborLinks'], function(result) {
        const links = result.linkHarborLinks || [];
        
        // Send to web app
        // This would need additional implementation to connect with the web app
        sendResponse({ success: true, count: links.length });
      });
      return true; // Keeps the message channel open for async response
    }
  });
  