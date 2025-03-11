// This script runs on web pages
(function () {
    // Add message listener for web app communication
    window.addEventListener('message', function (event) {
        // Verify the sender origin
        if (event.origin !== 'https://yourlinkharborapp.com') return;

        if (event.data.type === 'LINK_HARBOR_IMPORT') {
            // Handle import request from web app
            chrome.runtime.sendMessage({
                action: 'importLinksFromWebApp',
                links: event.data.links
            });
        }
    });

    // Check if we're on the Link Harbor web app
    if (window.location.href.includes('yourlinkharborapp.com')) {
        // Initialize communication with web app
        console.log('Link Harbor extension connected to web app');

        // Inject button
        const button = document.createElement('button');
        button.textContent = 'Sync with Extension';
        button.style.position = 'fixed';
        button.style.bottom = '20px';
        button.style.right = '20px';
        button.style.zIndex = '9999';
        button.style.padding = '8px 16px';
        button.style.background = '#3B82F6';
        button.style.color = 'white';
        button.style.border = 'none';
        button.style.borderRadius = '4px';
        button.style.cursor = 'pointer';

        button.addEventListener('click', function () {
            chrome.runtime.sendMessage({ action: 'exportLinks' }, function (response) {
                if (response && response.success) {
                    alert(`Successfully synced ${response.count} links!`);
                } else {
                    alert('Failed to sync links. Please try again.');
                }
            });
        });

        document.body.appendChild(button);
    }
})();
