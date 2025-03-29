import os
import json
import uuid
from flask import current_app
from bs4 import BeautifulSoup
from flask_login import current_user

ALLOWED_EXTENSIONS = {'json', 'html'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_chrome_bookmarks(html_content):
    """Parse Chrome bookmarks HTML file and return list of links."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    
    print("Starting to parse bookmarks") # Debug print
    
    def process_bookmark(a_tag, category=None):
        bookmark = {
            'id': str(uuid.uuid4()),
            'title': a_tag.text.strip(),
            'url': a_tag.get('href', ''),
            'icon': a_tag.get('ICON', ''),
            'category': category,
            'description': ''
        }
        print(f"Found bookmark: {bookmark['title']} - {bookmark['url']}") # Debug print
        return bookmark

    def process_folder(dl_tag, current_category=None):
        print(f"Processing folder: {current_category}") # Debug print
        for dt in dl_tag.find_all('dt'):
            h3 = dt.find('h3')
            if h3:
                # Found a folder
                folder_name = h3.text.strip()
                print(f"Found folder: {folder_name}") # Debug print
                # Find the next DL after this H3
                next_dl = dt.find('dl')
                if next_dl:
                    process_folder(next_dl, folder_name)
            else:
                # It's a bookmark
                a_tag = dt.find('a')
                if a_tag and a_tag.get('href'):  # Make sure it has a URL
                    links.append(process_bookmark(a_tag, current_category))

    # Find the Bookmarks Bar folder specifically
    bookmarks_bar = soup.find('h3', text='Bookmarks bar')
    if bookmarks_bar:
        print("Found Bookmarks bar") # Debug print
        # Get the parent DL that contains all bookmarks
        bookmarks_container = bookmarks_bar.find_parent('dt').find_parent('dl')
        if bookmarks_container:
            process_folder(bookmarks_container)
    else:
        print("No Bookmarks bar found, trying root DL") # Debug print
        # Fallback to processing the entire file
        root_dl = soup.find('dl')
        if root_dl:
            process_folder(root_dl)

    print(f"Total bookmarks found: {len(links)}") # Debug print
    return links

def merge_bookmarks_with_config(config, new_bookmarks):
    """Merge new bookmarks with existing configuration."""
    # Keep track of existing URLs to avoid duplicates
    existing_urls = {link['url'] for link in config['links']}
    
    # Add only new bookmarks
    for bookmark in new_bookmarks:
        if bookmark['url'] not in existing_urls:
            config['links'].append(bookmark)
            existing_urls.add(bookmark['url'])
    
    return config

def get_user_config_path():
    """Get the configuration path for the current user."""
    if not current_user or not current_user.is_authenticated:
        return None
    
    # Create user-specific config directory if it doesn't exist
    user_config_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
    os.makedirs(user_config_dir, exist_ok=True)
    return os.path.join(user_config_dir, 'config.json')

def get_default_config():
    """Return the default configuration."""
    return {
        'title': 'Link Dashboard',
        'theme': {
            'primary_color': 'blue',
            'layout': 'grid',
            'container_spacing': 'less'
        },
        'categories': [],
        'links': []
    }

def load_config():
    """Load the active configuration file or return default config.
    Also ensure that each link has a unique 'id'."""
    config_path = get_user_config_path()
    if not config_path or not os.path.exists(config_path):
        return get_default_config()
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    changed = False
    for link in config.get('links', []):
        if 'id' not in link or not link['id']:
            link['id'] = str(uuid.uuid4())
            changed = True
    if changed:
        save_config(config)
    return config

def save_config(config):
    """Save the current configuration."""
    config_path = get_user_config_path()
    if not config_path:
        return
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

def validate_config(config):
    """Validate the uploaded configuration file."""
    required_keys = ['title', 'theme', 'categories', 'links']
    if not all(key in config for key in required_keys):
        return False
    
    # Validate theme
    if not isinstance(config['theme'], dict):
        return False
    if 'primary_color' not in config['theme'] or 'layout' not in config['theme']:
        return False
    
    # Validate links
    if not isinstance(config['links'], list):
        return False
    for link in config['links']:
        if not all(key in link for key in ['title', 'url']):
            return False
    
    return True

def inject_config():
    """Inject configuration into templates."""
    if not current_user or not current_user.is_authenticated:
        return dict(config=get_default_config())
    
    try:
        config = load_config()
    except Exception:
        config = get_default_config()
    return dict(config=config)