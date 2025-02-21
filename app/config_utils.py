import os
import json
import uuid
from flask import current_app
from bs4 import BeautifulSoup

ALLOWED_EXTENSIONS = {'json', 'html'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_chrome_bookmarks(html_content):
    """Parse Chrome bookmarks HTML file and return list of links."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    
    def extract_folder_name(dt_tag):
        h3_tag = dt_tag.find('h3')
        if h3_tag:
            return h3_tag.text
        return None

    def process_bookmark(a_tag, category=None):
        icon_data = a_tag.get('ICON', '')  # Get icon data if it exists
        return {
            'id': str(uuid.uuid4()),
            'title': a_tag.text.strip(),
            'url': a_tag.get('href', ''),
            'icon': icon_data if icon_data else '',  # Store icon data if available
            'category': category,
            'description': ''  # Default empty description
        }

    def process_dl(dl_tag, current_category=None):
        for dt in dl_tag.find_all('dt', recursive=False):
            # Check if it's a folder
            h3 = dt.find('h3')
            if h3:
                folder_name = h3.text
                dl = dt.find('dl')
                if dl:
                    process_dl(dl, folder_name)
            else:
                # It's a bookmark
                a_tag = dt.find('a')
                if a_tag:
                    links.append(process_bookmark(a_tag, current_category))

    # Start processing from the root
    root_dl = soup.find('dl')
    if root_dl:
        process_dl(root_dl)

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

def load_config():
    """Load the active configuration file or return default config.
    Also ensure that each link has a unique 'id'."""
    config_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'active_config.json')
    if not os.path.exists(config_path):
        config = {
            'title': 'Link Dashboard',
            'theme': {
                'primary_color': 'blue',
                'layout': 'grid',
                'container_spacing': 'less'
            },
            'categories': [],
            'links': []
        }
        return config
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
    config_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'active_config.json')
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
    try:
        config = load_config()
    except Exception:
        config = {
            'title': 'Link Dashboard',
            'theme': {
                'primary_color': 'blue',
                'layout': 'grid',
                'container_spacing': 'less'
            },
            'categories': [],
            'links': []
        }
    return dict(config=config)