import os
import json
import uuid
from flask import current_app

ALLOWED_EXTENSIONS = {'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
