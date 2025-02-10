import os
import json
import uuid
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configure SQLAlchemy for a local SQLite database.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# -------------------------------------------------------------------
# User Model
# -------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create the database tables (if not exist)
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------------------------------
# Existing configuration functions (for dashboard/links)
# -------------------------------------------------------------------
ALLOWED_EXTENSIONS = {'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_config():
    """Load the active configuration file or return default config.
    Also ensure that each link has a unique 'id'."""
    config_path = os.path.join(app.config['UPLOAD_FOLDER'], 'active_config.json')
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
    config_path = os.path.join(app.config['UPLOAD_FOLDER'], 'active_config.json')
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

@app.context_processor
def inject_config():
    # Try to load the configuration, if it fails, use a default configuration.
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


# -------------------------------------------------------------------
# Routes for User Management
# -------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Please fill in all fields")
            return redirect(url_for('register'))
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("Username already taken")
            return redirect(url_for('register'))
        # Create new user
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully!")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('login'))

# -------------------------------------------------------------------
# Protected Routes for Dashboard & Link Management
# (Require login)
# -------------------------------------------------------------------
@app.route('/')
@login_required
def dashboard():
    config = load_config()
    return render_template('dashboard.html', config=config)

@app.route('/upload_config', methods=['GET', 'POST'])
@login_required
def upload_config():
    if request.method == 'POST':
        if 'config_file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['config_file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                config = json.load(file)
                if validate_config(config):
                    save_config(config)
                    flash('Configuration uploaded successfully!')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid configuration format')
            except json.JSONDecodeError:
                flash('Invalid JSON file')
        else:
            flash('Invalid file type. Please upload a JSON file.')
        
        return redirect(request.url)
    
    return render_template('upload_config.html', config=load_config())

@app.route('/download_config')
@login_required
def download_config():
    template_config = {
        'title': 'My Dashboard',
        'theme': {
            'primary_color': 'blue',
            'layout': 'grid',
            'container_spacing': 'less'
        },
        'categories': [
            'Work',
            'Personal',
            'Development',
            'Social Media'
        ],
        'links': [
            {
                'id': 'example-1',
                'title': 'Example Work Link',
                'url': 'https://example.com/work',
                'description': 'This is an example work-related link',
                'category': 'Work'
            },
            {
                'id': 'example-2',
                'title': 'Example Personal Link',
                'url': 'https://example.com/personal',
                'description': 'This is an example personal link',
                'category': 'Personal'
            }
        ]
    }
    
    from io import BytesIO
    import json
    
    # Convert to JSON string with nice formatting
    json_str = json.dumps(template_config, indent=2)
    buffer = BytesIO(json_str.encode('utf-8'))
    
    return send_file(
        buffer,
        mimetype='application/json',
        as_attachment=True,
        download_name='dashboard_template.json'
    )

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_link():
    if request.method == 'POST':
        config = load_config()
        
        url = request.form.get('url')
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url

        new_link = {
            'id': str(uuid.uuid4()),
            'title': request.form.get('title'),
            'url': url,
            'description': request.form.get('description', ''),
            'category': request.form.get('category', ''),
            'icon': request.form.get('icon', '')
        }
        
        config['links'].append(new_link)
        save_config(config)
        return redirect(url_for('dashboard'))
    
    return render_template('add_link.html', config=load_config())

@app.route('/edit/<link_id>', methods=['GET', 'POST'])
@login_required
def edit_link(link_id):
    config = load_config()
    link = next((l for l in config['links'] if l['id'] == link_id), None)
    if not link:
        flash("Link not found")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        url = request.form.get('url')
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        link['title'] = request.form.get('title')
        link['url'] = url
        link['description'] = request.form.get('description', '')
        link['category'] = request.form.get('category', '')
        link['icon'] = request.form.get('icon', '')
        save_config(config)
        return redirect(url_for('dashboard'))
    return render_template('edit_link.html', config=load_config(), link=link)

@app.route('/delete/<link_id>')
@login_required
def delete_link(link_id):
    config = load_config()
    config['links'] = [l for l in config['links'] if l['id'] != link_id]
    save_config(config)
    return redirect(url_for('dashboard'))

@app.route('/update_order', methods=['POST'])
@login_required
def update_order():
    data = request.get_json()
    category = data.get('category')
    new_order = data.get('order')  # list of link IDs

    config = load_config()
    links = config.get('links', [])

    if category == "uncategorized":
        group_links = [l for l in links if not l.get('category')]
    else:
        group_links = [l for l in links if l.get('category') == category]

    link_dict = {l['id']: l for l in group_links}
    new_group = []
    for link_id in new_order:
        if link_id in link_dict:
            new_group.append(link_dict[link_id])
    
    new_links = []
    for l in links:
        if category == "uncategorized":
            if not l.get('category'):
                new_links.append(new_group.pop(0))
            else:
                new_links.append(l)
        else:
            if l.get('category') == category:
                new_links.append(new_group.pop(0))
            else:
                new_links.append(l)
    
    config['links'] = new_links
    save_config(config)
    return {"status": "ok"}

# -------------------------------------------------------------------
# Route for updating settings (e.g., container spacing)
# -------------------------------------------------------------------
@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    config = load_config()
    container_spacing = request.form.get('container_spacing', 'less')
    if 'theme' not in config:
        config['theme'] = {}
    config['theme']['container_spacing'] = container_spacing
    save_config(config)
    flash('Settings updated!')
    return redirect(url_for('dashboard'))

# -------------------------------------------------------------------
# Run the Application
# -------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
