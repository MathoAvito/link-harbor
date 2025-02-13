import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv

# Load environment variables from a .env file if available
load_dotenv()

# Create the Flask application; use instance_relative_config so that the
# instance folder (outside version control) can store configuration and the database.
app = Flask(__name__, instance_relative_config=True)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super-secret-key')

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Set configuration variables
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size
# Use DATABASE_URL environment variable if set, otherwise store the SQLite DB in the instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') or \
    'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
# The login view is in the auth blueprint
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

# Import models so that they register with SQLAlchemy
from app import models

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# Register Blueprints
from app import auth_routes, dashboard_routes
app.register_blueprint(auth_routes.auth_bp)
app.register_blueprint(dashboard_routes.main_bp)

# Register a context processor to inject configuration into templates
from app.config_utils import inject_config
app.context_processor(inject_config)

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()
