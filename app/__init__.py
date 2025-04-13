import os
import logging
from flask import Flask, send_from_directory, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_awscognito import AWSCognitoAuthentication
from flask_migrate import Migrate
from datetime import timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from a .env file if available
load_dotenv()

# Create the Flask application
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

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Use DATABASE_URL environment variable if set, otherwise store the SQLite DB in the instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') or \
    'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set AWS configuration
app.config['AWS_DEPLOYMENT'] = os.getenv('AWS_DEPLOYMENT', 'False').lower() == 'true'
app.config['AWS_DEFAULT_REGION'] = os.getenv('AWS_DEFAULT_REGION')
app.config['AWS_COGNITO_DOMAIN'] = os.getenv('AWS_COGNITO_DOMAIN')
app.config['AWS_COGNITO_USER_POOL_ID'] = os.getenv('AWS_COGNITO_USER_POOL_ID')
app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'] = os.getenv('AWS_COGNITO_USER_POOL_CLIENT_ID')
app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = os.getenv('AWS_COGNITO_USER_POOL_CLIENT_SECRET')
app.config['AWS_COGNITO_REDIRECT_URL'] = os.getenv('AWS_COGNITO_REDIRECT_URL')
app.config['AWS_COGNITO_LOGOUT_URL'] = os.getenv('AWS_COGNITO_LOGOUT_URL')

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate()
migrate.init_app(app, db)

# Import models so that they register with SQLAlchemy
from app import models

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# Initialize AWS Cognito (if we're in AWS deployment mode)
aws_auth = None
if app.config['AWS_DEPLOYMENT']:
    from app.cognito_config import init_cognito
    aws_auth = init_cognito(app)

# Register Blueprints
from app import auth_routes, dashboard_routes
app.register_blueprint(auth_routes.auth_bp)
app.register_blueprint(dashboard_routes.main_bp)

# Initialize OAuth
auth_routes.init_oauth(app)

# Register a context processor to inject configuration into templates
from app.config_utils import inject_config
app.context_processor(inject_config)

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Add static file caching
@app.after_request
def add_cache_headers(response):
    # Cache static assets
    if request.path and 'static' in request.path:
        # Cache icons and manifest for 1 week
        if any(ext in request.path for ext in ['.ico', '.png', '.webmanifest']):
            response.cache_control.max_age = int(timedelta(weeks=1).total_seconds())
            response.cache_control.public = True
            response.headers['Vary'] = 'Accept-Encoding'
        # Cache other static files for 1 day
        else:
            response.cache_control.max_age = int(timedelta(days=1).total_seconds())
            response.cache_control.public = True
            response.headers['Vary'] = 'Accept-Encoding'
    return response
