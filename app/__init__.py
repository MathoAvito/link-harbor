import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

# Import models so that they are registered with SQLAlchemy
from app import models

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# Register Blueprints
from app import auth_routes, dashboard_routes
app.register_blueprint(auth_routes.auth_bp)
app.register_blueprint(dashboard_routes.main_bp)

# Register context processor for configuration injection
from app.config_utils import inject_config
app.context_processor(inject_config)

# Create the database tables (if they do not exist)
with app.app_context():
    db.create_all()
