from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from app.models import User
from app import db, aws_auth
import boto3
import botocore.exceptions
import json
import logging
import requests
import base64

# Configure logging for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    logger.debug("Redirecting to Cognito sign-up URL")
    return redirect(aws_auth.get_sign_up_url())

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    # Clear any existing session data
    session.clear()
    logger.debug("Redirecting to Cognito sign-in URL")
    return redirect(aws_auth.get_sign_in_url())

@auth_bp.route('/logout')
@login_required
def logout():
    # Clear Flask-Login session
    logout_user()
    # Clear Flask session
    session.clear()
    
    logger.debug("Constructing Cognito sign-out URL")
    
    # Construct the sign-out URL
    cognito_domain = current_app.config['AWS_COGNITO_DOMAIN']
    client_id = current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID']
    logout_uri = url_for('auth.login', _external=True)
    
    # Cognito logout endpoint
    logout_url = (
        f"{cognito_domain}/logout?"
        f"client_id={client_id}&"
        f"logout_uri={logout_uri}"
    )
    
    logger.debug(f"Redirecting to Cognito logout URL: {logout_url}")
    return redirect(logout_url)

@auth_bp.route('/aws-cognito-callback')
def aws_cognito_callback():
    """Handle the callback from AWS Cognito"""
    try:
        # Log the incoming request parameters
        logger.info(f"Callback received with args: {request.args}")
        logger.debug(f"Full request headers: {dict(request.headers)}")
        
        if 'error' in request.args:
            logger.error(f"Error in callback: {request.args.get('error')}")
            logger.error(f"Error description: {request.args.get('error_description')}")
            flash(f"Authentication error: {request.args.get('error_description', 'Unknown error')}")
            return redirect(url_for('auth.login'))

        # Log the state parameter
        state = request.args.get('state')
        logger.debug(f"State parameter: {state}")
        
        # Exchange the authorization code for tokens
        logger.debug("Attempting to exchange authorization code for access token")
        try:
            # Get the access token using the library's method
            access_token = aws_auth.get_access_token(request.args)
            logger.debug(f"Access token received")
            
            if not access_token:
                raise ValueError("No access token received")
            
            # Decode the JWT token to get user info
            logger.debug("Decoding JWT token")
            token_parts = access_token.split('.')
            if len(token_parts) != 3:
                raise ValueError("Invalid JWT token format")
            
            # Decode the payload (second part)
            payload = token_parts[1]
            # Add padding if needed
            payload += '=' * ((4 - len(payload) % 4) % 4)
            decoded_payload = base64.b64decode(payload)
            user_info = json.loads(decoded_payload)
            logger.debug(f"Decoded token payload: {json.dumps(user_info)}")
            
            # Extract user details from token claims
            username = user_info.get('username')
            # The email claim might be in the token if we requested the 'email' scope
            email = user_info.get('email')
            # The 'sub' claim is the unique identifier for the user
            sub = user_info.get('sub')
            
            if not username or not sub:
                logger.error(f"Missing required user info: username={username}, sub={sub}")
                flash("Failed to get complete user information")
                return redirect(url_for('auth.login'))
            
            # If email is not in the token, use username@example.com as a fallback
            if not email:
                email = f"{username}@example.com"
                logger.warning(f"Email not found in token, using fallback: {email}")
            
            return handle_user_login(username, email, sub, access_token, access_token)  # Using access_token as id_token for now
            
        except Exception as e:
            logger.error(f"Failed to get tokens: {str(e)}")
            flash("Failed to authenticate. Please try again.")
            return redirect(url_for('auth.login'))
    except Exception as e:
        logger.error(f"Login failed: {str(e)}", exc_info=True)
        logger.error(f"Request args: {request.args}")
        flash(f"Login failed: {str(e)}")
        return redirect(url_for('auth.login'))

def handle_user_login(username, email, sub, access_token, id_token):
    """Helper function to handle user login after successful authentication"""
    # Check if we know this user
    user = User.query.filter_by(aws_cognito_id=sub).first()
    if not user:
        logger.info(f"Creating new user with username={username}, email={email}")
        # Create the user in our database
        user = User(
            username=username,
            email=email,
            aws_cognito_id=sub
        )
        db.session.add(user)
        db.session.commit()
    else:
        logger.info(f"Found existing user: {user.username}")
    
    # Log the user in
    login_user(user)
    logger.info(f"Successfully logged in user {username}")
    
    # Store the tokens in the session
    session['access_token'] = access_token
    session['id_token'] = id_token
    
    next_url = session.get('next', url_for('main.dashboard'))
    logger.info(f"Redirecting to {next_url}")
    
    flash("Logged in successfully!")
    return redirect(next_url)
