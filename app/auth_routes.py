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
import hmac
import hashlib
import secrets
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
from sqlalchemy.exc import IntegrityError
from functools import wraps

# Configure logging for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

auth_bp = Blueprint('auth', __name__)
oauth = OAuth()

def init_oauth(app):
    """Initialize OAuth with the application context"""
    oauth.init_app(app)
    
    # Log all configuration values (except secrets)
    logger.debug("AWS Configuration:")
    logger.debug(f"AWS_DEFAULT_REGION: {app.config.get('AWS_DEFAULT_REGION')}")
    logger.debug(f"AWS_COGNITO_DOMAIN: {app.config.get('AWS_COGNITO_DOMAIN')}")
    logger.debug(f"AWS_COGNITO_USER_POOL_ID: {app.config.get('AWS_COGNITO_USER_POOL_ID')}")
    logger.debug(f"AWS_COGNITO_USER_POOL_CLIENT_ID: {app.config.get('AWS_COGNITO_USER_POOL_CLIENT_ID')}")
    logger.debug(f"AWS_COGNITO_REDIRECT_URL: {app.config.get('AWS_COGNITO_REDIRECT_URL')}")
    logger.debug(f"AWS_COGNITO_LOGOUT_URL: {app.config.get('AWS_COGNITO_LOGOUT_URL')}")
    
    # Construct the full Cognito domain
    domain = f"{app.config['AWS_COGNITO_DOMAIN']}.auth.{app.config['AWS_DEFAULT_REGION']}.amazoncognito.com"
    logger.debug(f"Using Cognito domain: {domain}")
    
    # Construct the OAuth URLs
    authorize_url = f"https://{domain}/oauth2/authorize"
    token_url = f"https://{domain}/oauth2/token"
    userinfo_url = f"https://{domain}/oauth2/userInfo"
    
    # Construct JWKS URL using the user pool ID
    region = app.config['AWS_DEFAULT_REGION']
    user_pool_id = app.config['AWS_COGNITO_USER_POOL_ID']
    jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    
    logger.debug("OAuth URLs:")
    logger.debug(f"Authorize URL: {authorize_url}")
    logger.debug(f"Token URL: {token_url}")
    logger.debug(f"UserInfo URL: {userinfo_url}")
    logger.debug(f"JWKS URL: {jwks_url}")
    
    # Define the OAuth scopes
    scopes = 'openid email profile'
    logger.debug(f"Using OAuth scopes: {scopes}")
    
    oauth.register(
        name='cognito',
        client_id=app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'],
        client_secret=app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'],
        authorize_url=authorize_url,
        access_token_url=token_url,
        api_base_url=f"https://{domain}",
        userinfo_endpoint=userinfo_url,
        jwks_uri=jwks_url,
        client_kwargs={
            'scope': scopes,
            'token_endpoint_auth_method': 'client_secret_post'
        }
    )
    
    logger.debug("OAuth initialization complete")

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

def verify_cognito_user_exists(f):
    """
    Decorator to verify that the user still exists in Cognito
    before proceeding with protected routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.aws_cognito_id:
            try:
                client = boto3.client('cognito-idp', 
                                     region_name=current_app.config['AWS_DEFAULT_REGION'])
                
                # Try to get the user from Cognito
                client.admin_get_user(
                    UserPoolId=current_app.config['AWS_COGNITO_USER_POOL_ID'],
                    Username=current_user.username
                )
                # If we get here, the user exists in Cognito
                return f(*args, **kwargs)
            except client.exceptions.UserNotFoundException:
                # User no longer exists in Cognito
                logger.warning(f"User {current_user.username} (ID: {current_user.id}) exists locally but was deleted from Cognito. Force logging out.")
                logout_user()
                session.clear()
                flash("Your account has been deleted or deactivated. Please contact support if this is unexpected.", "error")
                return redirect(url_for('auth.login'))
            except Exception as e:
                # If we can't connect to Cognito, let the user continue but log the error
                logger.error(f"Error verifying Cognito user {current_user.username}: {str(e)}")
                return f(*args, **kwargs)
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/profile')
@login_required
@verify_cognito_user_exists
def profile():
    return render_template('profile.html')

@auth_bp.route('/change-username')
@login_required
@verify_cognito_user_exists
def change_username():
    return render_template('change_username.html')

@auth_bp.route('/change-password')
@login_required
@verify_cognito_user_exists
def change_password():
    return render_template('change_password.html')

def calculate_secret_hash(username):
    """Calculate the secret hash for Cognito authentication"""
    try:
        client_id = current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID']
        client_secret = current_app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET']
        if not client_secret:
            # If there's no client secret, no hash is needed
            return None
        message = username + client_id
        dig = hmac.new(
            key=client_secret.encode('utf-8'),
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(dig).decode()
    except KeyError as e:
        logger.error(f"Missing Cognito configuration for secret hash: {e}")
        return None # Or raise an error if secret hash is strictly required

@auth_bp.route('/update-username', methods=['POST'])
@login_required
@verify_cognito_user_exists
def update_username():
    new_username_input = request.form.get('new_username')
    current_password = request.form.get('current_password')

    if not new_username_input or not current_password:
        flash('Please provide both new username and current password', 'error')
        return redirect(url_for('auth.change_username'))

    try:
        # Create Cognito client
        client = boto3.client('cognito-idp', 
                            region_name=current_app.config['AWS_DEFAULT_REGION'])

        # Get the Cognito username (login name) and sub from the logged-in user
        cognito_login_username = current_user.username # The name used to log in (e.g., 'matan')
        cognito_sub = current_user.aws_cognito_id    # The unique identifier
        
        if not cognito_login_username or not cognito_sub:
            logger.error("Could not find Cognito login username or sub for current user")
            flash('User authentication error. Please log in again.', 'error')
            return redirect(url_for('auth.login'))

        logger.debug(f"Attempting password verification for Cognito user: {cognito_login_username} (sub: {cognito_sub})")

        # Calculate secret hash if client secret exists
        secret_hash = calculate_secret_hash(cognito_login_username)
        auth_params = {
            'USERNAME': cognito_login_username,
            'PASSWORD': current_password
        }
        if secret_hash:
            auth_params['SECRET_HASH'] = secret_hash
            logger.debug("Including SECRET_HASH in initiate_auth call")
        else:
            logger.debug("No SECRET_HASH included (client secret likely not configured)")

        # Log the parameters right before the call
        logger.debug(f"Calling initiate_auth with ClientId: {current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID']}")
        logger.debug(f"AuthFlow: USER_PASSWORD_AUTH")
        # Be cautious logging password in production, ok for debug
        logger.debug(f"AuthParameters: {json.dumps(auth_params)}") 

        # Verify the current password using initiate_auth
        try:
            client.initiate_auth(
                ClientId=current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'],
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters=auth_params
            )
            logger.debug("Password verification successful")

        except client.exceptions.NotAuthorizedException:
            logger.error("Password verification failed: Incorrect password or username/hash issue")
            flash('Current password is incorrect', 'error')
            return redirect(url_for('auth.change_username'))
        except client.exceptions.UserNotFoundException:
            logger.error(f"Password verification failed: User {cognito_login_username} not found")
            flash('User not found. Please log in again.', 'error')
            return redirect(url_for('auth.login'))
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            logger.error(f"Password verification failed with ClientError: {error_code} - {str(e)}", exc_info=True)
            flash(f'Password verification error: {error_code}', 'error')
            return redirect(url_for('auth.change_username'))
        except Exception as e:
            logger.error(f"Password verification failed with unexpected error: {str(e)}", exc_info=True)
            flash('An error occurred during password verification.', 'error')
            return redirect(url_for('auth.change_username'))

        # Password verified, now update the username attribute (preferred_username)
        try:
            logger.debug(f"Updating preferred_username for {cognito_login_username} to {new_username_input}")
            response = client.admin_update_user_attributes(
                UserPoolId=current_app.config['AWS_COGNITO_USER_POOL_ID'],
                Username=cognito_login_username, # Use the LOGIN USERNAME for this call
                UserAttributes=[
                    {
                        'Name': 'preferred_username', 
                        'Value': new_username_input
                    },
                    {
                        'Name': 'email', # Keep email the same, just include it
                        'Value': current_user.email
                    }
                ]
            )
            logger.debug(f"Username update response: {response}")

            # Update username in local database
            # Note: We update the local 'username' field which might store preferred_username or login name
            current_user.username = new_username_input 
            db.session.commit()
            logger.debug("Username updated in local database")

            flash('Username updated successfully!', 'success')
            return redirect(url_for('auth.profile'))

        except client.exceptions.AliasExistsException:
            logger.error(f"Failed to update username: Alias {new_username_input} already exists")
            flash('This username is already taken', 'error')
            return redirect(url_for('auth.change_username'))
        except client.exceptions.InvalidParameterException as e:
            logger.error(f"Invalid parameter error during username update: {str(e)}")
            flash(f'Invalid username format or parameter: {e}', 'error')
            return redirect(url_for('auth.change_username'))
        except botocore.exceptions.ClientError as e:
             error_code = e.response.get('Error', {}).get('Code')
             logger.error(f"Client error updating username: {error_code} - {e.response.get('Error', {}).get('Message')}", exc_info=True)
             flash(f'Error updating username: {error_code}', 'error')
             return redirect(url_for('auth.change_username'))
        except Exception as e:
            logger.error(f"Error updating username in Cognito: {str(e)}", exc_info=True)
            flash('Failed to update username in Cognito. Please try again.', 'error')
            return redirect(url_for('auth.change_username'))

    except Exception as e:
        logger.error(f"Unexpected error in update_username route: {str(e)}", exc_info=True)
        flash('An unexpected error occurred. Please try again.', 'error')
        return redirect(url_for('auth.change_username'))

@auth_bp.route('/update-password', methods=['POST'])
@login_required
@verify_cognito_user_exists
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        flash('Please fill in all password fields', 'error')
        return redirect(url_for('auth.change_password'))

    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('auth.change_password'))

    try:
        # Get Cognito client
        client = boto3.client('cognito-idp', region_name=current_app.config['AWS_DEFAULT_REGION'])

        # Use the existing access token from the session
        access_token = session.get('access_token')
        if not access_token:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('auth.login'))

        try:
            # Change password using the access token
            client.change_password(
                PreviousPassword=current_password,
                ProposedPassword=new_password,
                AccessToken=access_token
            )

            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth.profile'))

        except client.exceptions.NotAuthorizedException:
            flash('Current password is incorrect', 'error')
            return redirect(url_for('auth.change_password'))

    except client.exceptions.InvalidPasswordException:
        flash('New password does not meet the requirements. Password must be at least 8 characters long and include uppercase and lowercase letters, numbers, and special characters.', 'error')
        return redirect(url_for('auth.change_password'))
    except botocore.exceptions.ClientError as e:
        logger.error(f"Failed to change password: {str(e)}")
        flash('Failed to change password. Please try again later.', 'error')
        return redirect(url_for('auth.change_password'))

def handle_user_login(username, email, sub, access_token, id_token):
    """Helper function to handle user login after successful authentication"""
    
    # First, check for users that have been deleted in Cognito but still exist in our database
    # This helps clean up orphaned records
    try:
        client = boto3.client('cognito-idp', region_name=current_app.config['AWS_DEFAULT_REGION'])
        # Look for potential duplicate user records with same email but different Cognito ID
        potential_duplicates = User.query.filter_by(email=email).all()
        
        for user in potential_duplicates:
            if user.aws_cognito_id != sub:
                try:
                    # Check if this user's Cognito ID still exists
                    client.admin_get_user(
                        UserPoolId=current_app.config['AWS_COGNITO_USER_POOL_ID'],
                        Username=user.username
                    )
                    # User still exists in Cognito, keep the record
                except client.exceptions.UserNotFoundException:
                    # User doesn't exist in Cognito anymore, delete the local record
                    logger.warning(f"Deleting orphaned user record for {user.username} (ID: {user.id}, Cognito ID: {user.aws_cognito_id})")
                    db.session.delete(user)
                    db.session.commit()
                except Exception as e:
                    # Log error but continue with login process
                    logger.error(f"Error checking Cognito status for potential duplicate {user.username}: {str(e)}")
    except Exception as e:
        # Log the error but continue with the login process
        logger.error(f"Error during Cognito user cleanup: {str(e)}")
    
    # Check if we know this user
    user = User.query.filter_by(aws_cognito_id=sub).first()
    
    if not user:
        # Check for existing user by username
        existing_user_by_username = User.query.filter_by(username=username).first()
        
        if existing_user_by_username:
            # Found a user by username, update their Cognito ID
            logger.warning(f"Found existing local user '{username}' by username. Updating Cognito ID to {sub}.")
            user = existing_user_by_username
            user.aws_cognito_id = sub  # Link to the Cognito sub
            user.email = email  # Update email too
            try:
                db.session.commit()
                logger.info(f"Successfully updated Cognito ID for user '{username}'")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to update Cognito ID for user '{username}': {e}", exc_info=True)
                flash("Failed to link your existing profile. Please contact support.", "error")
                return redirect(url_for('auth.login'))
        else:
            # Check for existing user by email
            existing_user_by_email = User.query.filter_by(email=email).first()
            
            if existing_user_by_email:
                # Found user by email - update their Cognito ID and username
                logger.warning(f"Found existing local user with email '{email}'. Updating Cognito ID and username.")
                user = existing_user_by_email
                user.aws_cognito_id = sub  # Link to the Cognito sub
                user.username = username  # Update username
                try:
                    db.session.commit()
                    logger.info(f"Successfully updated existing user with email '{email}' to Cognito ID {sub}")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Failed to update existing user with email '{email}': {e}", exc_info=True)
                    flash("Failed to link your existing profile. Please contact support.", "error")
                    return redirect(url_for('auth.login'))
            else:
                # No existing user found - create a new one
                logger.info(f"Creating new user with username={username}, email={email}")
                try:
                    user = User(
                        username=username,
                        email=email,
                        aws_cognito_id=sub
                    )
                    db.session.add(user)
                    db.session.commit()
                    logger.info(f"Successfully created new user: {username}")
                except IntegrityError as e:
                    db.session.rollback()
                    logger.error(f"Database integrity error during user creation for {username}: {e}", exc_info=True)
                    flash("Failed to create user profile due to a database conflict. Please try with a different username or contact support.", "error")
                    return redirect(url_for('auth.login'))
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Unexpected error during user creation for {username}: {e}", exc_info=True)
                    flash("An unexpected error occurred while creating your user profile.", "error")
                    return redirect(url_for('auth.login'))
    else:
        logger.info(f"Found existing user: {user.username}")
        # Update user info if needed
        needs_update = False
        if user.username != username:
            user.username = username
            needs_update = True
        if user.email != email:
            user.email = email
            needs_update = True
        
        if needs_update:
            try:
                db.session.commit()
                logger.info(f"Updated user information for {username}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to update user information: {e}")
                # Not critical, continue with login
    
    # Log the user in
    if user:
        login_user(user)
        logger.info(f"Successfully logged in user {username}")
        
        # Store the tokens in the session
        session['access_token'] = access_token
        session['id_token'] = id_token
        
        next_url = session.get('next', url_for('main.dashboard'))
        logger.info(f"Redirecting to {next_url}")
        
        flash("Logged in successfully!")
        return redirect(next_url)
    else:
        # Should not happen if logic above is correct, but handle defensively
        logger.error("User object is None after attempting find/link/create.")
        flash("Login failed due to an internal error.")
        return redirect(url_for('auth.login'))
