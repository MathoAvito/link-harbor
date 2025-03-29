import os
import json
import logging
from flask_awscognito import AWSCognitoAuthentication
from flask_awscognito.exceptions import FlaskAWSCognitoError
from flask_awscognito.services import CognitoService

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Enable debug logging for urllib3 and requests
logging.getLogger('urllib3').setLevel(logging.DEBUG)
logging.getLogger('requests').setLevel(logging.DEBUG)

# Cognito configuration
AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
AWS_COGNITO_DOMAIN = os.environ.get('AWS_COGNITO_DOMAIN')
AWS_COGNITO_USER_POOL_ID = os.environ.get('AWS_COGNITO_USER_POOL_ID')
AWS_COGNITO_USER_POOL_CLIENT_ID = os.environ.get('AWS_COGNITO_USER_POOL_CLIENT_ID')
AWS_COGNITO_USER_POOL_CLIENT_SECRET = os.environ.get('AWS_COGNITO_CLIENT_SECRET')
AWS_COGNITO_REDIRECT_URL = os.environ.get('AWS_COGNITO_REDIRECT_URL')
AWS_COGNITO_LOGOUT_URL = os.environ.get('AWS_COGNITO_LOGOUT_URL')
AWS_COGNITO_APP_SECRET = os.environ.get('AWS_COGNITO_APP_SECRET')

# Get OAuth scopes from environment or use defaults
try:
    AWS_COGNITO_OAUTH_SCOPES = json.loads(os.environ.get('AWS_COGNITO_OAUTH_SCOPES', '["email", "openid", "profile"]'))
except json.JSONDecodeError:
    AWS_COGNITO_OAUTH_SCOPES = ["email", "openid", "profile"]

def get_cognito_config():
    """Returns the Cognito configuration for the app."""
    # Use the full domain with https://
    domain = AWS_COGNITO_DOMAIN
    if not domain.startswith('https://'):
        domain = f'https://{domain}'
    
    logger.debug(f"Full Cognito Domain: {domain}")
    logger.debug(f"Redirect URL: {AWS_COGNITO_REDIRECT_URL}")
    logger.debug(f"Client ID: {AWS_COGNITO_USER_POOL_CLIENT_ID}")
    logger.debug(f"User Pool ID: {AWS_COGNITO_USER_POOL_ID}")
    logger.debug(f"OAuth Scopes: {AWS_COGNITO_OAUTH_SCOPES}")
    
    config = {
        'AWS_DEFAULT_REGION': AWS_DEFAULT_REGION,
        'AWS_COGNITO_DOMAIN': domain,
        'AWS_COGNITO_USER_POOL_ID': AWS_COGNITO_USER_POOL_ID,
        'AWS_COGNITO_USER_POOL_CLIENT_ID': AWS_COGNITO_USER_POOL_CLIENT_ID,
        'AWS_COGNITO_REDIRECT_URL': AWS_COGNITO_REDIRECT_URL,
        'AWS_COGNITO_LOGOUT_URL': AWS_COGNITO_LOGOUT_URL,
        'AWS_COGNITO_OAUTH_SCOPES': AWS_COGNITO_OAUTH_SCOPES,
        'COGNITO_APP_SECRET': AWS_COGNITO_APP_SECRET,
        'COGNITO_CHECK_TOKEN_EXPIRATION': False,  # For development
    }
    
    # Only add client secret if it's set
    if AWS_COGNITO_USER_POOL_CLIENT_SECRET:
        config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = AWS_COGNITO_USER_POOL_CLIENT_SECRET
        logger.debug("Client secret is configured")
    
    return config

def init_cognito(app):
    """Initialize AWS Cognito authentication."""
    try:
        # Add Cognito config to app
        config = get_cognito_config()
        app.config.update(config)
        
        # Log full configuration (excluding secrets)
        safe_config = {k: v for k, v in config.items() if 'SECRET' not in k}
        logger.debug(f"Cognito Configuration: {json.dumps(safe_config, indent=2)}")
        
        # Initialize the AWSCognitoAuthentication extension
        aws_auth = AWSCognitoAuthentication(app)
        logger.debug("AWSCognitoAuthentication initialized")
        
        return aws_auth
    except FlaskAWSCognitoError as e:
        logger.error(f"Failed to initialize Cognito: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error initializing Cognito: {str(e)}")
        raise 