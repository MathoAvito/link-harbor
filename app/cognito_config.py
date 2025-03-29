import os
from flask_awscognito import AWSCognitoAuthentication

# Cognito configuration
AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
AWS_COGNITO_DOMAIN = os.environ.get('AWS_COGNITO_DOMAIN')
AWS_COGNITO_USER_POOL_ID = os.environ.get('AWS_COGNITO_USER_POOL_ID')
AWS_COGNITO_USER_POOL_CLIENT_ID = os.environ.get('AWS_COGNITO_USER_POOL_CLIENT_ID')
AWS_COGNITO_USER_POOL_CLIENT_SECRET = os.environ.get('AWS_COGNITO_USER_POOL_CLIENT_SECRET')
AWS_COGNITO_REDIRECT_URL = os.environ.get('AWS_COGNITO_REDIRECT_URL')
AWS_COGNITO_LOGOUT_URL = os.environ.get('AWS_COGNITO_LOGOUT_URL')

def get_cognito_config():
    """Returns the Cognito configuration for the app."""
    return {
        'AWS_DEFAULT_REGION': AWS_DEFAULT_REGION,
        'AWS_COGNITO_DOMAIN': AWS_COGNITO_DOMAIN,
        'AWS_COGNITO_USER_POOL_ID': AWS_COGNITO_USER_POOL_ID,
        'AWS_COGNITO_USER_POOL_CLIENT_ID': AWS_COGNITO_USER_POOL_CLIENT_ID,
        'AWS_COGNITO_USER_POOL_CLIENT_SECRET': AWS_COGNITO_USER_POOL_CLIENT_SECRET,
        'AWS_COGNITO_REDIRECT_URL': AWS_COGNITO_REDIRECT_URL,
        'AWS_COGNITO_LOGOUT_URL': AWS_COGNITO_LOGOUT_URL
    }

def init_cognito(app):
    """Initialize AWS Cognito authentication."""
    # Add Cognito config to app
    app.config.update(get_cognito_config())
    
    # Initialize the AWSCognitoAuthentication extension
    aws_auth = AWSCognitoAuthentication(app)
    
    return aws_auth 