# AWS Cognito Setup Guide

This guide provides instructions for setting up AWS Cognito authentication for the Link Harbor dashboard.

## Prerequisites

- AWS Account
- AWS CLI installed and configured
- Basic understanding of AWS Cognito concepts

## Setting up AWS Cognito

### 1. Create User Pool
1. Go to AWS Cognito Console
2. Create a new User Pool
3. Choose "Traditional web application"
4. Configure sign-in options:
   - Enable email and username sign-in
   - Add email as a required attribute

### 2. Configure App Client
1. Create a new app client in your User Pool
2. Configure OAuth:
   - Callback URL: `http://localhost:5000/aws-cognito-callback` (development)
   - Sign out URL: `http://localhost:5000/login`
   - Allowed OAuth Flows: Authorization code grant
   - Allowed OAuth Scopes: email, openid, profile

### 3. Configure Domain
1. Set up a Cognito domain for your User Pool
2. Note down the domain URL

## Local Development Configuration

1. Copy `.env.example` to `.env`
2. Update the following variables:
   ```
   AWS_DEPLOYMENT=True
   AWS_DEFAULT_REGION=your-region
   AWS_COGNITO_DOMAIN=your-domain.auth.region.amazoncognito.com
   AWS_COGNITO_USER_POOL_ID=your-user-pool-id
   AWS_COGNITO_USER_POOL_CLIENT_ID=your-client-id
   AWS_COGNITO_USER_POOL_CLIENT_SECRET=your-client-secret
   AWS_COGNITO_REDIRECT_URL=http://localhost:5000/aws-cognito-callback
   AWS_COGNITO_LOGOUT_URL=http://localhost:5000/login
   ```

## Production Deployment

When deploying to production:
1. Update the callback and sign out URLs in your Cognito App Client settings
2. Update the environment variables in your deployment environment
3. Ensure your domain has proper SSL certification

## Troubleshooting

- If login fails, check that all environment variables are correctly set
- Verify that callback URLs match exactly between your app and Cognito settings
- Ensure your app's domain is allowed in the App Client settings 