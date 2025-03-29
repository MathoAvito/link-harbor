#!/bin/bash

# AWS Elastic Beanstalk Deployment Script for Link Harbor
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Link Harbor AWS Deployment Script${NC}"
echo "-----------------------------------"

# Check if EB CLI is installed
if ! command -v eb &> /dev/null; then
    echo -e "${RED}Error: AWS EB CLI is not installed. Please install with: pip install awsebcli${NC}"
    exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check AWS configuration
echo -e "${BLUE}Checking AWS configuration...${NC}"
if ! aws configure list &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not configured. Run 'aws configure' first.${NC}"
    exit 1
fi

# Create or update EB configuration
if [ ! -d .elasticbeanstalk ]; then
    echo -e "${BLUE}Initializing Elastic Beanstalk application...${NC}"
    read -p "Enter AWS region [us-east-1]: " region
    region=${region:-us-east-1}
    
    read -p "Enter application name [link-harbor]: " app_name
    app_name=${app_name:-link-harbor}
    
    echo -e "${BLUE}Initializing EB application in ${region}...${NC}"
    eb init -p python-3.8 "$app_name" --region "$region"
else
    echo -e "${GREEN}EB application already initialized.${NC}"
fi

# Create or update environment
if ! eb status &> /dev/null; then
    echo -e "${BLUE}Creating new EB environment...${NC}"
    read -p "Enter environment name [link-harbor-env]: " env_name
    env_name=${env_name:-link-harbor-env}
    
    # Create the environment
    echo -e "${BLUE}Creating environment ${env_name}...${NC}"
    eb create "$env_name"
else
    echo -e "${GREEN}EB environment already exists.${NC}"
fi

# Remind about environment variables
echo -e "${BLUE}Important: Set these environment variables in the EB Console:${NC}"
echo "- AWS_DEPLOYMENT=True"
echo "- FLASK_SECRET_KEY=<your-secret-key>"
echo "- AWS_COGNITO_DOMAIN=<your-cognito-domain>"
echo "- AWS_COGNITO_USER_POOL_ID=<your-user-pool-id>"
echo "- AWS_COGNITO_USER_POOL_CLIENT_ID=<your-client-id>"
echo "- AWS_COGNITO_USER_POOL_CLIENT_SECRET=<your-client-secret>"
echo "- AWS_COGNITO_REDIRECT_URL=<your-eb-url>/aws-cognito-callback"
echo "- AWS_COGNITO_LOGOUT_URL=<your-eb-url>/login"

# Ask to deploy
read -p "Deploy now? (y/n): " deploy_now
if [[ $deploy_now == "y" || $deploy_now == "Y" ]]; then
    echo -e "${BLUE}Deploying to Elastic Beanstalk...${NC}"
    eb deploy
    
    echo -e "${GREEN}Deployment complete! Opening application...${NC}"
    eb open
    
    echo -e "${BLUE}Configure your Cognito app client with these URLs:${NC}"
    echo "- Sign in callback URL: <your-eb-url>/aws-cognito-callback"
    echo "- Sign out URL: <your-eb-url>/login"
else
    echo -e "${BLUE}To deploy later, run:${NC} eb deploy"
fi

echo -e "${GREEN}Setup complete!${NC}" 