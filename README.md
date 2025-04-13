# 🚢 Link Harbor

<div align="center">

[![Made with: Flask](https://img.shields.io/badge/Made%20with-Flask-black?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Style: Black](https://img.shields.io/badge/Style-Black-black?style=for-the-badge)](https://black.readthedocs.io/en/stable/)
[![Styled with: Tailwind CSS](https://img.shields.io/badge/Styled%20with-Tailwind-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)

Your personal harbor for bookmark management - modern, clean, and efficient.

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Running the Application](#-running-the-application) • [Troubleshooting](#-troubleshooting)

</div>

## 🌟 Features

### Core Features
- 🔐 **Enterprise-Grade Authentication** - Secure user management with AWS Cognito
- 📁 **Smart Organization** - Categorize and group your bookmarks effortlessly
- 🌓 **Dark/Light Mode** - Easy on your eyes, day or night
- 📱 **Responsive Design** - Perfect viewing on any device
- 🎯 **Chrome Import** - Seamlessly import your Chrome bookmarks
- 🎨 **Customizable UI** - Choose between compact and spacious views

### Power Features
- 🔄 **Drag & Drop Reordering** - Organize your bookmarks naturally
- 🔍 **Quick Access** - Find your bookmarks instantly
- 📊 **Category Management** - Expand/collapse categories for better overview
- 🎲 **Dynamic Layouts** - Adapt the view to your preferences

### Security Features
- 🔒 **AWS Cognito Integration** - Enterprise-level authentication and user management
- 👥 **Multi-User Support** - Each user has their own secure bookmark space
- 🔑 **OAuth 2.0 Flow** - Industry-standard authentication protocol
- 📧 **Email Verification** - Ensure user authenticity through email verification
- 🔄 **Token-Based Sessions** - Secure session management with JWT tokens

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pip
- virtualenv (recommended)
- An AWS account with Cognito configured (see Configuration section)

### Quick Start

1️⃣ **Clone & Navigate**
```bash
# Replace with your actual repository URL if different
git clone https://github.com/yourusername/link-harbor.git
cd link-harbor/dashboard
```

2️⃣ **Set Up Environment**
```bash
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

3️⃣ **Install Dependencies**
```bash
pip install -r requirements.txt
```

4️⃣ **Environment Setup**
Create a `.env` file in the `dashboard` directory (where `requirements.txt` is). See the [Configuration](#-configuration) section below for the required variables.

5️⃣ **Database Initialization**
The application uses Flask-SQLAlchemy and Flask-Migrate. The database tables should be created automatically on the first run based on the models defined in `app/models.py`. For schema changes later, you might need migration commands:
```bash
# One-time setup if using migrations for the first time
# flask db init

# When models change:
flask db migrate -m "Describe changes"
flask db upgrade
```
*(Note: Currently, `db.create_all()` in `app/__init__.py` handles initial creation, but migrations are set up for future use.)*


## ⚙️ Configuration

Configuration is primarily handled through environment variables loaded from a `.env` file located in the `dashboard` directory.

**Create a file named `.env`** and add the following variables, replacing the placeholder values with your actual settings:

```dotenv
# Flask Specific
# Generate a strong secret key (e.g., using python -c 'import secrets; print(secrets.token_hex(32))')
FLASK_SECRET_KEY=your_strong_random_secret_key

# Database Configuration
# Use a file-based SQLite DB (default) or a different URL (e.g., PostgreSQL)
# DATABASE_URL=sqlite:///users.db
# Example for PostgreSQL: DATABASE_URL=postgresql://user:password@host:port/dbname
DATABASE_URL=sqlite:///instance/users.db # Recommended to store in instance folder

# AWS Cognito Configuration (Required)
# Set to True if using Cognito for authentication
AWS_DEPLOYMENT=True

# Your AWS Region (e.g., us-east-1, eu-north-1)
AWS_DEFAULT_REGION=your_aws_region

# --- CRITICAL ---
# Your Cognito User Pool Domain. This can be either:
# 1. The Domain Prefix you configured (e.g., my-link-harbor-app)
# OR
# 2. The Full Domain URL (e.g., my-link-harbor-app.auth.your_aws_region.amazoncognito.com)
# **Do NOT use a mix of region/pool ID here.** Using the full URL is often safer.
AWS_COGNITO_DOMAIN=your_cognito_domain_prefix_or_full_url

# Your Cognito User Pool ID (e.g., your_aws_region_xxxxxxxxx)
AWS_COGNITO_USER_POOL_ID=your_user_pool_id

# Your Cognito User Pool App Client ID
AWS_COGNITO_USER_POOL_CLIENT_ID=your_app_client_id

# Your Cognito User Pool App Client Secret (Required by flask_awscognito)
# Found in the App Client settings in Cognito.
AWS_COGNITO_USER_POOL_CLIENT_SECRET=your_app_client_secret

# The full URL for the Cognito callback endpoint in your app
# (Must match one of the Allowed Callback URLs in your Cognito App Client settings)
AWS_COGNITO_REDIRECT_URL=http://localhost:8000/aws-cognito-callback # Adjust port if needed

# The URL users are redirected to *after* logging out from Cognito
# Typically the login page of your app.
AWS_COGNITO_LOGOUT_URL=http://localhost:8000/login # Adjust port if needed

# --- Optional but potentially used by flask_awscognito/OAuth ---
# Scopes requested from Cognito (space-separated or JSON list)
AWS_COGNITO_OAUTH_SCOPES='openid email profile' # Default used if not set

# A secret key used by Flask-AWSCognito for session management?
# Matches the client secret in the provided .env example
AWS_COGNITO_APP_SECRET=your_app_client_secret
```

**Important:** Ensure the `AWS_COGNITO_REDIRECT_URL` matches exactly (including HTTP/HTTPS and port) one of the "Allowed callback URLs" configured in your AWS Cognito App Client settings. Similarly, ensure the `AWS_COGNITO_LOGOUT_URL` matches one of the "Allowed sign-out URLs".

## 🏃 Running the Application

### Development
For development, you can use the Flask development server:

```bash
# Ensure your virtual environment is active
source venv/bin/activate

# Set debug mode (optional, provides more output and auto-reloading)
export FLASK_DEBUG=1

# Run using Flask CLI
flask run --host=0.0.0.0 --port=8000

# Or run using the provided run.py script (if it exists and is configured)
# python3 run.py
```
The application will typically be available at `http://localhost:8000`.

### Production
**Do not use the Flask development server in production.** Use a production-grade WSGI server like Gunicorn (which is included in `requirements.txt`):

```bash
# Ensure your virtual environment is active
source venv/bin/activate

# Example: Run Gunicorn with 4 worker processes, binding to port 8000
# Adjust workers (-w) based on your server resources
gunicorn --workers 4 --bind 0.0.0.0:8000 'app:app'
```
You would typically run Gunicorn behind a reverse proxy like Nginx or Apache for handling HTTPS, static files, and load balancing.

## 🔧 Troubleshooting

### DNS Error on Login Redirect (`DNS_PROBE_FINISHED_NXDOMAIN` or similar)

This is almost always caused by an **incorrect `AWS_COGNITO_DOMAIN` value** in your `.env` file.

*   **Problem:** The browser is being redirected to a URL like `https://some-invalid-value/login?...` which doesn't actually exist.
*   **Cause:** The `AWS_COGNITO_DOMAIN` variable in your `.env` file is set incorrectly. It might be missing, misspelled, contain invalid characters, or be set to something that isn't your actual Cognito domain prefix or full domain URL (like `eu-north-1xq3o4wokd` which combines region and pool ID).
*   **Solution:**
    1.  Go to your AWS Cognito User Pool settings in the AWS Management Console.
    2.  Navigate to "App integration" -> "Domain".
    3.  Find your configured **Domain prefix** (e.g., `my-link-harbor`) or the **Full domain URL** (e.g., `my-link-harbor.auth.eu-north-1.amazoncognito.com`).
    4.  Open your `dashboard/.env` file.
    5.  Set the `AWS_COGNITO_DOMAIN` variable to **exactly** match either the prefix *or* the full URL found in step 3. Using the full URL is often less error-prone.
    6.  **Restart your Flask application** for the changes in `.env` to take effect.

### Callback URL Mismatch

*   **Problem:** After logging in successfully at Cognito, you get an error page mentioning a redirect URI mismatch.
*   **Cause:** The `AWS_COGNITO_REDIRECT_URL` in your `.env` file does not exactly match one of the "Allowed callback URLs" configured in your Cognito App Client settings.
*   **Solution:** Ensure the URL in `.env` (e.g., `http://localhost:8000/aws-cognito-callback`) is listed in the Cognito App Client's allowed callback URLs. Check for HTTP vs HTTPS, port numbers, and trailing slashes.

### Sign-out URL Mismatch

*   **Problem:** Clicking logout works, but you get an error page mentioning a sign-out URI mismatch.
*   **Cause:** The `AWS_COGNITO_LOGOUT_URL` in your `.env` file does not exactly match one of the "Allowed sign-out URLs" configured in your Cognito App Client settings.
*   **Solution:** Ensure the URL in `.env` (e.g., `http://localhost:8000/login`) is listed in the Cognito App Client's allowed sign-out URLs.

### 🔄 Import Chrome Bookmarks

1. Open Chrome → Bookmarks → Bookmark Manager
2. Click ⋮ → "Export bookmarks"
3. In Link Harbor → "Import Bookmarks" → Upload

### 🔄 GitHub Actions

Automated workflows ensure code quality:

| Workflow | Purpose |
|----------|---------|
| 🛡️ Snyk Security | Dependency vulnerability scanning |
