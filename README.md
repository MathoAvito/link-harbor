# 🚢 Link Harbor

<div align="center">

[![Made with: Flask](https://img.shields.io/badge/Made%20with-Flask-black?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Style: Black](https://img.shields.io/badge/Style-Black-black?style=for-the-badge)](https://black.readthedocs.io/en/stable/)
[![Styled with: Tailwind CSS](https://img.shields.io/badge/Styled%20with-Tailwind-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)

Your personal harbor for bookmark management - modern, clean, and efficient.

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration)

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

### Quick Start

1️⃣ **Clone & Navigate**
```bash
git clone https://github.com/yourusername/link-harbor.git
cd link-harbor
```

2️⃣ **Set Up Environment**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3️⃣ **Install Dependencies**
```bash
pip install -r requirements.txt
```

4️⃣ **Environment Setup**
Copy `.env.example` to `.env` and configure your environment variables.

5️⃣ **Launch**
```bash
flask run
```

🎉 Access your Link Harbor at `http://localhost:5000`

## 🔐 User Management

Link Harbor implements a robust user management system powered by AWS Cognito, providing:

### Authentication Features
- Secure email & password authentication
- Social identity provider integration (optional)
- Multi-factor authentication support
- Password policies and account recovery
- Session management with JWT tokens

### User Features
- Personal bookmark spaces for each user
- Secure data isolation between users
- Enhanced profile management
  - Dedicated interfaces for username and password changes
  - Intuitive password requirements visualization
  - Real-time password validation
  - Visibility toggles for sensitive fields
- Password reset functionality
- Email verification

### Security Measures
- OAuth 2.0 authorization flow
- Secure token handling
- HTTPS enforcement
- Protection against common web vulnerabilities
- Regular security updates

For detailed AWS Cognito setup instructions, see [COGNITO_SETUP.md](COGNITO_SETUP.md)

## ⚙️ Configuration

### 🔄 Import Chrome Bookmarks

1. Open Chrome → Bookmarks → Bookmark Manager
2. Click ⋮ → "Export bookmarks"
3. In Link Harbor → "Import Bookmarks" → Upload

### 🔄 GitHub Actions

Automated workflows ensure code quality:

| Workflow | Purpose |
|----------|---------|
| 🛡️ Snyk Security | Dependency vulnerability scanning |
