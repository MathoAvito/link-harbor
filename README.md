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
- 🔐 **Secure Authentication** - Keep your bookmarks private and secure
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
```bash
# Linux/Mac
export FLASK_SECRET_KEY='your-secret-key'

# Windows
set FLASK_SECRET_KEY=your-secret-key
```

5️⃣ **Launch**
```bash
flask run
```

🎉 Access your Link Harbor at `http://localhost:5000`

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
