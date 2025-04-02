from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, session, jsonify
from flask_login import login_required, current_user
import json
import uuid
from io import BytesIO
from app.config_utils import (allowed_file, load_config, save_config, validate_config, parse_chrome_bookmarks, merge_bookmarks_with_config)
import os
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
import pandas as pd
from app.auth_routes import verify_cognito_user_exists

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
@verify_cognito_user_exists
def dashboard():
    config = load_config()
    view_mode = request.args.get('view', session.get('view_mode', 'categories'))
    session['view_mode'] = view_mode
    template = 'dashboard_open.html' if view_mode == 'open' else 'dashboard.html'
    return render_template(template, config=config, view_mode=view_mode)

@main_bp.route('/upload_config', methods=['GET', 'POST'])
@login_required
@verify_cognito_user_exists
def upload_config():
    if request.method == 'POST':
        if 'config_file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['config_file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                config = json.load(file)
                if validate_config(config):
                    save_config(config)
                    flash('Configuration uploaded successfully!')
                    return redirect(url_for('main.dashboard'))
                else:
                    flash('Invalid configuration format')
            except json.JSONDecodeError:
                flash('Invalid JSON file')
        else:
            flash('Invalid file type. Please upload a JSON file.')
        
        return redirect(request.url)
    
    return render_template('upload_config.html', config=load_config())

@main_bp.route('/upload', methods=['GET'])
@login_required
@verify_cognito_user_exists
def upload_page():
    return render_template('upload.html')

@main_bp.route('/upload/bulk', methods=['POST'])
@login_required
@verify_cognito_user_exists
def upload_bulk():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('main.upload_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('main.upload_page'))

    if not file.filename.endswith(('.csv', '.xlsx', '.xls')):
        flash('Invalid file format. Please upload a CSV or Excel file.', 'error')
        return redirect(url_for('main.upload_page'))

    try:
        # Read the file using pandas
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)

        # Validate required columns
        required_columns = ['Title', 'URL']
        if not all(col in df.columns for col in required_columns):
            flash('Invalid file format. Please use the template provided.', 'error')
            return redirect(url_for('main.upload_config'))

        # Load existing config
        config = load_config()
        
        # Process each row
        for _, row in df.iterrows():
            link = {
                'id': str(len(config['links']) + 1),
                'title': row['Title'],
                'url': row['URL'],
                'description': row['Description'] if 'Description' in row and pd.notna(row['Description']) else '',
                'category': row['Category'] if 'Category' in row and pd.notna(row['Category']) else None,
                'icon': row['Icon'] if 'Icon' in row and pd.notna(row['Icon']) else None
            }
            config['links'].append(link)

        # Save updated config
        save_config(config)
        flash('Links imported successfully!', 'success')

    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('main.upload_config'))

    return redirect(url_for('main.dashboard'))

@main_bp.route('/upload/bookmarks', methods=['GET', 'POST'])
@login_required
@verify_cognito_user_exists
def upload_bookmarks():
    if request.method == 'GET':
        return redirect(url_for('main.upload_page'))
        
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('main.upload_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('main.upload_page'))

    if not file.filename.endswith(('.html', '.htm')):
        flash('Invalid file format. Please upload a bookmark HTML file.', 'error')
        return redirect(url_for('main.upload_page'))

    try:
        # Parse the HTML file
        soup = BeautifulSoup(file.read(), 'html.parser')
        
        # Load existing config
        config = load_config()
        
        # Find all bookmark entries
        bookmarks = []
        current_category = None

        def process_folder(folder, category=None):
            nonlocal bookmarks
            # Get folder name if it exists
            folder_name = folder.find('h3')
            if folder_name:
                category = folder_name.get_text()
            
            # Process links in this folder
            links = folder.find_all('a')
            for link in links:
                bookmark = {
                    'id': str(len(config['links']) + len(bookmarks) + 1),
                    'title': link.get_text(),
                    'url': link.get('href'),
                    'description': link.get('description', ''),
                    'category': category,
                    'icon': 'bookmark'  # Default icon
                }
                bookmarks.append(bookmark)

            # Process subfolders
            subfolders = folder.find_all('dl')
            for subfolder in subfolders:
                process_folder(subfolder, category)

        # Start processing from root folders
        root_folders = soup.find_all('dl')
        for folder in root_folders:
            process_folder(folder)

        # Add all bookmarks to config
        config['links'].extend(bookmarks)
        
        # Save updated config
        save_config(config)
        
        flash(f'Successfully imported {len(bookmarks)} bookmarks!', 'success')

    except Exception as e:
        flash(f'Error processing bookmarks: {str(e)}', 'error')
        return redirect(url_for('main.upload_config'))

    return redirect(url_for('main.dashboard'))

@main_bp.route('/download_config')
@login_required
@verify_cognito_user_exists
def download_config():
    template_config = {
        'title': 'My Dashboard',
        'theme': {
            'primary_color': 'blue',
            'layout': 'grid',
            'container_spacing': 'less'
        },
        'categories': [
            'Work',
            'Personal',
            'Development',
            'Social Media'
        ],
        'links': [
            {
                'id': 'example-1',
                'title': 'Example Work Link',
                'url': 'https://example.com/work',
                'description': 'This is an example work-related link',
                'category': 'Work'
            },
            {
                'id': 'example-2',
                'title': 'Example Personal Link',
                'url': 'https://example.com/personal',
                'description': 'This is an example personal link',
                'category': 'Personal'
            }
        ]
    }
    
    json_str = json.dumps(template_config, indent=2)
    buffer = BytesIO(json_str.encode('utf-8'))
    
    return send_file(
        buffer,
        mimetype='application/json',
        as_attachment=True,
        download_name='dashboard_template.json'
    )

@main_bp.route('/edit/<link_id>', methods=['GET', 'POST'])
@login_required
@verify_cognito_user_exists
def edit_link(link_id):
    config = load_config()
    link = next((l for l in config['links'] if l['id'] == link_id), None)
    if not link:
        flash("Link not found")
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        url = request.form.get('url')
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        link['title'] = request.form.get('title')
        link['url'] = url
        link['description'] = request.form.get('description', '')
        link['category'] = request.form.get('category', '')
        link['icon'] = request.form.get('icon', '')
        save_config(config)
        return redirect(url_for('main.dashboard'))
    return render_template('edit_link.html', config=load_config(), link=link)

@main_bp.route('/delete/<link_id>')
@login_required
@verify_cognito_user_exists
def delete_link(link_id):
    config = load_config()
    config['links'] = [l for l in config['links'] if l['id'] != link_id]
    save_config(config)
    return redirect(url_for('main.dashboard'))

@main_bp.route('/update_order', methods=['POST'])
@login_required
@verify_cognito_user_exists
def update_order():
    try:
        data = request.get_json()
        category = data.get('category')
        new_order = data.get('order', [])
        
        config = load_config()
        
        if category == "open":
            # For open view, maintain the order of all links
            ordered_links = []
            for link_id in new_order:
                link = next((l for l in config['links'] if l['id'] == link_id), None)
                if link:
                    ordered_links.append(link)
            
            # Add any links that weren't in the order (shouldn't happen, but just in case)
            for link in config['links']:
                if link not in ordered_links:
                    ordered_links.append(link)
            
            config['links'] = ordered_links
        else:
            # For categorized view, maintain the order within each category
            for link in config['links']:
                if link['category'] == category:
                    link['order'] = new_order.index(link['id'])
        
        save_config(config)
        return jsonify({"status": "ok"})
    except Exception as e:
        print(f"Error updating order: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@main_bp.route('/update_settings', methods=['POST'])
@login_required
@verify_cognito_user_exists
def update_settings():
    config = load_config()
    container_spacing = request.form.get('container_spacing', 'less')
    if 'theme' not in config:
        config['theme'] = {}
    config['theme']['container_spacing'] = container_spacing
    save_config(config)
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'success'})
    
    flash('Settings updated!')
    return redirect(url_for('main.dashboard'))
