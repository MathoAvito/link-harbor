from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, session, jsonify
from flask_login import login_required
import json
import uuid
from io import BytesIO
from app.config_utils import (allowed_file, load_config, save_config, validate_config, parse_chrome_bookmarks, merge_bookmarks_with_config)

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def dashboard():
    config = load_config()
    view_mode = request.args.get('view', session.get('view_mode', 'categories'))
    session['view_mode'] = view_mode
    template = 'dashboard_open.html' if view_mode == 'open' else 'dashboard.html'
    return render_template(template, config=config, view_mode=view_mode)

@main_bp.route('/upload_config', methods=['GET', 'POST'])
@login_required
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

@main_bp.route('/upload_bookmarks', methods=['GET', 'POST'])
@login_required
def upload_bookmarks():
    if request.method == 'POST':
        print("POST request received") # Debug print
        if 'bookmark_file' not in request.files:
            print("No bookmark_file in request") # Debug print
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['bookmark_file']
        if file.filename == '':
            print("Empty filename") # Debug print
            flash('No file selected')
            return redirect(request.url)
        
        if file and file.filename.endswith('.html'):
            try:
                # Read the HTML content
                bookmark_content = file.read().decode('utf-8')
                print(f"File content length: {len(bookmark_content)}") # Debug print
                
                # Parse bookmarks
                new_bookmarks = parse_chrome_bookmarks(bookmark_content)
                print(f"Found {len(new_bookmarks)} bookmarks") # Debug print
                
                # Load current config
                config = load_config()
                
                # Merge bookmarks with existing config
                old_count = len(config['links'])
                config = merge_bookmarks_with_config(config, new_bookmarks)
                new_count = len(config['links'])
                print(f"Added {new_count - old_count} new bookmarks") # Debug print
                
                # Save updated config
                save_config(config)
                
                flash(f'Successfully imported {len(new_bookmarks)} bookmarks!')
                return redirect(url_for('main.dashboard'))
                
            except Exception as e:
                print(f"Error occurred: {str(e)}") # Debug print
                flash(f'Error processing bookmarks: {str(e)}')
                return redirect(request.url)
        else:
            print(f"Invalid file type: {file.filename}") # Debug print
            flash('Invalid file type. Please upload a Chrome bookmarks HTML file.')
        
        return redirect(request.url)
    
    return render_template('upload_bookmarks.html', config=load_config())

@main_bp.route('/download_config')
@login_required
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

@main_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_link():
    if request.method == 'POST':
        config = load_config()
        
        url = request.form.get('url')
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url

        new_link = {
            'id': str(uuid.uuid4()),
            'title': request.form.get('title'),
            'url': url,
            'description': request.form.get('description', ''),
            'category': request.form.get('category', ''),
            'icon': request.form.get('icon', '')
        }
        
        config['links'].append(new_link)
        save_config(config)
        return redirect(url_for('main.dashboard'))
    
    return render_template('add_link.html', config=load_config())

@main_bp.route('/edit/<link_id>', methods=['GET', 'POST'])
@login_required
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
def delete_link(link_id):
    config = load_config()
    config['links'] = [l for l in config['links'] if l['id'] != link_id]
    save_config(config)
    return redirect(url_for('main.dashboard'))

@main_bp.route('/update_order', methods=['POST'])
@login_required
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
def update_settings():
    config = load_config()
    container_spacing = request.form.get('container_spacing', 'less')
    if 'theme' not in config:
        config['theme'] = {}
    config['theme']['container_spacing'] = container_spacing
    save_config(config)
    flash('Settings updated!')
    return redirect(url_for('main.dashboard'))
