from app import app

if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(host='localhost', port=8000, debug=True, use_reloader=True)
