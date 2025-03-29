import flask
import werkzeug
import gunicorn
from app import app

print("Running with:")
print(f"Flask version: {flask.__version__}")
print(f"Werkzeug version: {werkzeug.__version__}")
print(f"Gunicorn version: {gunicorn.__version__}")

if __name__ == '__main__':
    app.config['DEBUG'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(host='localhost', port=8000, debug=True, use_reloader=True)
