from flask import Flask
from dashboard.routes import create_routes

def create_app(config):
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
    app.config['NIDS_CONFIG'] = config
    
    # Register routes
    create_routes(app, config)
    
    return app