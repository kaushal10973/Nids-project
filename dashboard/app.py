from flask import Flask
from dashboard.routes import create_routes

def create_app(config):
    """Application factory."""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    app.config['SECRET_KEY'] = 'nids-secret-key-change-me'
    app.config['NIDS_CONFIG'] = config
    
    create_routes(app, config)
    
    return app