"""
Flask application for the PhishFence dashboard
"""
import os
import logging
from flask import Flask
from flask_socketio import SocketIO

# Initialize Flask-SocketIO
socketio = SocketIO()

def create_app():
    """Create and configure the Flask application"""
    # Initialize Flask app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Initialize Socket.IO
    socketio.init_app(app, cors_allowed_origins="*")
    
    # Load configuration
    from utils.config_manager import ConfigManager
    config_manager = ConfigManager()
    
    # Register routes
    from dashboard.routes import register_routes
    register_routes(app, socketio, config_manager)
    
    return app

def run_dashboard(host='0.0.0.0', port=5000, debug=True):
    """Run the dashboard application"""
    app = create_app()
    socketio.run(app, host=host, port=port, debug=debug)