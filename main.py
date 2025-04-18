"""
PhishFence - Main Flask application entry point
"""
from dashboard.app import create_app

# Create the Flask application
app = create_app()

if __name__ == "__main__":
    from dashboard.app import run_dashboard
    run_dashboard(host='0.0.0.0', port=5000, debug=True)