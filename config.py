"""
Configuration settings for PhishFence
"""
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Application settings
APP_NAME = "PhishFence"
APP_VERSION = "1.0.0"

# Data directory
HOME_DIR = os.path.expanduser('~')
DATA_DIR = os.path.join(HOME_DIR, '.phishfence')

# Certificate settings
CERT_DIR = os.path.join(DATA_DIR, 'certificates')
CA_CERT_PATH = os.path.join(CERT_DIR, 'ca.crt')
CA_KEY_PATH = os.path.join(CERT_DIR, 'ca.key')

# Default ports
DEFAULT_PROXY_PORT = 8080
DEFAULT_DASHBOARD_PORT = 5000

# Detection thresholds
THRESHOLDS = {
    'domain_similarity': 0.8,    # Domain similarity threshold (0-1)
    'link_mismatch': 0.7,        # Link text/URL mismatch confidence threshold (0-1)
    'ml_model': 0.7              # ML model prediction threshold (0-1)
}

# Minimum length for whitelist/blacklist entries
MIN_DOMAIN_LENGTH = 3