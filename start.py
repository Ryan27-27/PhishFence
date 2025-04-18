"""
PhishFence - Phishing Detection Proxy
Main entry point to start both proxy and dashboard
"""
import os
import sys
import time
import signal
import logging
import argparse
import threading
from utils.config_manager import ConfigManager
from utils.logger import get_logger

# Set up logger
logger = get_logger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='PhishFence - Phishing Detection Proxy')
    parser.add_argument('--proxy-port', type=int, default=8080, help='Port for the proxy server')
    parser.add_argument('--dashboard-port', type=int, default=5000, help='Port for the dashboard')
    parser.add_argument('--generate-certificate', action='store_true', help='Generate CA certificate')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    return parser.parse_args()

def setup_environment():
    """Set up the environment for PhishFence"""
    # Create data directory
    home_dir = os.path.expanduser('~')
    phishfence_dir = os.path.join(home_dir, '.phishfence')
    if not os.path.exists(phishfence_dir):
        os.makedirs(phishfence_dir)
        logger.info(f"Created PhishFence directory at {phishfence_dir}")
    
    # Create subdirectories
    for subdir in ['certificates', 'logs', 'models']:
        path = os.path.join(phishfence_dir, subdir)
        if not os.path.exists(path):
            os.makedirs(path)
            logger.info(f"Created {subdir} directory")

def start_proxy(port, config_manager):
    """Start the proxy server"""
    from proxy_engine.proxy_server import ProxyServer
    from proxy_engine.request_handler import RequestHandler
    
    # Create and start proxy server
    request_handler = RequestHandler(config_manager)
    proxy_server = ProxyServer(config_manager, request_handler)
    proxy_thread = proxy_server.start_in_thread(port=port)
    
    return proxy_thread

def start_dashboard(port, debug=False):
    """Start the dashboard server"""
    from dashboard.app import run_dashboard
    
    # Run in a thread for non-blocking operation
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        kwargs={
            'host': '0.0.0.0',
            'port': port,
            'debug': debug
        }
    )
    dashboard_thread.daemon = True
    dashboard_thread.start()
    
    return dashboard_thread

def main():
    """Main entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging level
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Set up environment
    setup_environment()
    
    # Load configuration
    config_manager = ConfigManager()
    
    # Initialize stats
    config_manager.set('stats.start_time', time.time())
    config_manager.set('stats.total_requests', 0)
    config_manager.set('stats.blocked_requests', 0)
    config_manager.set('stats.phishing_detected', 0)
    
    # Set up signal handling for clean shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down PhishFence...")
        config_manager.save_config()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Generate CA certificate if requested
    if args.generate_certificate:
        from proxy_engine.certificate_manager import CertificateManager
        cert_manager = CertificateManager()
        cert_path = cert_manager._create_ca_certificate()
        logger.info(f"CA certificate generated at {cert_path}")
        logger.info("Please install this certificate in your browser to intercept HTTPS traffic")
    
    # Start proxy server
    logger.info(f"Starting proxy server on port {args.proxy_port}...")
    proxy_thread = start_proxy(args.proxy_port, config_manager)
    
    # Start dashboard
    logger.info(f"Starting dashboard on port {args.dashboard_port}...")
    dashboard_thread = start_dashboard(args.dashboard_port, args.debug)
    
    logger.info("PhishFence is running. Press Ctrl+C to stop.")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down PhishFence...")
        config_manager.save_config()

if __name__ == "__main__":
    main()