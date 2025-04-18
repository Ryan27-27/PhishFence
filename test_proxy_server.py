#!/usr/bin/env python3
"""
Test script for PhishFence proxy server
This script sends HTTP requests through the proxy to verify it's working properly
"""
import sys
import time
import logging
import argparse
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_proxy(url, proxy_host="127.0.0.1", proxy_port=8080):
    """
    Test accessing a URL through the PhishFence proxy
    
    Args:
        url: URL to access
        proxy_host: Proxy server host
        proxy_port: Proxy server port
    """
    # Set up proxy configuration
    proxies = {
        "http": f"http://{proxy_host}:{proxy_port}",
        "https": f"http://{proxy_host}:{proxy_port}"
    }
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    logger.info(f"Testing access to {url} through proxy at {proxy_host}:{proxy_port}")
    
    try:
        # Make the request through the proxy
        start_time = time.time()
        response = requests.get(url, proxies=proxies, timeout=30, verify=False)
        elapsed_time = time.time() - start_time
        
        # Log the response
        status_color = "\033[92m" if response.status_code < 400 else "\033[91m"  # Green or red
        logger.info(f"Status: {status_color}{response.status_code} {response.reason}\033[0m")
        logger.info(f"Time: {elapsed_time:.2f} seconds")
        logger.info(f"Content type: {response.headers.get('content-type', 'Unknown')}")
        logger.info(f"Content length: {len(response.content)} bytes")
        
        # Check if the response is from the proxy (blocked page)
        if "PhishFence" in response.text and ("blocked" in response.text.lower() or "warning" in response.text.lower()):
            logger.warning("⚠️ Request was BLOCKED by the proxy")
            
            # Try to extract the reason
            import re
            reason_match = re.search(r'<div class="reason">\s*<strong>Reason:</strong>\s*(.*?)\s*</div>', response.text)
            if reason_match:
                logger.warning(f"Reason: {reason_match.group(1)}")
            
            return False
        else:
            logger.info("✅ Request was ALLOWED by the proxy")
            return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error accessing URL through proxy: {e}")
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Test the PhishFence proxy server')
    parser.add_argument('url', help='URL to access through the proxy')
    parser.add_argument('--host', default='127.0.0.1', help='Proxy server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8080, help='Proxy server port (default: 8080)')
    
    args = parser.parse_args()
    
    # Suppress InsecureRequestWarning for simplicity in tests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        test_proxy(args.url, args.host, args.port)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()