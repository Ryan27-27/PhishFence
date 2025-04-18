"""
Core proxy server implementation using Flask
"""
import threading
import logging
from urllib.parse import urlparse, urljoin
import requests
from flask import Flask, request, Response, render_template_string
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

class ProxyServer:
    def __init__(self, config_manager=None, request_handler=None):
        """
        Initialize the proxy server
        
        Args:
            config_manager: ConfigManager instance
            request_handler: RequestHandler instance for analyzing requests
        """
        self.app = Flask(__name__)
        self.config_manager = config_manager
        self.request_handler = request_handler
        
        # Set up routes
        self.setup_routes()
    
    def setup_routes(self):
        """Set up Flask routes for the proxy server"""
        
        @self.app.route('/', defaults={'path': ''})
        @self.app.route('/<path:path>')
        def proxy(path):
            """Handle all HTTP/HTTPS requests"""
            # Increment request counter
            if self.config_manager:
                self.config_manager.increment_stat('total_requests')
            
            # Get the target URL
            target_url = request.args.get('url')
            
            if not target_url:
                # If no URL provided, use the path and query string
                scheme = request.headers.get('X-Forwarded-Proto', 'http')
                host = request.headers.get('X-Forwarded-Host', request.headers.get('Host', ''))
                
                # If this is a direct request to the proxy, show a proxy form
                if not path and not request.query_string:
                    return self._show_proxy_form()
                
                # Build the target URL
                if path:
                    target_url = f"{scheme}://{path}"
                    if request.query_string:
                        target_url += f"?{request.query_string.decode('utf-8')}"
                else:
                    target_url = f"{scheme}://{host}"
            
            # Parse the URL
            parsed_url = urlparse(target_url)
            
            # Ensure the URL has a scheme
            if not parsed_url.scheme:
                target_url = f"http://{target_url}"
                parsed_url = urlparse(target_url)
            
            # Log the request
            logger.info(f"Proxying request to {target_url}")
            
            # Analyze the request if a request handler is available
            if self.request_handler:
                action, message = self.request_handler.analyze_request(request, target_url)
                if action == 'block':
                    logger.warning(f"Blocked request to {target_url}: {message}")
                    if self.config_manager:
                        self.config_manager.increment_stat('blocked_requests')
                    return self._show_block_page(target_url, message)
            
            try:
                # Forward the request to the target server
                # Prepare headers
                headers = {key: value for key, value in request.headers if key.lower() not in ('host', 'connection')}
                
                # Prepare request kwargs
                kwargs = {
                    'method': request.method,
                    'url': target_url,
                    'headers': headers,
                    'data': request.get_data(),
                    'cookies': request.cookies,
                    'allow_redirects': False,
                    'timeout': 10
                }
                
                # Add query parameters if present
                if request.query_string and '?' not in target_url:
                    kwargs['params'] = request.args
                
                # Send the request
                response = requests.request(**kwargs)
                
                # Process response headers
                response_headers = {key: value for key, value in response.headers.items()
                                  if key.lower() not in ('connection', 'transfer-encoding')}
                
                # Fix any relative redirects
                if response.is_redirect and 'location' in response_headers:
                    redirect_url = response_headers['location']
                    if not redirect_url.startswith(('http://', 'https://')):
                        # Make relative redirect URL absolute
                        redirect_url = urljoin(target_url, redirect_url)
                        response_headers['location'] = redirect_url
                
                # Analyze the response if a request handler is available
                if self.request_handler:
                    action, message = self.request_handler.analyze_response(response, target_url)
                    if action == 'block':
                        logger.warning(f"Blocked response from {target_url}: {message}")
                        if self.config_manager:
                            self.config_manager.increment_stat('blocked_requests')
                        return self._show_block_page(target_url, message)
                
                # Create Flask response
                proxy_response = Response(
                    response.content,
                    status=response.status_code,
                    headers=response_headers,
                    content_type=response.headers.get('content-type')
                )
                
                return proxy_response
                
            except RequestException as e:
                logger.error(f"Error proxying request to {target_url}: {e}")
                return self._show_error_page(target_url, str(e))
    
    def _show_proxy_form(self):
        """Show a form for entering a URL to proxy"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishFence Proxy</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                }
                .form-container {
                    background-color: white;
                    border-radius: 5px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                input[type="text"] {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    background-color: #4CAF50;
                    color: white;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                button:hover {
                    background-color: #45a049;
                }
                .info {
                    margin-top: 20px;
                    font-size: 0.9em;
                    color: #666;
                }
            </style>
        </head>
        <body>
            <h1>PhishFence Proxy</h1>
            <div class="form-container">
                <form action="/" method="get">
                    <label for="url">Enter URL to browse:</label>
                    <input type="text" id="url" name="url" placeholder="https://example.com" required>
                    <button type="submit">Browse</button>
                </form>
            </div>
            <div class="info">
                <p>This proxy will analyze the website for potential phishing indicators.</p>
                <p>For configuration, visit the <a href="http://localhost:5000">dashboard</a>.</p>
            </div>
        </body>
        </html>
        """
        return render_template_string(html)
    
    def _show_block_page(self, url, reason):
        """Show a page indicating the request was blocked"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishFence - Access Blocked</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff0f0;
                }
                h1 {
                    color: #d32f2f;
                }
                .alert-container {
                    background-color: white;
                    border-left: 5px solid #d32f2f;
                    border-radius: 5px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .url {
                    word-break: break-all;
                    padding: 10px;
                    background-color: #f8f8f8;
                    border-radius: 4px;
                    margin: 15px 0;
                    font-family: monospace;
                }
                .reason {
                    margin: 15px 0;
                    padding: 10px;
                    background-color: #f8d7da;
                    border-radius: 4px;
                    color: #721c24;
                }
                .back-button {
                    background-color: #f44336;
                    color: white;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 10px;
                }
                .back-button:hover {
                    background-color: #d32f2f;
                }
            </style>
        </head>
        <body>
            <div class="alert-container">
                <h1>⚠️ Potential Phishing Site Blocked</h1>
                <p>PhishFence has blocked access to this website because it may be attempting to steal your information.</p>
                
                <div class="url">
                    <strong>URL:</strong> {{ url }}
                </div>
                
                <div class="reason">
                    <strong>Reason:</strong> {{ reason }}
                </div>
                
                <p>If you believe this is a mistake, you can add this domain to your whitelist in the PhishFence dashboard.</p>
                
                <a href="/" class="back-button">Go Back</a>
            </div>
        </body>
        </html>
        """
        return render_template_string(html, url=url, reason=reason), 403
    
    def _show_error_page(self, url, error):
        """Show a page indicating an error occurred"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishFence - Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                }
                .error-container {
                    background-color: white;
                    border-left: 5px solid #f9a825;
                    border-radius: 5px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .url {
                    word-break: break-all;
                    padding: 10px;
                    background-color: #f8f8f8;
                    border-radius: 4px;
                    margin: 15px 0;
                    font-family: monospace;
                }
                .error {
                    margin: 15px 0;
                    padding: 10px;
                    background-color: #fff3cd;
                    border-radius: 4px;
                    color: #856404;
                }
                .back-button {
                    background-color: #f9a825;
                    color: white;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 10px;
                }
                .back-button:hover {
                    background-color: #e69c00;
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>⚠️ Error Loading Website</h1>
                <p>PhishFence encountered an error while trying to access this website.</p>
                
                <div class="url">
                    <strong>URL:</strong> {{ url }}
                </div>
                
                <div class="error">
                    <strong>Error:</strong> {{ error }}
                </div>
                
                <p>This could be due to the website being unavailable, or an issue with your internet connection.</p>
                
                <a href="/" class="back-button">Go Back</a>
            </div>
        </body>
        </html>
        """
        return render_template_string(html, url=url, error=error), 500
    
    def run(self, host='0.0.0.0', port=8080):
        """Run the proxy server"""
        self.app.run(host=host, port=port, threaded=True, debug=False)
    
    def start_in_thread(self, host='0.0.0.0', port=8080):
        """Start the proxy server in a separate thread"""
        thread = threading.Thread(
            target=self.run,
            kwargs={'host': host, 'port': port}
        )
        thread.daemon = True
        thread.start()
        logger.info(f"Proxy server started on {host}:{port}")
        return thread