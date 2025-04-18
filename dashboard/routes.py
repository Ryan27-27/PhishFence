"""
Routes for the PhishFence dashboard
"""
import os
import time
import json
import logging
import threading
from flask import render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from utils.logger import LogMonitor

logger = logging.getLogger(__name__)

def register_routes(app, socketio, config_manager):
    """Register all routes for the dashboard"""
    
    # Set up log monitor for real-time updates
    log_monitor = LogMonitor()
    
    @app.route('/')
    def index():
        """Dashboard home page"""
        stats = {
            'total_requests': config_manager.get('stats.total_requests', 0),
            'blocked_requests': config_manager.get('stats.blocked_requests', 0),
            'phishing_detected': config_manager.get('stats.phishing_detected', 0),
            'start_time': config_manager.get('stats.start_time', time.time())
        }
        
        return render_template('index.html', stats=stats)
    
    @app.route('/logs')
    def logs():
        """Log viewer page"""
        return render_template('logs.html')
    
    @app.route('/settings')
    def settings():
        """Settings page"""
        whitelist = config_manager.get('whitelist', [])
        blacklist = config_manager.get('blacklist', [])
        trusted_domains = config_manager.get('trusted_domains', [])
        virustotal_api_key = config_manager.get('virustotal_api_key', '')
        
        return render_template('settings.html', 
                              whitelist=whitelist,
                              blacklist=blacklist,
                              trusted_domains=trusted_domains,
                              virustotal_api_key=virustotal_api_key)
    
    @app.route('/api/logs/recent')
    def api_recent_logs():
        """API endpoint to get recent logs"""
        count = request.args.get('count', 100, type=int)
        logs = log_monitor.get_recent_logs(count)
        return jsonify(logs)
    
    @app.route('/api/stats')
    def api_stats():
        """API endpoint to get current stats"""
        stats = {
            'total_requests': config_manager.get('stats.total_requests', 0),
            'blocked_requests': config_manager.get('stats.blocked_requests', 0),
            'phishing_detected': config_manager.get('stats.phishing_detected', 0),
            'uptime_seconds': int(time.time() - config_manager.get('stats.start_time', time.time()))
        }
        return jsonify(stats)
    
    @socketio.on('connect')
    def handle_connect():
        logger.debug("Client connected to Socket.IO")
        
    # Start thread for emitting log updates
    def emit_log_updates():
        """Emit log updates to connected clients"""
        while True:
            new_logs = log_monitor.get_new_logs()
            if new_logs:
                socketio.emit('log_update', new_logs)
            socketio.sleep(1)
    
    socketio.start_background_task(emit_log_updates)