"""
Logging utility for PhishFence
"""
import logging
import threading
import time
from collections import deque

class LogMonitor:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LogMonitor, cls).__new__(cls)
                cls._instance._buffer = deque(maxlen=1000)
                cls._instance._last_read_index = 0
                cls._instance._setup_handler()
            return cls._instance
    
    def _setup_handler(self):
        """Set up a handler to capture logs to the buffer"""
        class BufferHandler(logging.Handler):
            def __init__(self, buffer):
                super().__init__()
                self.buffer = buffer
            
            def emit(self, record):
                # Convert record to dict for JSON serialization
                log_entry = {
                    'created': record.created,
                    'levelname': record.levelname,
                    'name': record.name,
                    'message': self.format(record)
                }
                self.buffer.append(log_entry)
        
        # Create and configure handler
        handler = BufferHandler(self._buffer)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        
        # Add handler to root logger
        root = logging.getLogger()
        root.addHandler(handler)
    
    def get_recent_logs(self, count=100):
        """Get the most recent log entries"""
        logs = list(self._buffer)[-count:]
        self._last_read_index = len(self._buffer)
        return logs
    
    def get_new_logs(self):
        """Get new log entries since last read"""
        current_size = len(self._buffer)
        if self._last_read_index < current_size:
            logs = list(self._buffer)[self._last_read_index:]
            self._last_read_index = current_size
            return logs
        return []

def get_logger(name):
    """Get a logger with the given name"""
    logger = logging.getLogger(name)
    
    # Configure handler if not already configured
    if not logger.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger