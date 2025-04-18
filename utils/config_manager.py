"""
Configuration management for PhishFence
"""
import os
import json
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_path=None):
        # Default configuration
        self.config = {
            'version': '1.0.0',
            'whitelist': [],
            'blacklist': [],
            'trusted_domains': [
                'google.com',
                'microsoft.com',
                'apple.com',
                'amazon.com',
                'facebook.com',
                'github.com',
                'paypal.com',
                'chase.com',
                'wellsfargo.com',
                'bankofamerica.com'
            ],
            'detection_thresholds': {
                'domain_similarity': 0.8,
                'link_mismatch': 0.5,
                'ml_model': 0.7
            },
            'virustotal_api_key': '',
            'model_path': '',
            'stats': {
                'start_time': time.time(),
                'total_requests': 0,
                'blocked_requests': 0,
                'phishing_detected': 0
            }
        }
        
        # Set config path
        if config_path:
            self.config_path = Path(config_path)
        else:
            home_dir = Path.home()
            phishfence_dir = home_dir / '.phishfence'
            self.config_path = phishfence_dir / 'config.json'
            
            # Create directory if it doesn't exist
            if not phishfence_dir.exists():
                phishfence_dir.mkdir(parents=True)
        
        # Load configuration
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # Update config with loaded values
                    self._merge_dict(self.config, loaded_config)
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
        else:
            # Save default configuration
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Saved configuration to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, key, default=None):
        """
        Get a configuration value
        
        Args:
            key: Configuration key (supports dot notation for nested values)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        try:
            # Handle nested keys with dot notation
            if '.' in key:
                parts = key.split('.')
                value = self.config
                for part in parts:
                    value = value.get(part, {})
                
                # If we've traversed all parts but ended up with an empty dict,
                # it means the key doesn't exist
                if value == {} and len(parts) > 0:
                    return default
                
                return value
            else:
                return self.config.get(key, default)
        except Exception:
            return default
    
    def set(self, key, value):
        """
        Set a configuration value
        
        Args:
            key: Configuration key (supports dot notation for nested values)
            value: Value to set
            
        Returns:
            Boolean indicating success
        """
        try:
            # Handle nested keys with dot notation
            if '.' in key:
                parts = key.split('.')
                config = self.config
                
                # Navigate to the nested dict
                for part in parts[:-1]:
                    if part not in config:
                        config[part] = {}
                    config = config[part]
                
                # Set the value
                config[parts[-1]] = value
            else:
                self.config[key] = value
            
            return True
        except Exception as e:
            logger.error(f"Error setting configuration value: {e}")
            return False
    
    def increment_stat(self, stat_name, increment=1):
        """
        Increment a statistics counter
        
        Args:
            stat_name: Name of the statistic to increment
            increment: Amount to increment by
            
        Returns:
            New value of the statistic
        """
        key = f"stats.{stat_name}"
        current = self.get(key, 0)
        new_value = current + increment
        self.set(key, new_value)
        return new_value
    
    def _merge_dict(self, base, update):
        """Recursively merge update dict into base dict"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dict(base[key], value)
            else:
                base[key] = value