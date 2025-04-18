"""
Tor exit node detection
"""
import logging
import time
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

class TorDetector:
    def __init__(self):
        """Initialize Tor exit node detector"""
        self.exit_nodes = set()
        self.last_update = 0
        self.update_interval = 86400  # 24 hours in seconds
        
        # Update the exit node list on initialization
        self._update_exit_nodes()
    
    def _update_exit_nodes(self):
        """Update the list of Tor exit nodes"""
        # Check if we need to update
        current_time = time.time()
        if current_time - self.last_update < self.update_interval and self.exit_nodes:
            return
        
        try:
            # Fetch the current list of Tor exit nodes
            response = requests.get('https://check.torproject.org/exit-addresses', timeout=10)
            response.raise_for_status()
            
            # Parse the response to extract IP addresses
            exit_nodes = set()
            for line in response.text.splitlines():
                if line.startswith('ExitAddress '):
                    parts = line.split()
                    if len(parts) >= 2:
                        exit_nodes.add(parts[1])
            
            # Update our set of exit nodes
            self.exit_nodes = exit_nodes
            self.last_update = current_time
            
            logger.info(f"Updated Tor exit node list, found {len(self.exit_nodes)} nodes")
            
        except RequestException as e:
            logger.error(f"Error updating Tor exit node list: {e}")
    
    def is_tor_exit_node(self, ip):
        """
        Check if an IP is a known Tor exit node
        
        Args:
            ip: IP address to check
            
        Returns:
            Boolean indicating if the IP is a Tor exit node
        """
        # Update the exit node list if needed
        self._update_exit_nodes()
        
        # Check if the IP is in our set of exit nodes
        return ip in self.exit_nodes