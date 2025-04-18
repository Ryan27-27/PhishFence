"""
VirusTotal API integration for checking URLs and content
"""
import hashlib
import logging
import time
import json
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self, api_key=None):
        """
        Initialize the VirusTotal client
        
        Args:
            api_key: VirusTotal API key
        """
        from utils.config_manager import ConfigManager
        config = ConfigManager()
        
        # Use provided API key or get from config
        self.api_key = api_key or config.get('virustotal_api_key')
        
        # Cache to avoid repeated API calls
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour in seconds
        
        # API endpoints
        self.base_url = 'https://www.virustotal.com/api/v3'
    
    def check_url(self, url):
        """
        Check a URL against VirusTotal
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with check results
        """
        result = {
            'threat_detected': False,
            'reputation_score': 0,
            'detection_ratio': '0/0',
            'categories': [],
            'message': None
        }
        
        # Check if we have a valid API key
        if not self.api_key:
            result['message'] = "VirusTotal API key not configured"
            return result
        
        # Check if URL is in cache
        cache_key = f"url:{url}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # First, check if URL has already been analyzed
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {'x-apikey': self.api_key}
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=headers)
            
            if response.status_code == 200:
                # URL has been analyzed before
                data = response.json()
                return self._process_url_report(data, cache_key)
            elif response.status_code == 404:
                # URL hasn't been analyzed before, submit it
                data = {'url': url}
                response = requests.post(f"{self.base_url}/urls", headers=headers, data=data)
                
                if response.status_code == 200:
                    # URL submitted successfully, get the analysis ID
                    data = response.json()
                    analysis_id = data.get('data', {}).get('id')
                    
                    if analysis_id:
                        # Wait for analysis to complete (poll with exponential backoff)
                        for i in range(5):  # Try up to 5 times
                            time.sleep(2 ** i)  # 1, 2, 4, 8, 16 seconds
                            
                            response = requests.get(f"{self.base_url}/analyses/{analysis_id}", headers=headers)
                            if response.status_code == 200:
                                data = response.json()
                                status = data.get('data', {}).get('attributes', {}).get('status')
                                
                                if status == 'completed':
                                    return self._process_analysis_report(data, cache_key)
                        
                        # Analysis didn't complete in time
                        result['message'] = "Analysis in progress, try again later"
                    else:
                        result['message'] = "Failed to get analysis ID"
                else:
                    result['message'] = f"Error submitting URL: HTTP {response.status_code}"
            else:
                result['message'] = f"Error checking URL: HTTP {response.status_code}"
        
        except RequestException as e:
            logger.error(f"Error in VirusTotal API request: {e}")
            result['message'] = f"Connection error: {str(e)}"
        
        return result
    
    def check_content(self, content):
        """
        Check content against VirusTotal
        
        Args:
            content: Binary content to check
            
        Returns:
            Dictionary with check results
        """
        result = {
            'threat_detected': False,
            'reputation_score': 0,
            'detection_ratio': '0/0',
            'categories': [],
            'message': None
        }
        
        # Check if we have a valid API key
        if not self.api_key:
            result['message'] = "VirusTotal API key not configured"
            return result
        
        # Check if content hash is in cache
        content_hash = hashlib.sha256(content).hexdigest()
        cache_key = f"file:{content_hash}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # First, check if file has already been analyzed
            headers = {'x-apikey': self.api_key}
            response = requests.get(f"{self.base_url}/files/{content_hash}", headers=headers)
            
            if response.status_code == 200:
                # File has been analyzed before
                data = response.json()
                return self._process_file_report(data, cache_key)
            elif response.status_code == 404:
                # File hasn't been analyzed before
                # For file uploads, use the specific endpoint with multipart form data
                # This is just a placeholder - actual implementation would depend on the API
                result['message'] = "File upload not implemented in this version"
            else:
                result['message'] = f"Error checking file: HTTP {response.status_code}"
        
        except RequestException as e:
            logger.error(f"Error in VirusTotal API request: {e}")
            result['message'] = f"Connection error: {str(e)}"
        
        return result
    
    def _process_url_report(self, data, cache_key):
        """Process URL report data from VirusTotal"""
        result = {
            'threat_detected': False,
            'reputation_score': 0,
            'detection_ratio': '0/0',
            'categories': [],
            'message': None
        }
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get the last analysis results
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            total = sum(last_analysis_stats.values())
            
            # Calculate reputation score (0-100)
            if total > 0:
                result['reputation_score'] = 100 - int((malicious + suspicious) * 100 / total)
            
            # Set detection ratio
            result['detection_ratio'] = f"{malicious + suspicious}/{total}"
            
            # Set categories
            result['categories'] = list(attributes.get('categories', {}).values())
            
            # Determine if threat is detected
            if malicious > 0 or suspicious > 0:
                result['threat_detected'] = True
            
            # Cache the result
            self._add_to_cache(cache_key, result)
        
        except Exception as e:
            logger.error(f"Error processing VirusTotal URL report: {e}")
            result['message'] = "Error processing report"
        
        return result
    
    def _process_analysis_report(self, data, cache_key):
        """Process analysis report data from VirusTotal"""
        result = {
            'threat_detected': False,
            'reputation_score': 0,
            'detection_ratio': '0/0',
            'categories': [],
            'message': None
        }
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get the analysis stats
            stats = attributes.get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            # Calculate reputation score (0-100)
            if total > 0:
                result['reputation_score'] = 100 - int((malicious + suspicious) * 100 / total)
            
            # Set detection ratio
            result['detection_ratio'] = f"{malicious + suspicious}/{total}"
            
            # Categories would be extracted from the results, simplified here
            result['categories'] = []
            
            # Determine if threat is detected
            if malicious > 0 or suspicious > 0:
                result['threat_detected'] = True
            
            # Cache the result
            self._add_to_cache(cache_key, result)
        
        except Exception as e:
            logger.error(f"Error processing VirusTotal analysis report: {e}")
            result['message'] = "Error processing report"
        
        return result
    
    def _process_file_report(self, data, cache_key):
        """Process file report data from VirusTotal"""
        result = {
            'threat_detected': False,
            'reputation_score': 0,
            'detection_ratio': '0/0',
            'categories': [],
            'message': None
        }
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get the last analysis results
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            total = sum(last_analysis_stats.values())
            
            # Calculate reputation score (0-100)
            if total > 0:
                result['reputation_score'] = 100 - int((malicious + suspicious) * 100 / total)
            
            # Set detection ratio
            result['detection_ratio'] = f"{malicious + suspicious}/{total}"
            
            # Set categories (might be file type or tags)
            result['categories'] = attributes.get('type_tags', [])
            
            # Determine if threat is detected
            if malicious > 0 or suspicious > 0:
                result['threat_detected'] = True
            
            # Cache the result
            self._add_to_cache(cache_key, result)
        
        except Exception as e:
            logger.error(f"Error processing VirusTotal file report: {e}")
            result['message'] = "Error processing report"
        
        return result
    
    def _add_to_cache(self, key, value):
        """Add result to cache with timestamp"""
        self.cache[key] = {
            'timestamp': time.time(),
            'data': value
        }
    
    def _get_from_cache(self, key):
        """Get result from cache if not expired"""
        cached = self.cache.get(key)
        if cached and time.time() - cached['timestamp'] < self.cache_ttl:
            return cached['data']
        return None