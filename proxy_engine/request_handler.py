"""
Request and response handler for the proxy
Performs analysis of web traffic for phishing detection
"""
import re
import logging
import urllib.parse
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

class RequestHandler:
    def __init__(self, config_manager):
        """
        Initialize the request handler
        
        Args:
            config_manager: ConfigManager instance
        """
        self.config_manager = config_manager
        self.ml_model = None
        self.domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    def analyze_request(self, request, url):
        """
        Analyze the request for potential phishing indicators
        
        Args:
            request: Flask request object
            url: Target URL
            
        Returns:
            Tuple of (action, message) where action is 'allow' or 'block'
        """
        # Parse URL
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return 'allow', ''
        
        # Check if domain is in whitelist
        whitelist = self.config_manager.get('whitelist', [])
        for pattern in whitelist:
            if self._match_domain(domain, pattern):
                logger.info(f"Request to {domain} allowed (whitelisted)")
                return 'allow', ''
        
        # Check if domain is in blacklist
        blacklist = self.config_manager.get('blacklist', [])
        for pattern in blacklist:
            if self._match_domain(domain, pattern):
                logger.warning(f"Request to {domain} blocked (blacklisted)")
                return 'block', f"Domain {domain} is blacklisted"
        
        # Basic URL analysis using URLAnalyzer
        from utils.url_analyzer import URLAnalyzer
        url_analyzer = URLAnalyzer()
        similarity_result = url_analyzer.check_domain_similarity(domain)
        
        if similarity_result['is_suspicious']:
            logger.warning(f"Request to {domain} blocked (similar to {similarity_result['similar_to']})")
            self.config_manager.increment_stat('phishing_detected')
            return 'block', f"Domain appears similar to {similarity_result['similar_to']}"
        
        # Allow the request to proceed
        return 'allow', ''
    
    def analyze_response(self, response, url):
        """
        Analyze the response for potential phishing indicators
        
        Args:
            response: Requests response object
            url: Target URL
            
        Returns:
            Tuple of (action, message) where action is 'allow' or 'block'
        """
        # Parse URL
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return 'allow', ''
        
        # Check if domain is in whitelist
        whitelist = self.config_manager.get('whitelist', [])
        for pattern in whitelist:
            if self._match_domain(domain, pattern):
                logger.info(f"Response from {domain} allowed (whitelisted)")
                return 'allow', ''
        
        # Check if domain is in blacklist (shouldn't reach here but check anyway)
        blacklist = self.config_manager.get('blacklist', [])
        for pattern in blacklist:
            if self._match_domain(domain, pattern):
                logger.warning(f"Response from {domain} blocked (blacklisted)")
                return 'block', f"Domain {domain} is blacklisted"
        
        # Check content type - only analyze text/html
        content_type = response.headers.get('content-type', '').lower()
        if not content_type.startswith('text/html'):
            return 'allow', ''
        
        try:
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for suspicious link mismatches
            from utils.link_comparator import LinkComparator
            link_comparator = LinkComparator()
            link_result = link_comparator.analyze_links(soup, url)
            
            if link_result['suspicious_links'] > 0 and link_result['confidence'] >= 0.7:
                logger.warning(f"Response from {domain} blocked (suspicious links detected)")
                self.config_manager.increment_stat('phishing_detected')
                return 'block', f"Suspicious links detected: visible text doesn't match the actual link URL"
            
            # Check for obfuscated URLs
            from utils.url_analyzer import URLAnalyzer
            url_analyzer = URLAnalyzer()
            obfuscation_result = url_analyzer.check_url_for_obfuscation(url)
            
            if obfuscation_result['is_obfuscated']:
                logger.warning(f"Response from {domain} blocked (URL obfuscation detected)")
                self.config_manager.increment_stat('phishing_detected')
                return 'block', f"URL obfuscation detected: {obfuscation_result['technique']}"
            
            # Machine learning-based detection
            features = self._extract_features(soup, url)
            
            if features:
                # Lazy-load the ML model to improve startup time
                if self.ml_model is None:
                    from ml_model.model_loader import ModelLoader
                    self.ml_model = ModelLoader()
                
                prediction = self.ml_model.predict(features)
                
                threshold = self.config_manager.get('detection_thresholds.ml_model', 0.7)
                if prediction['is_phishing'] and prediction['probability'] >= threshold:
                    logger.warning(f"Response from {domain} blocked (ML model detected phishing)")
                    self.config_manager.increment_stat('phishing_detected')
                    return 'block', f"Machine learning model identified this as a potential phishing site (confidence: {prediction['confidence']:.2f})"
            
            # Allow the response if no issues were detected
            return 'allow', ''
            
        except Exception as e:
            logger.error(f"Error analyzing response from {url}: {e}")
            return 'allow', ''
    
    def _match_domain(self, domain, pattern):
        """Check if domain matches the pattern (supports wildcards)"""
        if pattern.startswith('*.'):
            # Wildcard subdomain match
            pattern = pattern[2:]  # Remove the *. prefix
            return domain.endswith(pattern)
        else:
            # Exact match
            return domain == pattern
    
    def _extract_features(self, soup, url):
        """Extract features from HTML content for ML prediction"""
        try:
            from ml_model.feature_extractor import FeatureExtractor
            extractor = FeatureExtractor()
            features = extractor.extract_features(soup, url)
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None