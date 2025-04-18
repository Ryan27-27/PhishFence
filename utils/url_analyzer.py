"""
URL analysis tools for checking domains against known trusted domains
"""
import re
import logging
import difflib
import urllib.parse

logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        # Load the list of trusted domains from configuration
        from utils.config_manager import ConfigManager
        config = ConfigManager()
        self.trusted_domains = config.get('trusted_domains', [])
        
        # Domain pattern for validation
        self.domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        
        # IP address pattern for detection
        self.ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        
        # Common TLDs for comparison
        self.common_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.co', '.io'}
    
    def check_domain_similarity(self, domain):
        """
        Check if a domain is similar to known trusted domains (potential phishing)
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with similarity results
        """
        result = {
            'is_suspicious': False,
            'similar_to': None,
            'similarity_score': 0.0,
            'checks': {}
        }
        
        # Validate domain format
        if not self.domain_pattern.match(domain):
            result['checks']['valid_domain'] = False
            
            # Check if it's an IP address
            if self.ip_pattern.match(domain):
                result['checks']['is_ip_address'] = True
                
                # IP addresses as domains are somewhat suspicious
                result['is_suspicious'] = True
                result['similar_to'] = "IP address instead of domain name"
                return result
            
            # Invalid domain format
            return result
        
        result['checks']['valid_domain'] = True
        
        # Get base domain (without subdomains)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = domain
        
        # Check for similarity with trusted domains
        highest_similarity = 0.0
        most_similar_domain = None
        
        for trusted_domain in self.trusted_domains:
            # Skip if trusted domain is a subdomain pattern (e.g., *.example.com)
            if trusted_domain.startswith('*.'):
                continue
                
            # Get base trusted domain
            trusted_parts = trusted_domain.split('.')
            if len(trusted_parts) >= 2:
                base_trusted = '.'.join(trusted_parts[-2:])
            else:
                base_trusted = trusted_domain
            
            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, base_domain, base_trusted).ratio()
            
            # Apply additional checks for very similar domains
            if similarity > 0.7:
                # Check for typosquatting by comparing character by character
                typo_score = self._check_for_typosquatting(base_domain, base_trusted)
                similarity = max(similarity, typo_score)
            
            # Keep track of the most similar domain
            if similarity > highest_similarity:
                highest_similarity = similarity
                most_similar_domain = trusted_domain
        
        # Set threshold for suspicious similarity
        threshold = 0.8
        if highest_similarity >= threshold:
            result['is_suspicious'] = True
            result['similar_to'] = most_similar_domain
            result['similarity_score'] = highest_similarity
        
        return result
    
    def check_url_for_obfuscation(self, url):
        """
        Check if URL uses obfuscation techniques
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with obfuscation check results
        """
        result = {
            'is_obfuscated': False,
            'technique': None,
            'checks': {}
        }
        
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            
            # Check for IP address instead of domain
            if self.ip_pattern.match(parsed_url.netloc):
                result['is_obfuscated'] = True
                result['technique'] = "IP address instead of domain name"
                result['checks']['ip_as_domain'] = True
                return result
            
            # Check for URL encoding
            if '%' in parsed_url.netloc:
                result['is_obfuscated'] = True
                result['technique'] = "URL encoding in domain"
                result['checks']['url_encoding'] = True
                return result
            
            # Check for hexadecimal or octal encoding
            if re.search(r'0x[0-9a-f]+', url, re.IGNORECASE) or re.search(r'\\[0-7]{3}', url):
                result['is_obfuscated'] = True
                result['technique'] = "Hexadecimal or octal encoding"
                result['checks']['hex_encoding'] = True
                return result
            
            # Check for excessive subdomains
            subdomain_count = parsed_url.netloc.count('.')
            if subdomain_count >= 3:
                result['is_obfuscated'] = True
                result['technique'] = f"Excessive subdomains ({subdomain_count + 1} levels)"
                result['checks']['excessive_subdomains'] = True
                return result
            
            # Check for numeric domain
            domain = parsed_url.netloc
            if domain.replace('.', '').isdigit():
                result['is_obfuscated'] = True
                result['technique'] = "Fully numeric domain"
                result['checks']['numeric_domain'] = True
                return result
            
            # Check for long domain
            if len(domain) > 30:
                result['is_obfuscated'] = True
                result['technique'] = f"Unusually long domain ({len(domain)} characters)"
                result['checks']['long_domain'] = True
                return result
            
            # Check for unusual TLD
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            if tld and tld not in self.common_tlds:
                result['checks']['unusual_tld'] = True
                # Not necessarily obfuscation, but worth noting
            
            # Check for username/password in URL
            if '@' in parsed_url.netloc:
                result['is_obfuscated'] = True
                result['technique'] = "Username/password embedded in URL"
                result['checks']['credentials_in_url'] = True
                return result
                
        except Exception as e:
            logger.error(f"Error checking URL for obfuscation: {e}")
        
        return result
    
    def _check_for_typosquatting(self, domain, trusted_domain):
        """Check for typosquatting techniques"""
        # Simple version for demonstration
        if len(domain) != len(trusted_domain):
            return 0.0
        
        # Count character differences
        diff_count = sum(1 for a, b in zip(domain, trusted_domain) if a != b)
        
        # If only 1-2 characters are different, it's likely typosquatting
        if diff_count <= 2:
            return 0.9  # High similarity score
        
        return 0.0