"""
Compares visible link text with the actual href for mismatch detection
"""
import re
import logging
import urllib.parse
import tldextract

logger = logging.getLogger(__name__)

class LinkComparator:
    def __init__(self):
        # Patterns for typical URL text content
        self.url_patterns = [
            re.compile(r'^(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'),  # Domains
            re.compile(r'^(?:click|visit|go to|check out)?\s*(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', re.IGNORECASE),  # "visit example.com"
            re.compile(r'(www\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'),  # www.example.com
        ]
        
        # Common legitimate keywords in link text
        self.legitimate_keywords = [
            'click here', 'read more', 'learn more', 'sign in', 'log in',
            'continue', 'register', 'download', 'upload', 'view', 'see',
            'more details', 'read article', 'official site', 'visit', 'website'
        ]
    
    def analyze_links(self, soup, base_url):
        """
        Analyze links in HTML content for suspicious mismatches
        
        Args:
            soup: BeautifulSoup object of HTML content
            base_url: Base URL for resolving relative links
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'total_links': 0,
            'suspicious_links': 0,
            'suspicious_link_details': [],
            'confidence': 0.0
        }
        
        # Get all links
        links = soup.find_all('a')
        result['total_links'] = len(links)
        
        if len(links) == 0:
            return result
        
        # Parse base URL for relative link resolution
        try:
            base_parsed = urllib.parse.urlparse(base_url)
            base_domain = base_parsed.netloc
        except Exception as e:
            logger.error(f"Error parsing base URL {base_url}: {e}")
            base_domain = ""
        
        # Analyze each link
        for link in links:
            href = link.get('href')
            text = link.get_text().strip()
            
            # Skip links without href or text
            if not href or not text:
                continue
            
            # Resolve relative URLs
            try:
                href = urllib.parse.urljoin(base_url, href)
            except Exception as e:
                logger.error(f"Error resolving relative URL {href}: {e}")
                continue
            
            # Check for suspicious mismatches
            mismatch_result = self._check_link_mismatch(text, href)
            
            if mismatch_result['is_suspicious']:
                result['suspicious_links'] += 1
                result['suspicious_link_details'].append({
                    'text': text,
                    'href': href,
                    'reason': mismatch_result['reason']
                })
        
        # Calculate confidence score
        if result['suspicious_links'] > 0:
            # Higher confidence if multiple suspicious links
            suspicious_ratio = result['suspicious_links'] / result['total_links']
            result['confidence'] = min(0.5 + suspicious_ratio, 0.95)
        
        return result
    
    def _check_link_mismatch(self, text, href):
        """
        Check if a link's text and href mismatch in a suspicious way
        
        Args:
            text: Visible text of the link
            href: Actual href URL
            
        Returns:
            Dictionary indicating if the link is suspicious
        """
        result = {
            'is_suspicious': False,
            'reason': None
        }
        
        # Skip checking common legitimate link texts
        if any(keyword.lower() in text.lower() for keyword in self.legitimate_keywords):
            return result
        
        try:
            # Parse the href URL
            parsed_href = urllib.parse.urlparse(href)
            href_domain = parsed_href.netloc
            
            # Extract the domain from href
            href_extract = tldextract.extract(href_domain)
            href_registered_domain = f"{href_extract.domain}.{href_extract.suffix}" if href_extract.suffix else ""
            
            # Check if text appears to be a URL or contains a domain
            text_contains_domain = False
            text_domain = ""
            
            for pattern in self.url_patterns:
                match = pattern.search(text)
                if match:
                    text_contains_domain = True
                    text_domain = match.group(1)
                    break
            
            if text_contains_domain:
                # Extract the domain from text
                text_extract = tldextract.extract(text_domain)
                text_registered_domain = f"{text_extract.domain}.{text_extract.suffix}" if text_extract.suffix else ""
                
                # If text contains a domain that's different from the href domain
                if text_registered_domain and href_registered_domain and text_registered_domain != href_registered_domain:
                    result['is_suspicious'] = True
                    result['reason'] = f"Text suggests {text_registered_domain} but link goes to {href_registered_domain}"
            
            # Check for deceptive brand names in text
            # This could be expanded with a database of common brand names
            common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix']
            for brand in common_brands:
                if brand.lower() in text.lower() and brand.lower() not in href_domain.lower():
                    result['is_suspicious'] = True
                    result['reason'] = f"Text mentions {brand} but link doesn't go to {brand}'s domain"
                    break
        
        except Exception as e:
            logger.error(f"Error checking link mismatch: {e}")
        
        return result