"""
Extracts features from URLs and HTML content for ML model prediction
"""
import re
import urllib.parse
from bs4 import BeautifulSoup

class FeatureExtractor:
    def __init__(self):
        pass
        
    def extract_features(self, soup, url):
        """
        Extract features from URL and HTML content
        
        Args:
            soup: BeautifulSoup object of HTML content
            url: URL string
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Parse URL
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # URL-based features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['num_dots'] = domain.count('.')
        features['num_hyphens'] = domain.count('-')
        features['num_underscores'] = domain.count('_')
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['num_subdomains'] = domain.count('.') + 1
        features['path_length'] = len(parsed_url.path)
        features['has_suspicious_words'] = 1 if re.search(r'(login|signin|verify|account|secure|confirm|password|bank)', url.lower()) else 0
        
        # If soup is None (couldn't retrieve or parse HTML), set some default content-based features
        if soup is None:
            features['num_forms'] = 0
            features['num_inputs'] = 0
            features['num_images'] = 0
            features['num_links'] = 0
            features['ratio_external_links'] = 0
            features['has_password_field'] = 0
            features['has_login_form'] = 0
            features['has_external_scripts'] = 0
            return features
        
        # Content-based features
        forms = soup.find_all('form')
        inputs = soup.find_all('input')
        images = soup.find_all('img')
        links = soup.find_all('a')
        scripts = soup.find_all('script')
        
        features['num_forms'] = len(forms)
        features['num_inputs'] = len(inputs)
        features['num_images'] = len(images)
        features['num_links'] = len(links)
        
        # Count external links
        external_links = 0
        for link in links:
            href = link.get('href')
            if href and href.startswith(('http', 'https')) and domain not in href:
                external_links += 1
        
        # Calculate ratio of external links to total links
        features['ratio_external_links'] = external_links / len(links) if len(links) > 0 else 0
        
        # Check for password fields
        password_fields = [input_field for input_field in inputs if input_field.get('type') == 'password']
        features['has_password_field'] = 1 if password_fields else 0
        
        # Check for login forms
        login_keywords = ['login', 'signin', 'log in', 'sign in', 'authenticate']
        has_login_form = False
        for form in forms:
            form_text = form.get_text().lower()
            if any(keyword in form_text for keyword in login_keywords):
                has_login_form = True
                break
        features['has_login_form'] = 1 if has_login_form else 0
        
        # Check for external scripts
        external_scripts = 0
        for script in scripts:
            src = script.get('src')
            if src and src.startswith(('http', 'https')) and domain not in src:
                external_scripts += 1
        features['has_external_scripts'] = 1 if external_scripts > 0 else 0
        
        return features
    
    def transform_features(self, features):
        """
        Transform dictionary of features into a feature vector for ML model
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            List of feature values in the order expected by the model
        """
        # Define the expected order of features for the model
        feature_order = [
            'url_length', 'domain_length', 'num_dots', 'num_hyphens', 
            'num_underscores', 'num_digits', 'has_https', 'num_subdomains',
            'path_length', 'has_suspicious_words', 'num_forms', 'num_inputs',
            'num_images', 'num_links', 'ratio_external_links', 'has_password_field',
            'has_login_form', 'has_external_scripts'
        ]
        
        # Create feature vector with values in the expected order
        feature_vector = [features.get(feature, 0) for feature in feature_order]
        
        return feature_vector