#!/usr/bin/env python3
"""
Quick URL Check Tool for PhishFence
This tool allows you to quickly test individual URLs for phishing indicators
without having to set up the full proxy server.
"""
import sys
import logging
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def check_url(url):
    """Check a URL for suspicious indicators"""
    # Ensure the URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    logger.info(f"Checking URL: {url}")
    
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check domain similarity using URLAnalyzer
    from utils.url_analyzer import URLAnalyzer
    url_analyzer = URLAnalyzer()
    
    logger.info("Checking domain similarity...")
    similarity_result = url_analyzer.check_domain_similarity(domain)
    
    if similarity_result['is_suspicious']:
        logger.warning(f"⚠️ Domain appears similar to {similarity_result['similar_to']} (score: {similarity_result['similarity_score']:.2f})")
    else:
        logger.info("✓ Domain does not appear similar to any known trusted domains")
    
    # Check URL for obfuscation
    logger.info("Checking for URL obfuscation...")
    obfuscation_result = url_analyzer.check_url_for_obfuscation(url)
    
    if obfuscation_result['is_obfuscated']:
        logger.warning(f"⚠️ URL appears to use obfuscation technique: {obfuscation_result['technique']}")
    else:
        logger.info("✓ URL does not appear to use obfuscation techniques")
    
    # Check IP legitimacy
    from utils.ip_checker import IPChecker
    ip_checker = IPChecker()
    
    logger.info(f"Resolving IP address for {domain}...")
    ip = ip_checker.get_ip_for_domain(domain)
    
    if ip:
        logger.info(f"Checking IP address: {ip}")
        ip_result = ip_checker.check_ip_legitimacy(ip)
        
        if ip_result['is_suspicious']:
            logger.warning(f"⚠️ IP address {ip} is suspicious: {ip_result['reason']}")
        else:
            logger.info(f"✓ IP address {ip} appears legitimate")
            if 'details' in ip_result and ip_result['details']:
                details = ip_result['details']
                logger.info(f"  ASN: {details.get('asn', 'Unknown')}")
                logger.info(f"  Organization: {details.get('asn_description', 'Unknown')}")
                logger.info(f"  Country: {details.get('asn_country', 'Unknown')}")
    else:
        logger.warning(f"Could not resolve IP address for {domain}")
    
    # Check if IP is a Tor exit node
    from utils.tor_detector import TorDetector
    tor_detector = TorDetector()
    
    if ip:
        logger.info(f"Checking if {ip} is a Tor exit node...")
        is_tor = tor_detector.is_tor_exit_node(ip)
        
        if is_tor:
            logger.warning(f"⚠️ IP address {ip} is a Tor exit node")
        else:
            logger.info(f"✓ IP address {ip} is not a Tor exit node")
    
    # Fetch the URL content
    try:
        logger.info(f"Fetching content from {url}...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('content-type', '')
        if 'text/html' in content_type:
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for suspicious link mismatches
            from utils.link_comparator import LinkComparator
            link_comparator = LinkComparator()
            
            logger.info("Checking for suspicious links...")
            link_result = link_comparator.analyze_links(soup, url)
            
            if link_result['suspicious_links'] > 0:
                logger.warning(f"⚠️ Found {link_result['suspicious_links']} suspicious links (confidence: {link_result['confidence']:.2f})")
                for link in link_result['suspicious_link_details'][:3]:  # Show first 3 for brevity
                    logger.warning(f"  - {link['reason']}: '{link['text']}' -> {link['href']}")
            else:
                logger.info("✓ No suspicious links detected")
            
            # Use ML model for prediction
            from ml_model.feature_extractor import FeatureExtractor
            from ml_model.model_loader import ModelLoader
            
            logger.info("Extracting features for ML analysis...")
            feature_extractor = FeatureExtractor()
            features = feature_extractor.extract_features(soup, url)
            
            logger.info("Making prediction with ML model...")
            model_loader = ModelLoader()
            prediction = model_loader.predict(features)
            
            if prediction['is_phishing'] and prediction['probability'] >= 0.7:
                logger.warning(f"⚠️ ML model detected this as a potential phishing site (confidence: {prediction['confidence']:.2f})")
            else:
                logger.info(f"✓ ML model did not identify this as a phishing site (confidence: {prediction['confidence']:.2f})")
        else:
            logger.info(f"Content is not HTML, skipping HTML-based checks (content type: {content_type})")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {e}")
    
    logger.info("Analysis complete")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Check a URL for phishing indicators')
    parser.add_argument('url', help='URL to check')
    args = parser.parse_args()
    
    try:
        check_url(args.url)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()