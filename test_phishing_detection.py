#!/usr/bin/env python3
"""
Test script for PhishFence phishing detection
This script tests the URL analysis and ML components to verify if they correctly identify phishing sites
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

def fetch_url(url):
    """Fetch a URL and return the BeautifulSoup object"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return BeautifulSoup(response.content, 'html.parser')
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL {url}: {e}")
        return None

def test_url(url):
    """Test a URL against all PhishFence detection mechanisms"""
    logger.info(f"Testing URL: {url}")
    
    # Parse URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Initialize test results
    results = {
        'domain_similarity': {
            'is_suspicious': False,
            'details': None
        },
        'url_obfuscation': {
            'is_suspicious': False,
            'details': None
        },
        'link_comparison': {
            'is_suspicious': False,
            'details': None
        },
        'ip_check': {
            'is_suspicious': False,
            'details': None
        },
        'tor_check': {
            'is_suspicious': False,
            'details': None
        },
        'ml_prediction': {
            'is_suspicious': False,
            'details': None
        }
    }
    
    # Test domain similarity
    from utils.url_analyzer import URLAnalyzer
    url_analyzer = URLAnalyzer()
    
    similarity_result = url_analyzer.check_domain_similarity(domain)
    if similarity_result['is_suspicious']:
        results['domain_similarity']['is_suspicious'] = True
        results['domain_similarity']['details'] = {
            'similar_to': similarity_result['similar_to'],
            'score': similarity_result['similarity_score']
        }
    
    # Test URL obfuscation
    obfuscation_result = url_analyzer.check_url_for_obfuscation(url)
    if obfuscation_result['is_obfuscated']:
        results['url_obfuscation']['is_suspicious'] = True
        results['url_obfuscation']['details'] = {
            'technique': obfuscation_result['technique']
        }
    
    # Fetch and analyze the URL content
    soup = fetch_url(url)
    if soup:
        # Test link comparison
        from utils.link_comparator import LinkComparator
        link_comparator = LinkComparator()
        
        link_result = link_comparator.analyze_links(soup, url)
        if link_result['suspicious_links'] > 0 and link_result['confidence'] >= 0.7:
            results['link_comparison']['is_suspicious'] = True
            results['link_comparison']['details'] = {
                'suspicious_links': link_result['suspicious_links'],
                'confidence': link_result['confidence'],
                'examples': link_result['suspicious_link_details'][:3]  # First 3 examples
            }
        
        # Test ML prediction
        from ml_model.feature_extractor import FeatureExtractor
        from ml_model.model_loader import ModelLoader
        
        feature_extractor = FeatureExtractor()
        features = feature_extractor.extract_features(soup, url)
        
        model_loader = ModelLoader()
        prediction = model_loader.predict(features)
        
        if prediction['is_phishing'] and prediction['probability'] >= 0.7:
            results['ml_prediction']['is_suspicious'] = True
            results['ml_prediction']['details'] = {
                'probability': prediction['probability'],
                'confidence': prediction['confidence']
            }
    
    # Test IP legitimacy
    from utils.ip_checker import IPChecker
    ip_checker = IPChecker()
    
    ip = ip_checker.get_ip_for_domain(domain)
    if ip:
        ip_result = ip_checker.check_ip_legitimacy(ip)
        if ip_result['is_suspicious']:
            results['ip_check']['is_suspicious'] = True
            results['ip_check']['details'] = {
                'ip': ip,
                'reason': ip_result['reason']
            }
        
        # Test Tor exit node
        from utils.tor_detector import TorDetector
        tor_detector = TorDetector()
        
        is_tor = tor_detector.is_tor_exit_node(ip)
        if is_tor:
            results['tor_check']['is_suspicious'] = True
            results['tor_check']['details'] = {
                'ip': ip
            }
    
    # Print test results
    print("\n=== PhishFence Detection Test Results ===")
    print(f"URL: {url}")
    
    suspicious_count = sum(1 for test, result in results.items() if result['is_suspicious'])
    if suspicious_count == 0:
        print("\n✅ No suspicious indicators detected")
    else:
        print(f"\n⚠️ Found {suspicious_count} suspicious indicators")
    
    for test, result in results.items():
        test_name = test.replace('_', ' ').capitalize()
        if result['is_suspicious']:
            print(f"\n⚠️ {test_name}: SUSPICIOUS")
            
            details = result['details']
            if test == 'domain_similarity':
                print(f"  - Similar to: {details['similar_to']}")
                print(f"  - Score: {details['score']:.2f}")
            elif test == 'url_obfuscation':
                print(f"  - Technique: {details['technique']}")
            elif test == 'link_comparison':
                print(f"  - Suspicious links: {details['suspicious_links']}")
                print(f"  - Confidence: {details['confidence']:.2f}")
                if 'examples' in details:
                    print("  - Examples:")
                    for ex in details['examples']:
                        print(f"    • {ex['reason']}: '{ex['text']}' -> {ex['href']}")
            elif test == 'ip_check':
                print(f"  - IP: {details['ip']}")
                print(f"  - Reason: {details['reason']}")
            elif test == 'tor_check':
                print(f"  - IP is a Tor exit node: {details['ip']}")
            elif test == 'ml_prediction':
                print(f"  - Probability: {details['probability']:.2f}")
                print(f"  - Confidence: {details['confidence']:.2f}")
        else:
            print(f"\n✅ {test_name}: OK")
    
    # Overall verdict
    print("\n=== Verdict ===")
    if suspicious_count >= 2:
        print("❗ HIGH RISK: Multiple suspicious indicators detected")
    elif suspicious_count == 1:
        print("⚠️ POTENTIAL RISK: One suspicious indicator detected")
    else:
        print("✅ LOW RISK: No suspicious indicators detected")
    
    return results

def main():
    """Main function to run tests"""
    parser = argparse.ArgumentParser(description='Test PhishFence detection mechanisms')
    parser.add_argument('urls', nargs='+', help='URLs to test')
    args = parser.parse_args()
    
    for url in args.urls:
        try:
            test_url(url)
            print("\n" + "-" * 80 + "\n")  # Separator between URLs
        except Exception as e:
            logger.error(f"Error testing URL {url}: {e}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)