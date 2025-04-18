#!/usr/bin/env python3
"""
Simple URL check that uses the URLAnalyzer class to test for phishing indicators
"""
import sys
import logging
import argparse
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Check a URL for suspicious indicators')
    parser.add_argument('url', help='URL or domain to check')
    args = parser.parse_args()
    
    url = args.url
    
    # Ensure the URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse the URL to get the domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    logger.info(f"Analyzing domain: {domain}")
    
    # Check domain similarity
    from utils.url_analyzer import URLAnalyzer
    analyzer = URLAnalyzer()
    result = analyzer.check_domain_similarity(domain)
    
    # Display results
    print("\n== Domain Similarity Analysis ==")
    if result['is_suspicious']:
        print(f"⚠️  WARNING: This domain appears similar to {result['similar_to']}")
        print(f"Similarity score: {result['similarity_score']:.2f}")
    else:
        print("✅ This domain does not appear similar to any known trusted domains")
    
    # Check for URL obfuscation
    print("\n== URL Obfuscation Analysis ==")
    obfuscation_result = analyzer.check_url_for_obfuscation(url)
    
    if obfuscation_result['is_obfuscated']:
        print(f"⚠️  WARNING: This URL appears to use obfuscation techniques")
        print(f"Technique detected: {obfuscation_result['technique']}")
    else:
        print("✅ No URL obfuscation techniques detected")
    
    # Show trusted domains for reference
    print("\n== Trusted Domain Reference ==")
    print("The following domains are used as reference for similarity checking:")
    for domain in analyzer.trusted_domains[:10]:  # Show first 10 for brevity
        print(f"- {domain}")
    if len(analyzer.trusted_domains) > 10:
        print(f"... and {len(analyzer.trusted_domains) - 10} more")
    
    print("\nReminder: This is a simple check and may not catch all phishing attempts.")
    print("For more comprehensive analysis, use the full PhishFence system.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)