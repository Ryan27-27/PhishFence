"""
IP address legitimacy checking using WHOIS and ASN information
"""
import re
import socket
import logging
from ipwhois import IPWhois

logger = logging.getLogger(__name__)

class IPChecker:
    def __init__(self):
        # Known suspicious ASN ranges or organizations
        self.suspicious_asn_ids = []  # Would be populated with known malicious ASNs
        
        # Suspicious keywords in ASN descriptions
        self.suspicious_keywords = [
            'vpn', 'proxy', 'tor', 'anonymous', 'hosting', 'bulletproof'
        ]
    
    def check_ip_legitimacy(self, ip):
        """
        Check if an IP address appears legitimate based on WHOIS/ASN information
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with legitimacy results
        """
        result = {
            'is_suspicious': False,
            'reason': None,
            'details': {}
        }
        
        # Validate IP format
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            result['is_suspicious'] = True
            result['reason'] = "Invalid IP address format"
            return result
        
        try:
            # Get WHOIS information
            whois = IPWhois(ip)
            whois_result = whois.lookup_rdap(depth=1)
            
            result['details'] = {
                'asn': whois_result.get('asn'),
                'asn_description': whois_result.get('asn_description'),
                'asn_country': whois_result.get('asn_country_code'),
                'network_name': whois_result.get('network', {}).get('name')
            }
            
            # Check if ASN is in known suspicious list
            asn = whois_result.get('asn')
            if asn and asn in self.suspicious_asn_ids:
                result['is_suspicious'] = True
                result['reason'] = f"IP is from a known suspicious ASN: {asn}"
                return result
            
            # Check for suspicious keywords in ASN description
            asn_description = whois_result.get('asn_description', '').lower()
            suspicious_words = [word for word in self.suspicious_keywords if word in asn_description]
            if suspicious_words:
                result['is_suspicious'] = True
                result['reason'] = f"IP is from a potentially suspicious network type: {', '.join(suspicious_words)}"
                return result
            
        except Exception as e:
            logger.error(f"Error checking IP legitimacy for {ip}: {e}")
            # If we can't check it, don't mark as suspicious
        
        return result
    
    def get_ip_for_domain(self, domain):
        """
        Resolve a domain name to an IP address
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror as e:
            logger.error(f"Error resolving domain {domain}: {e}")
            return None