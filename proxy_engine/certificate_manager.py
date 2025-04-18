"""
Certificate manager for HTTPS interception
"""
import os
import logging
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

class CertificateManager:
    def __init__(self):
        """Initialize the certificate manager"""
        # Set up paths
        home_dir = Path.home()
        self.cert_dir = home_dir / '.phishfence' / 'certificates'
        
        # Create directory if it doesn't exist
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up paths for CA certificate
        self.ca_cert_path = self.cert_dir / 'ca.crt'
        self.ca_key_path = self.cert_dir / 'ca.key'
        
        # Create CA certificate if it doesn't exist
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._create_ca_certificate()
    
    def _create_ca_certificate(self):
        """Create a new CA certificate"""
        try:
            # Generate a private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create a self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PhishFence CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "PhishFence Root CA"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # 10 years validity
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ), critical=True
            ).sign(private_key, hashes.SHA256())
            
            # Write the CA certificate and key to files
            with open(self.ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(self.ca_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logger.info(f"Created CA certificate at {self.ca_cert_path}")
            return str(self.ca_cert_path)
            
        except Exception as e:
            logger.error(f"Error creating CA certificate: {e}")
            return None
    
    def generate_domain_certificate(self, domain):
        """
        Generate a certificate for a specific domain signed by our CA
        
        Args:
            domain: Domain name to generate certificate for
            
        Returns:
            Tuple of (cert_path, key_path)
        """
        try:
            # Load CA certificate and key
            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            
            with open(self.ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Generate a private key for the domain
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create a certificate for the domain
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PhishFence"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # 1 year validity
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]),
                critical=False,
            ).sign(ca_key, hashes.SHA256())
            
            # Write the domain certificate and key to files
            domain_cert_path = self.cert_dir / f"{domain}.crt"
            domain_key_path = self.cert_dir / f"{domain}.key"
            
            with open(domain_cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(domain_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logger.info(f"Created certificate for {domain}")
            return (str(domain_cert_path), str(domain_key_path))
            
        except Exception as e:
            logger.error(f"Error creating certificate for {domain}: {e}")
            return (None, None)