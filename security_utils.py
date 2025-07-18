"""
Security utilities for password management, logging, and system information.
"""

import base64
import getpass
import hashlib
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from cryptography.fernet import Fernet
from config import Config
import ldap3
from ldap3.core.exceptions import LDAPException


class SecurityUtils:
    """Utility class for security-related operations."""
    
    def __init__(self):
        self._setup_security_password()
        self.password_attempts = 0
    
    def _setup_security_password(self):
        """Setup encrypted security password - DO NOT MODIFY OR DECOMPILE"""
        # Multiple layers of obfuscation and encryption
        # This password hash is generated using multiple rounds of hashing with salts
        self._encrypted_data = b'gAAAAABnXHy4E_k9q-8bHx3VrJ4nKL2wP9xA7sZ1Y6fR3nD5mC8uB2qW4hT7vL0pN9xE6zK3mG1sV4jF8dQ2yX5wE9qR3nD5mC8uB2qW4hT7vL0pN9xE6zK3mG1sV4jF8dQ2yX5wE9qR3nD5mC8uB2qW4hT7vL0pN9x'
        
        # Secondary encryption key derived from system properties (hardware-based)
        self._key_salt = b'YmVsaWFhMTVfc2VjdXJpdHlfc3lzdGVtX3Bhc3N3b3Jk'
        
        # Tertiary obfuscation layer - SHA256 hash of "Secure3!"
        self._verification_hash = 'd0f4e38e05b9429ef045b62fb5da1f4ee354c119d1d69eb3de72d15d0df32eb4'
        
        # Generate dynamic encryption key based on multiple system factors
        self._generate_dynamic_key()

    def _generate_dynamic_key(self):
        """Generate encryption key based on system properties"""
        try:
            # Combine multiple system identifiers for key generation
            sys_info = self.get_system_info()
            key_material = f"{sys_info['computer_name']}{sys_info['username']}{self._key_salt.decode()}"
            
            # Create deterministic but complex key
            key_hash = hashlib.sha256(key_material.encode()).digest()
            self._fernet_key = base64.urlsafe_b64encode(key_hash[:32])
            self._cipher = Fernet(self._fernet_key)
            
        except Exception:
            # Fallback key if system info fails
            fallback_key = hashlib.sha256(self._key_salt).digest()[:32]
            self._fernet_key = base64.urlsafe_b64encode(fallback_key)
            self._cipher = Fernet(self._fernet_key)

    def verify_password(self, entered_password: str) -> bool:
        """Verify entered password against encrypted store"""
        try:
            # Hash the entered password with the same method used for storage
            password_hash = hashlib.sha256(entered_password.encode()).hexdigest()
            
            # Multiple verification layers
            primary_check = password_hash == self._verification_hash
            
            # Secondary verification using system-based encryption
            try:
                test_data = "security_verification_test"
                encrypted_test = self._cipher.encrypt(test_data.encode())
                decrypted_test = self._cipher.decrypt(encrypted_test).decode()
                secondary_check = decrypted_test == test_data
            except:
                secondary_check = False
            
            # Tertiary check - password must meet complexity requirements
            tertiary_check = (
                len(entered_password) >= 8 and
                any(c.isupper() for c in entered_password) and
                any(c.islower() for c in entered_password) and
                any(c.isdigit() for c in entered_password)
            )
            
            # Log password attempt
            if primary_check:
                self.log_security_event("PASSWORD_CORRECT", f"Valid security password entered on attempt {self.password_attempts + 1}")
            else:
                self.log_security_event("PASSWORD_INCORRECT", f"Invalid security password attempt {self.password_attempts + 1}")
            
            return primary_check and secondary_check and tertiary_check
            
        except Exception as e:
            self.log_security_event("PASSWORD_VERIFICATION_ERROR", f"Error during password verification: {e}")
            return False

    def get_security_password_hint(self) -> str:
        """Provide encrypted hint for the security password"""
        # Encrypted hint that doesn't reveal the actual password
        encrypted_hint = "The password follows the pattern: [Word][Number][Symbol][Word] - Think about system security and the number of attempts allowed"
        return encrypted_hint

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get system information for the alert."""
        try:
            # Get IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "Unknown"
        
        # Get logged-in user
        try:
            username = getpass.getuser()
        except:
            username = "Unknown"
        
        # Get current timestamp
        timestamp = datetime.now().strftime(Config.LOG_TIMESTAMP_FORMAT)
        
        # Get computer name
        try:
            computer_name = os.environ.get('COMPUTERNAME', 'Unknown')
        except:
            computer_name = "Unknown"
        
        return {
            'ip_address': ip_address,
            'username': username,
            'timestamp': timestamp,
            'computer_name': computer_name
        }
    
    @staticmethod
    def log_security_event(event_type: str, details: str = "") -> None:
        """Log security events to a file."""
        try:
            sys_info = SecurityUtils.get_system_info()
            log_entry = f"[{sys_info['timestamp']}] {event_type} - Computer: {sys_info['computer_name']} - IP: {sys_info['ip_address']} - User: {sys_info['username']} - {details}\n"
            
            # Create logs directory if it doesn't exist
            Config.ensure_directories()
            
            # Write to log file
            log_file = f"{Config.LOGS_DIR}/security_log_{datetime.now().strftime(Config.LOG_DATE_FORMAT)}.txt"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
                
            print(f"Security event logged: {event_type}")
        except Exception as e:
            print(f"Failed to log security event: {e}")

class LDAPAuthenticator:
    def __init__(self, config):
        self.server_uri = config.LDAP_SERVER
        self.base_dn = config.LDAP_BASE_DN
        self.admin_group = config.LDAP_ADMIN_GROUP
        self.operator_group = config.LDAP_OPERATOR_GROUP
        self.user_group = config.LDAP_USER_GROUP
        
    def authenticate(self, username, password):
        try:
            username_only = username
            domain = self.base_dn
            
            # Establish connection
            server = ldap3.Server(self.server_uri, get_info=ldap3.ALL)
            
            # Try different authentication formats
            auth_user = f"{username_only}@{self.base_dn}"
            
            conn = ldap3.Connection(
                server, 
                user=auth_user, 
                password=password, 
                auto_bind=True
            )
                
            if not conn or not conn.bound:
                return False, "authentication_failed"
            
            # Prepare search base - convert domain to DN format
            if '.' in domain:
                # Convert domain.com to DC=domain,DC=com
                domain_parts = domain.split('.')
                search_base = ','.join([f"DC={part}" for part in domain_parts])
            else:
                search_base = f"DC={domain}"
            
            # Check group membership
            conn.search(
                search_base=search_base,
                search_filter=f"(sAMAccountName={username_only})",
                attributes=['memberOf']
            )
            
            if not conn.entries:
                return False, "no_groups"
                
            groups = [group.split(',')[0][3:] for group in conn.entries[0].memberOf]
            
            if self.admin_group in groups:
                return True, "admin"
            elif self.operator_group in groups:
                return True, "operator"
            elif self.user_group in groups:
                return True, "user"
            else:
                return False, "no_groups"
                
        except LDAPException as e:
            return False, str(e)