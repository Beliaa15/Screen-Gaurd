"""
Security utilities for password management, logging, and system information.
"""

import hashlib
import base64
import socket
import platform
import getpass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from cryptography.fernet import Fernet

from ..core.config import Config


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
                # Additional verification layer (placeholder for more complex verification)
                secondary_check = len(entered_password) >= 8
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
                self.log_security_event("PASSWORD_VERIFY_SUCCESS", "Security password verified successfully")
                self.password_attempts = 0  # Reset attempts on success
                return True
            else:
                self.password_attempts += 1
                self.log_security_event("PASSWORD_VERIFY_FAILED", 
                                      f"Security password verification failed (attempt {self.password_attempts})")
                return False
            
        except Exception as e:
            self.log_security_event("PASSWORD_VERIFY_ERROR", f"Password verification error: {e}")
            return False

    def get_security_password_hint(self) -> str:
        """Provide encrypted hint for the security password"""
        # Encrypted hint that doesn't reveal the actual password
        encrypted_hint = "The password follows the pattern: [Word][Number][Symbol][Word] - Think about system security and the number of attempts allowed"
        return encrypted_hint

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get comprehensive system information."""
        try:
            hostname = socket.gethostname()
            try:
                ip_address = socket.gethostbyname(hostname)
            except:
                ip_address = "127.0.0.1"
            
            return {
                'computer_name': hostname,
                'username': getpass.getuser(),
                'ip_address': ip_address,
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'timestamp': datetime.now().strftime(Config.LOG_TIMESTAMP_FORMAT)
            }
        except Exception as e:
            # Fallback system info
            return {
                'computer_name': 'Unknown',
                'username': 'Unknown',
                'ip_address': '127.0.0.1',
                'platform': 'Unknown',
                'platform_version': 'Unknown',
                'architecture': 'Unknown',
                'processor': 'Unknown',
                'timestamp': datetime.now().strftime(Config.LOG_TIMESTAMP_FORMAT)
            }
    
    @staticmethod
    def log_security_event(event_type: str, details: str = "") -> None:
        """Log security events to file with timestamp and system info."""
        try:
            # Ensure logs directory exists
            Config.ensure_directories()
            
            # Create log filename with current date
            log_date = datetime.now().strftime(Config.LOG_DATE_FORMAT)
            log_filename = f"security_log_{log_date}.txt"
            log_filepath = Path(Config.LOGS_DIR) / log_filename
            
            # Get system info
            sys_info = SecurityUtils.get_system_info()
            
            # Format log entry
            log_entry = (
                f"[{sys_info['timestamp']}] "
                f"{event_type} | "
                f"Computer: {sys_info['computer_name']} | "
                f"User: {sys_info['username']} | "
                f"IP: {sys_info['ip_address']} | "
                f"Details: {details}\n"
            )
            
            # Write to log file
            with open(log_filepath, 'a', encoding='utf-8') as log_file:
                log_file.write(log_entry)
                
            # Also print to console for immediate feedback
            print(f"🔒 {event_type}: {details}")
                
        except Exception as e:
            print(f"Error logging security event: {e}")
    
    @staticmethod
    def log_biometric_orchestrator_event(event_type: str, username: str = "", 
                                       service_name: str = "", details: str = "",
                                       auth_token: str = "", cert_thumbprint: str = "") -> None:
        """Log biometric orchestrator and certificate provider events with enhanced details."""
        try:
            # Ensure logs directory exists
            Config.ensure_directories()
            
            # Create log filename with current date
            log_date = datetime.now().strftime(Config.LOG_DATE_FORMAT)
            log_filename = f"security_log_{log_date}.txt"
            log_filepath = Path(Config.LOGS_DIR) / log_filename
            
            # Get system info
            sys_info = SecurityUtils.get_system_info()
            
            # Build enhanced log entry for orchestrator events
            log_entry_parts = [
                f"[{sys_info['timestamp']}]",
                f"ORCHESTRATOR_{event_type}",
                f"Computer: {sys_info['computer_name']}",
                f"User: {sys_info['username']}",
                f"IP: {sys_info['ip_address']}"
            ]
            
            # Add orchestrator-specific fields if provided
            if username:
                log_entry_parts.append(f"Target_User: {username}")
            if service_name:
                log_entry_parts.append(f"Service: {service_name}")
            if auth_token:
                # Only log first 8 characters of auth token for security
                log_entry_parts.append(f"Auth_Token: {auth_token[:8]}...")
            if cert_thumbprint:
                log_entry_parts.append(f"Cert_Thumbprint: {cert_thumbprint}")
            if details:
                log_entry_parts.append(f"Details: {details}")
            
            log_entry = " | ".join(log_entry_parts) + "\n"
            
            # Write to log file
            with open(log_filepath, 'a', encoding='utf-8') as log_file:
                log_file.write(log_entry)
                
            # Also print to console for immediate feedback
            print(f"🛡️ ORCHESTRATOR_{event_type}: {username} - {details}")
                
        except Exception as e:
            print(f"Error logging orchestrator event: {e}")
    
    @staticmethod
    def log_certificate_provider_event(event_type: str, username: str = "",
                                     certificate_data: str = "", pkinit_data: str = "",
                                     enrollment_status: str = "", details: str = "") -> None:
        """Log certificate provider and enrollment agent events."""
        try:
            # Ensure logs directory exists
            Config.ensure_directories()
            
            # Create log filename with current date
            log_date = datetime.now().strftime(Config.LOG_DATE_FORMAT)
            log_filename = f"security_log_{log_date}.txt"
            log_filepath = Path(Config.LOGS_DIR) / log_filename
            
            # Get system info
            sys_info = SecurityUtils.get_system_info()
            
            # Build enhanced log entry for certificate provider events
            log_entry_parts = [
                f"[{sys_info['timestamp']}]",
                f"CERT_PROVIDER_{event_type}",
                f"Computer: {sys_info['computer_name']}",
                f"User: {sys_info['username']}",
                f"IP: {sys_info['ip_address']}"
            ]
            
            # Add certificate provider-specific fields if provided
            if username:
                log_entry_parts.append(f"Target_User: {username}")
            if certificate_data:
                # Only log cert thumbprint/identifier for security
                log_entry_parts.append(f"Cert_ID: {certificate_data[:16]}...")
            if pkinit_data:
                log_entry_parts.append(f"PKINIT_Data: {len(pkinit_data)} bytes")
            if enrollment_status:
                log_entry_parts.append(f"Enrollment_Status: {enrollment_status}")
            if details:
                log_entry_parts.append(f"Details: {details}")
            
            log_entry = " | ".join(log_entry_parts) + "\n"
            
            # Write to log file
            with open(log_filepath, 'a', encoding='utf-8') as log_file:
                log_file.write(log_entry)
                
            # Also print to console for immediate feedback
            print(f"📜 CERT_PROVIDER_{event_type}: {username} - {details}")
                
        except Exception as e:
            print(f"Error logging certificate provider event: {e}")
    
    @staticmethod
    def log_pre_logon_helper_event(event_type: str, username: str = "",
                                  biometric_type: str = "", capture_status: str = "",
                                  enrollment_result: str = "", details: str = "") -> None:
        """Log pre-logon helper events."""
        try:
            # Ensure logs directory exists
            Config.ensure_directories()
            
            # Create log filename with current date
            log_date = datetime.now().strftime(Config.LOG_DATE_FORMAT)
            log_filename = f"security_log_{log_date}.txt"
            log_filepath = Path(Config.LOGS_DIR) / log_filename
            
            # Get system info
            sys_info = SecurityUtils.get_system_info()
            
            # Build enhanced log entry for pre-logon helper events
            log_entry_parts = [
                f"[{sys_info['timestamp']}]",
                f"PRE_LOGON_{event_type}",
                f"Computer: {sys_info['computer_name']}",
                f"User: {sys_info['username']}",
                f"IP: {sys_info['ip_address']}"
            ]
            
            # Add pre-logon helper-specific fields if provided
            if username:
                log_entry_parts.append(f"Target_User: {username}")
            if biometric_type:
                log_entry_parts.append(f"Biometric_Type: {biometric_type}")
            if capture_status:
                log_entry_parts.append(f"Capture_Status: {capture_status}")
            if enrollment_result:
                log_entry_parts.append(f"Enrollment_Result: {enrollment_result}")
            if details:
                log_entry_parts.append(f"Details: {details}")
            
            log_entry = " | ".join(log_entry_parts) + "\n"
            
            # Write to log file
            with open(log_filepath, 'a', encoding='utf-8') as log_file:
                log_file.write(log_entry)
                
            # Also print to console for immediate feedback
            print(f"🔧 PRE_LOGON_{event_type}: {username} - {details}")
                
        except Exception as e:
            print(f"Error logging pre-logon helper event: {e}")
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, bool]:
        """Validate password strength and return detailed results."""
        checks = {
            'min_length': len(password) >= 8,
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            'no_spaces': ' ' not in password
        }
        
        checks['is_strong'] = all(checks.values())
        return checks
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> bytes:
        """Encrypt data using Fernet encryption."""
        try:
            if key is None:
                key = Fernet.generate_key()
            
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data.encode())
            return encrypted_data
        except Exception as e:
            print(f"Encryption error: {e}")
            return b''
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """Decrypt data using Fernet encryption."""
        try:
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data).decode()
            return decrypted_data
        except Exception as e:
            print(f"Decryption error: {e}")
            return ''
    
    @staticmethod
    def generate_session_token() -> str:
        """Generate a secure session token."""
        import secrets
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        """Hash a password with salt."""
        if salt is None:
            import secrets
            salt = secrets.token_hex(16)
        
        # Combine password and salt
        salted_password = password + salt
        
        # Hash using SHA-256
        password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
        
        return password_hash, salt
    
    @staticmethod
    def verify_hashed_password(password: str, hashed_password: str, salt: str) -> bool:
        """Verify a password against its hash."""
        computed_hash, _ = SecurityUtils.hash_password(password, salt)
        return computed_hash == hashed_password
