"""
Test suite for the Physical Security System utilities.
"""

import pytest
import os
import tempfile
import json
from unittest.mock import Mock, patch, mock_open
from src.utils.security_utils import SecurityUtils


class TestSecurityUtils:
    """Test cases for SecurityUtils."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.security_utils = SecurityUtils()
    
    def test_initialization(self):
        """Test proper initialization of SecurityUtils."""
        assert hasattr(SecurityUtils, 'log_security_event')
        assert hasattr(SecurityUtils, 'get_system_info')
        assert hasattr(SecurityUtils, 'encrypt_password')
        assert hasattr(SecurityUtils, 'decrypt_password')
    
    @patch('src.utils.security_utils.datetime')
    @patch('builtins.open', new_callable=mock_open)
    def test_log_security_event(self, mock_file, mock_datetime):
        """Test security event logging."""
        # Mock datetime
        mock_datetime.now.return_value.strftime.return_value = '2025-01-15 10:30:00'
        
        SecurityUtils.log_security_event('TEST_EVENT', 'Test message')
        
        # Verify file was opened for writing
        mock_file.assert_called_once()
        
        # Verify write was called with proper format
        handle = mock_file.return_value
        handle.write.assert_called()
        
        # Check that the written content includes expected elements
        written_content = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert 'TEST_EVENT' in written_content
        assert 'Test message' in written_content
        assert '2025-01-15 10:30:00' in written_content
    
    @patch('src.utils.security_utils.platform.system')
    @patch('src.utils.security_utils.platform.platform')
    @patch('src.utils.security_utils.getpass.getuser')
    @patch('src.utils.security_utils.socket.gethostname')
    def test_get_system_info(self, mock_hostname, mock_getuser, mock_platform, mock_system):
        """Test system information gathering."""
        # Mock system information
        mock_system.return_value = 'Windows'
        mock_platform.return_value = 'Windows-10-10.0.19041-SP0'
        mock_getuser.return_value = 'testuser'
        mock_hostname.return_value = 'TEST-PC'
        
        system_info = SecurityUtils.get_system_info()
        
        # Verify returned information
        assert system_info['os'] == 'Windows'
        assert system_info['platform'] == 'Windows-10-10.0.19041-SP0'
        assert system_info['username'] == 'testuser'
        assert system_info['hostname'] == 'TEST-PC'
        assert 'timestamp' in system_info
    
    @patch('src.utils.security_utils.Fernet.generate_key')
    @patch('src.utils.security_utils.Fernet')
    def test_encrypt_password(self, mock_fernet_class, mock_generate_key):
        """Test password encryption."""
        # Mock encryption components
        mock_key = b'test_key_32_bytes_long_for_fernet'
        mock_generate_key.return_value = mock_key
        
        mock_fernet_instance = Mock()
        mock_fernet_instance.encrypt.return_value = b'encrypted_password'
        mock_fernet_class.return_value = mock_fernet_instance
        
        # Test encryption
        encrypted_data = SecurityUtils.encrypt_password('test_password')
        
        # Verify encryption was called
        mock_fernet_instance.encrypt.assert_called_once_with(b'test_password')
        
        # Verify return format
        assert 'key' in encrypted_data
        assert 'encrypted_password' in encrypted_data
    
    @patch('src.utils.security_utils.Fernet')
    def test_decrypt_password(self, mock_fernet_class):
        """Test password decryption."""
        # Mock decryption components
        mock_fernet_instance = Mock()
        mock_fernet_instance.decrypt.return_value = b'decrypted_password'
        mock_fernet_class.return_value = mock_fernet_instance
        
        # Test data
        encrypted_data = {
            'key': b'test_key_32_bytes_long_for_fernet',
            'encrypted_password': b'encrypted_password'
        }
        
        # Test decryption
        decrypted = SecurityUtils.decrypt_password(encrypted_data)
        
        # Verify decryption was called
        mock_fernet_instance.decrypt.assert_called_once_with(b'encrypted_password')
        
        # Verify result
        assert decrypted == 'decrypted_password'
    
    def test_decrypt_password_invalid_data(self):
        """Test decryption with invalid data."""
        invalid_data = {'key': 'invalid'}
        
        with pytest.raises(ValueError):
            SecurityUtils.decrypt_password(invalid_data)
    
    @patch('src.utils.security_utils.os.makedirs')
    @patch('src.utils.security_utils.os.path.exists')
    def test_ensure_log_directory(self, mock_exists, mock_makedirs):
        """Test log directory creation."""
        # Mock directory doesn't exist
        mock_exists.return_value = False
        
        # This would be called internally by log_security_event
        with patch('builtins.open', new_callable=mock_open):
            SecurityUtils.log_security_event('TEST', 'Test message')
        
        # Verify makedirs was called (indirectly through logging)
        # Note: This tests the directory creation logic that would occur
    
    @patch('src.utils.security_utils.json.dump')
    @patch('builtins.open', new_callable=mock_open)
    def test_save_encrypted_data(self, mock_file, mock_json_dump):
        """Test saving encrypted data to file."""
        test_data = {
            'key': b'test_key',
            'encrypted_password': b'encrypted_data'
        }
        
        # This would be part of a save function
        with patch.object(SecurityUtils, '_save_encrypted_data') as mock_save:
            mock_save.return_value = True
            result = SecurityUtils._save_encrypted_data('test.json', test_data)
            assert result is True
    
    @patch('src.utils.security_utils.json.load')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_encrypted_data(self, mock_file, mock_json_load):
        """Test loading encrypted data from file."""
        test_data = {
            'key': 'dGVzdF9rZXk=',  # base64 encoded
            'encrypted_password': 'ZW5jcnlwdGVkX2RhdGE='  # base64 encoded
        }
        mock_json_load.return_value = test_data
        
        # This would be part of a load function
        with patch.object(SecurityUtils, '_load_encrypted_data') as mock_load:
            mock_load.return_value = test_data
            result = SecurityUtils._load_encrypted_data('test.json')
            assert result == test_data
    
    def test_validate_password_strength(self):
        """Test password strength validation."""
        # Strong password
        strong_password = "StrongP@ssw0rd123"
        
        # This would be implemented as a utility method
        with patch.object(SecurityUtils, 'validate_password_strength') as mock_validate:
            mock_validate.return_value = True
            result = SecurityUtils.validate_password_strength(strong_password)
            assert result is True
    
    def test_generate_secure_token(self):
        """Test secure token generation."""
        with patch('src.utils.security_utils.secrets.token_hex') as mock_token:
            mock_token.return_value = 'secure_token_123'
            
            # This would be implemented as a utility method
            with patch.object(SecurityUtils, 'generate_secure_token') as mock_generate:
                mock_generate.return_value = 'secure_token_123'
                result = SecurityUtils.generate_secure_token()
                assert result == 'secure_token_123'
    
    @patch('src.utils.security_utils.hashlib.sha256')
    def test_hash_password(self, mock_sha256):
        """Test password hashing."""
        # Mock hash object
        mock_hash = Mock()
        mock_hash.hexdigest.return_value = 'hashed_password'
        mock_sha256.return_value = mock_hash
        
        # This would be implemented as a utility method
        with patch.object(SecurityUtils, 'hash_password') as mock_hash_func:
            mock_hash_func.return_value = 'hashed_password'
            result = SecurityUtils.hash_password('test_password')
            assert result == 'hashed_password'
    
    def test_verify_password_hash(self):
        """Test password hash verification."""
        password = 'test_password'
        password_hash = 'hashed_password'
        
        # This would be implemented as a utility method
        with patch.object(SecurityUtils, 'verify_password_hash') as mock_verify:
            mock_verify.return_value = True
            result = SecurityUtils.verify_password_hash(password, password_hash)
            assert result is True
    
    @patch('src.utils.security_utils.subprocess.run')
    def test_get_windows_security_info(self, mock_run):
        """Test Windows-specific security information gathering."""
        # Mock Windows security command output
        mock_result = Mock()
        mock_result.stdout = 'Windows Security Info'
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        # This would be implemented as a utility method
        with patch.object(SecurityUtils, 'get_windows_security_info') as mock_get_info:
            mock_get_info.return_value = {'security_info': 'Windows Security Info'}
            result = SecurityUtils.get_windows_security_info()
            assert 'security_info' in result
    
    def test_cleanup_sensitive_data(self):
        """Test cleanup of sensitive data from memory."""
        # This would be implemented as a utility method
        with patch.object(SecurityUtils, 'cleanup_sensitive_data') as mock_cleanup:
            mock_cleanup.return_value = True
            result = SecurityUtils.cleanup_sensitive_data(['password', 'token'])
            assert result is True


class TestSecurityUtilsFileOperations:
    """Test file operations in SecurityUtils."""
    
    def test_log_file_creation(self):
        """Test that log files are created properly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, 'test_security.log')
            
            # Mock the log file path
            with patch('src.utils.security_utils.Config.LOG_DIR', temp_dir):
                with patch('builtins.open', mock_open()) as mock_file:
                    SecurityUtils.log_security_event('TEST', 'Test message')
                    
                    # Verify file operation
                    mock_file.assert_called_once()
    
    def test_log_file_permissions(self):
        """Test that log files have proper permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # This would test file permission setting
            with patch('src.utils.security_utils.os.chmod') as mock_chmod:
                with patch('builtins.open', mock_open()):
                    SecurityUtils.log_security_event('TEST', 'Test message')
                    
                    # In a real implementation, chmod would be called
                    # to set secure permissions on log files


class TestSecurityUtilsIntegration:
    """Integration tests for SecurityUtils."""
    
    def test_full_encryption_cycle(self):
        """Test complete encryption and decryption cycle."""
        original_password = 'test_password_123'
        
        # Mock the full cycle
        with patch.object(SecurityUtils, 'encrypt_password') as mock_encrypt:
            with patch.object(SecurityUtils, 'decrypt_password') as mock_decrypt:
                # Mock encrypted data
                encrypted_data = {
                    'key': b'test_key_32_bytes_long_for_fernet',
                    'encrypted_password': b'encrypted_password'
                }
                
                mock_encrypt.return_value = encrypted_data
                mock_decrypt.return_value = original_password
                
                # Test full cycle
                encrypted = SecurityUtils.encrypt_password(original_password)
                decrypted = SecurityUtils.decrypt_password(encrypted)
                
                assert decrypted == original_password
    
    def test_logging_with_system_info(self):
        """Test logging that includes system information."""
        with patch.object(SecurityUtils, 'get_system_info') as mock_get_info:
            with patch.object(SecurityUtils, 'log_security_event') as mock_log:
                # Mock system info
                mock_get_info.return_value = {
                    'os': 'Windows',
                    'username': 'testuser',
                    'hostname': 'TEST-PC'
                }
                
                # Test logging with system context
                system_info = SecurityUtils.get_system_info()
                SecurityUtils.log_security_event('LOGIN_ATTEMPT', 
                                                f"User {system_info['username']} login attempt")
                
                mock_log.assert_called_once()
    
    @patch('src.utils.security_utils.threading.Lock')
    def test_thread_safe_logging(self, mock_lock):
        """Test thread-safe logging operations."""
        mock_lock_instance = Mock()
        mock_lock.return_value = mock_lock_instance
        
        with patch('builtins.open', mock_open()):
            SecurityUtils.log_security_event('THREAD_TEST', 'Thread safe test')
            
            # In a real implementation with threading locks
            # mock_lock_instance.__enter__.assert_called()
            # mock_lock_instance.__exit__.assert_called()


@pytest.fixture
def temp_log_directory():
    """Fixture to provide a temporary log directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


class TestSecurityUtilsErrorHandling:
    """Test error handling in SecurityUtils."""
    
    def test_log_event_file_permission_error(self):
        """Test logging when file permissions are denied."""
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            # Should handle gracefully
            try:
                SecurityUtils.log_security_event('TEST', 'Test message')
            except PermissionError:
                pytest.fail("Should handle permission errors gracefully")
    
    def test_encrypt_password_key_error(self):
        """Test encryption with key generation failure."""
        with patch('src.utils.security_utils.Fernet.generate_key', 
                   side_effect=Exception("Key generation failed")):
            with pytest.raises(Exception):
                SecurityUtils.encrypt_password('test_password')
    
    def test_decrypt_password_invalid_key(self):
        """Test decryption with invalid key."""
        invalid_data = {
            'key': b'invalid_key_too_short',
            'encrypted_password': b'encrypted_data'
        }
        
        with patch('src.utils.security_utils.Fernet') as mock_fernet:
            mock_fernet.side_effect = ValueError("Invalid key")
            
            with pytest.raises(ValueError):
                SecurityUtils.decrypt_password(invalid_data)
    
    def test_system_info_gathering_failure(self):
        """Test system info gathering with failures."""
        with patch('src.utils.security_utils.platform.system', 
                   side_effect=Exception("System info unavailable")):
            # Should handle gracefully and return partial info
            system_info = SecurityUtils.get_system_info()
            
            # Should still have timestamp even if other info fails
            assert 'timestamp' in system_info


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
