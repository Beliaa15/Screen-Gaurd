"""
Test suite for the Physical Security System authentication module.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from src.auth.auth_manager import AuthenticationManager
from src.auth.ldap_auth import LDAPAuthenticator
from src.auth.biometric_auth import BiometricAuthenticator
from src.auth.session_manager import SessionManager
from src.core.config import Config


class TestAuthenticationManager:
    """Test cases for AuthenticationManager."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.auth_manager = AuthenticationManager()
    
    def test_initialization(self):
        """Test proper initialization of AuthenticationManager."""
        assert self.auth_manager.ldap_auth is not None
        assert self.auth_manager.biometric_auth is not None
        assert self.auth_manager.session_manager is not None
    
    @patch('src.core.config.Config.AUTHENTICATION_REQUIRED', False)
    def test_require_authentication_disabled(self):
        """Test authentication bypass when disabled."""
        result = self.auth_manager.require_authentication()
        assert result is True
    
    def test_is_authenticated_no_session(self):
        """Test authentication check with no active session."""
        result = self.auth_manager.is_authenticated()
        assert result is False
    
    @patch.object(AuthenticationManager, '_try_gui_authentication')
    def test_require_authentication_gui_success(self, mock_gui_auth):
        """Test successful GUI authentication."""
        mock_gui_auth.return_value = True
        
        with patch('src.core.config.Config.AUTHENTICATION_REQUIRED', True):
            result = self.auth_manager.require_authentication()
            assert result is True
            mock_gui_auth.assert_called_once()


class TestLDAPAuthenticator:
    """Test cases for LDAPAuthenticator."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.ldap_auth = LDAPAuthenticator()
    
    def test_initialization(self):
        """Test proper initialization of LDAPAuthenticator."""
        assert self.ldap_auth.server_uri == Config.LDAP_SERVER
        assert self.ldap_auth.base_dn == Config.LDAP_BASE_DN
    
    def test_authenticate_missing_credentials(self):
        """Test authentication with missing credentials."""
        # Test missing username
        success, result = self.ldap_auth.authenticate({'password': 'test'})
        assert success is False
        assert "Username and password required" in result
        
        # Test missing password
        success, result = self.ldap_auth.authenticate({'username': 'test'})
        assert success is False
        assert "Username and password required" in result
    
    @patch('ldap3.Connection')
    @patch('ldap3.Server')
    def test_authenticate_success(self, mock_server, mock_connection):
        """Test successful LDAP authentication."""
        # Mock successful connection
        mock_conn = Mock()
        mock_conn.bind.return_value = True
        mock_conn.entries = [Mock()]
        mock_conn.entries[0].memberOf.values = ['CN=SecurityUsers,OU=Groups,DC=test,DC=com']
        mock_connection.return_value = mock_conn
        
        success, result = self.ldap_auth.authenticate({
            'username': 'testuser',
            'password': 'testpass'
        })
        
        assert success is True
        assert isinstance(result, dict)
        assert result['username'] == 'testuser'
    
    def test_determine_user_role(self):
        """Test user role determination from group membership."""
        # Test admin role
        admin_groups = ['CN=SecurityAdmins,OU=Groups,DC=test,DC=com']
        role = self.ldap_auth._determine_user_role(admin_groups)
        assert role == 'admin'
        
        # Test user role
        user_groups = ['CN=SecurityUsers,OU=Groups,DC=test,DC=com']
        role = self.ldap_auth._determine_user_role(user_groups)
        assert role == 'user'
        
        # Test guest role (no groups)
        no_groups = []
        role = self.ldap_auth._determine_user_role(no_groups)
        assert role == 'guest'


class TestBiometricAuthenticator:
    """Test cases for BiometricAuthenticator."""
    
    def setup_method(self):
        """Setup test fixtures."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('src.core.config.Config.FACE_IMAGES_DIR', temp_dir):
                self.biometric_auth = BiometricAuthenticator()
    
    def test_initialization(self):
        """Test proper initialization of BiometricAuthenticator."""
        assert self.biometric_auth.face_encodings_db == {}
        assert self.biometric_auth.face_data_dir.exists()
    
    def test_is_available(self):
        """Test availability check."""
        # This will depend on whether face_recognition is installed
        result = self.biometric_auth.is_available()
        assert isinstance(result, bool)
    
    def test_authenticate_unknown_method(self):
        """Test authentication with unknown method."""
        success, result = self.biometric_auth.authenticate({
            'method': 'unknown_method'
        })
        
        assert success is False
        assert "Unknown biometric method" in result
    
    @patch('src.auth.biometric_auth.FACE_RECOGNITION_AVAILABLE', False)
    def test_authenticate_face_unavailable(self):
        """Test face authentication when not available."""
        success, result = self.biometric_auth.authenticate({
            'method': 'face'
        })
        
        assert success is False
        assert "Face authentication failed" in result


class TestSessionManager:
    """Test cases for SessionManager."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.session_manager = SessionManager()
    
    def test_initialization(self):
        """Test proper initialization of SessionManager."""
        assert self.session_manager.current_session is None
        assert self.session_manager.failed_attempts == {}
    
    def test_create_session(self):
        """Test session creation."""
        session = self.session_manager.create_session(
            username='testuser',
            auth_method='email_password',
            user_role='user'
        )
        
        assert session['username'] == 'testuser'
        assert session['auth_method'] == 'email_password'
        assert session['role'] == 'user'
        assert 'login_time' in session
        assert 'last_activity' in session
    
    def test_is_session_valid_no_session(self):
        """Test session validity check with no session."""
        result = self.session_manager.is_session_valid()
        assert result is False
    
    def test_add_failed_attempt(self):
        """Test adding failed login attempts."""
        username = 'testuser'
        
        # Add first attempt
        self.session_manager.add_failed_attempt(username)
        assert self.session_manager.failed_attempts[username]['count'] == 1
        
        # Add more attempts
        for i in range(2, Config.MAX_LOGIN_ATTEMPTS + 1):
            self.session_manager.add_failed_attempt(username)
        
        # User should be locked out after max attempts
        assert self.session_manager.is_user_locked_out(username) is True
    
    def test_clear_session(self):
        """Test session clearing."""
        # Create a session first
        self.session_manager.create_session('testuser', 'email_password')
        assert self.session_manager.current_session is not None
        
        # Clear the session
        self.session_manager.clear_session()
        assert self.session_manager.current_session is None
    
    def test_lock_unlock_session(self):
        """Test session locking and unlocking."""
        # Create a session
        self.session_manager.create_session('testuser', 'email_password')
        
        # Lock the session
        self.session_manager.lock_session()
        assert self.session_manager.current_session['is_locked'] is True
        
        # Session should be invalid when locked
        assert self.session_manager.is_session_valid() is False
        
        # Unlock the session
        result = self.session_manager.unlock_session()
        assert result is True
        assert self.session_manager.current_session['is_locked'] is False


@pytest.fixture
def temp_config():
    """Fixture to provide temporary configuration for testing."""
    original_values = {}
    
    # Store original values
    for attr in ['AUTHENTICATION_REQUIRED', 'SESSION_TIMEOUT', 'MAX_LOGIN_ATTEMPTS']:
        if hasattr(Config, attr):
            original_values[attr] = getattr(Config, attr)
    
    yield Config
    
    # Restore original values
    for attr, value in original_values.items():
        setattr(Config, attr, value)


class TestIntegration:
    """Integration tests for authentication system."""
    
    def test_full_authentication_flow(self, temp_config):
        """Test complete authentication flow."""
        # Disable actual authentication for testing
        temp_config.AUTHENTICATION_REQUIRED = True
        
        auth_manager = AuthenticationManager()
        
        # Test that components are properly integrated
        assert auth_manager.ldap_auth is not None
        assert auth_manager.biometric_auth is not None
        assert auth_manager.session_manager is not None
        
        # Test authentication method routing
        success, result = auth_manager.authenticate_with_method('ldap', {
            'username': 'test',
            'password': 'test'
        })
        # This should fail with real LDAP, but should not crash
        assert isinstance(success, bool)
        assert isinstance(result, str)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
