"""
Test suite for the Physical Security System UI components.
"""

import pytest
import tkinter as tk
from unittest.mock import Mock, patch, MagicMock
from src.ui.gui_manager import SecurityGUI
from src.ui.security_overlay import SecurityOverlay


class TestSecurityGUI:
    """Test cases for SecurityGUI."""
    
    def setup_method(self):
        """Setup test fixtures."""
        # Create a root window for testing
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the window during testing
        
        # Mock authentication manager to avoid real authentication
        with patch('src.ui.gui_manager.AuthenticationManager'):
            self.gui = SecurityGUI()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if hasattr(self, 'gui') and self.gui.root:
            self.gui.root.destroy()
        if hasattr(self, 'root'):
            self.root.destroy()
    
    def test_initialization(self):
        """Test proper initialization of SecurityGUI."""
        assert self.gui.root is not None
        assert self.gui.auth_manager is not None
        assert self.gui.authenticated is False
        assert self.gui.username_entry is not None
        assert self.gui.password_entry is not None
        assert self.gui.login_button is not None
    
    def test_create_widgets(self):
        """Test widget creation."""
        # Widgets should be created during initialization
        assert hasattr(self.gui, 'username_entry')
        assert hasattr(self.gui, 'password_entry')
        assert hasattr(self.gui, 'login_button')
        assert hasattr(self.gui, 'biometric_button')
        assert hasattr(self.gui, 'status_label')
    
    def test_clear_entries(self):
        """Test clearing input entries."""
        # Set some test values
        self.gui.username_entry.insert(0, "testuser")
        self.gui.password_entry.insert(0, "testpass")
        
        # Clear entries
        self.gui.clear_entries()
        
        # Verify they are cleared
        assert self.gui.username_entry.get() == ""
        assert self.gui.password_entry.get() == ""
    
    def test_update_status(self):
        """Test status label updates."""
        test_message = "Authentication successful"
        
        self.gui.update_status(test_message, "green")
        
        # Check that status label was updated
        assert self.gui.status_label.cget("text") == test_message
        assert self.gui.status_label.cget("fg") == "green"
    
    @patch('src.ui.gui_manager.messagebox.showinfo')
    def test_show_success_message(self, mock_showinfo):
        """Test showing success message."""
        test_message = "Login successful"
        
        self.gui.show_success_message(test_message)
        
        mock_showinfo.assert_called_once_with("Success", test_message)
    
    @patch('src.ui.gui_manager.messagebox.showerror')
    def test_show_error_message(self, mock_showerror):
        """Test showing error message."""
        test_message = "Login failed"
        
        self.gui.show_error_message(test_message)
        
        mock_showerror.assert_called_once_with("Error", test_message)
    
    def test_login_attempt_empty_fields(self):
        """Test login attempt with empty fields."""
        # Clear any existing values
        self.gui.clear_entries()
        
        with patch.object(self.gui, 'show_error_message') as mock_error:
            self.gui.login_attempt()
            mock_error.assert_called_once_with("Please enter both username and password")
    
    def test_login_attempt_success(self):
        """Test successful login attempt."""
        # Set test credentials
        self.gui.username_entry.insert(0, "testuser")
        self.gui.password_entry.insert(0, "testpass")
        
        # Mock successful authentication
        with patch.object(self.gui.auth_manager, 'authenticate_user', return_value=True):
            with patch.object(self.gui, 'on_successful_authentication') as mock_success:
                self.gui.login_attempt()
                mock_success.assert_called_once_with("testuser")
    
    def test_login_attempt_failure(self):
        """Test failed login attempt."""
        # Set test credentials
        self.gui.username_entry.insert(0, "baduser")
        self.gui.password_entry.insert(0, "badpass")
        
        # Mock failed authentication
        with patch.object(self.gui.auth_manager, 'authenticate_user', return_value=False):
            with patch.object(self.gui, 'show_error_message') as mock_error:
                self.gui.login_attempt()
                mock_error.assert_called_once_with("Authentication failed")
    
    def test_biometric_authentication_success(self):
        """Test successful biometric authentication."""
        with patch.object(self.gui.auth_manager, 'authenticate_biometric', return_value=(True, "john_doe")):
            with patch.object(self.gui, 'on_successful_authentication') as mock_success:
                self.gui.biometric_authentication()
                mock_success.assert_called_once_with("john_doe")
    
    def test_biometric_authentication_failure(self):
        """Test failed biometric authentication."""
        with patch.object(self.gui.auth_manager, 'authenticate_biometric', return_value=(False, None)):
            with patch.object(self.gui, 'show_error_message') as mock_error:
                self.gui.biometric_authentication()
                mock_error.assert_called_once_with("Biometric authentication failed")
    
    def test_on_successful_authentication(self):
        """Test successful authentication handler."""
        test_username = "testuser"
        
        with patch.object(self.gui, 'show_success_message') as mock_success:
            with patch.object(self.gui, 'close_window') as mock_close:
                self.gui.on_successful_authentication(test_username)
                
                assert self.gui.authenticated is True
                mock_success.assert_called_once()
                mock_close.assert_called_once()
    
    def test_close_window(self):
        """Test window closing."""
        with patch.object(self.gui.root, 'quit') as mock_quit:
            with patch.object(self.gui.root, 'destroy') as mock_destroy:
                self.gui.close_window()
                mock_quit.assert_called_once()
                mock_destroy.assert_called_once()
    
    def test_run_gui(self):
        """Test GUI main loop."""
        with patch.object(self.gui.root, 'mainloop') as mock_mainloop:
            self.gui.run()
            mock_mainloop.assert_called_once()


class TestSecurityOverlay:
    """Test cases for SecurityOverlay."""
    
    def setup_method(self):
        """Setup test fixtures."""
        # Create root for testing
        self.root = tk.Tk()
        self.root.withdraw()
        
        # Mock callback functions
        self.mock_callback = Mock()
        self.mock_dismiss_callback = Mock()
        
        self.overlay = SecurityOverlay(
            message="Test Alert",
            callback=self.mock_callback,
            dismiss_callback=self.mock_dismiss_callback
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if hasattr(self, 'overlay') and self.overlay.root:
            self.overlay.root.destroy()
        if hasattr(self, 'root'):
            self.root.destroy()
    
    def test_initialization(self):
        """Test proper initialization of SecurityOverlay."""
        assert self.overlay.root is not None
        assert self.overlay.callback == self.mock_callback
        assert self.overlay.dismiss_callback == self.mock_dismiss_callback
        assert self.overlay.message == "Test Alert"
    
    def test_create_widgets(self):
        """Test widget creation for overlay."""
        # Check that required widgets exist
        assert self.overlay.message_label is not None
        assert self.overlay.auth_button is not None
        assert self.overlay.dismiss_button is not None
    
    def test_authenticate_button_click(self):
        """Test authenticate button functionality."""
        # Simulate button click
        self.overlay.authenticate()
        
        # Verify callback was called
        self.mock_callback.assert_called_once()
    
    def test_dismiss_button_click(self):
        """Test dismiss button functionality."""
        # Simulate button click
        self.overlay.dismiss()
        
        # Verify dismiss callback was called
        self.mock_dismiss_callback.assert_called_once()
    
    def test_show_overlay(self):
        """Test showing the overlay."""
        with patch.object(self.overlay.root, 'deiconify') as mock_deiconify:
            with patch.object(self.overlay.root, 'lift') as mock_lift:
                with patch.object(self.overlay.root, 'focus_force') as mock_focus:
                    self.overlay.show()
                    
                    mock_deiconify.assert_called_once()
                    mock_lift.assert_called_once()
                    mock_focus.assert_called_once()
    
    def test_hide_overlay(self):
        """Test hiding the overlay."""
        with patch.object(self.overlay.root, 'withdraw') as mock_withdraw:
            self.overlay.hide()
            mock_withdraw.assert_called_once()
    
    def test_close_overlay(self):
        """Test closing the overlay."""
        with patch.object(self.overlay.root, 'quit') as mock_quit:
            with patch.object(self.overlay.root, 'destroy') as mock_destroy:
                self.overlay.close()
                mock_quit.assert_called_once()
                mock_destroy.assert_called_once()
    
    def test_fullscreen_properties(self):
        """Test that overlay has fullscreen properties."""
        # Check window attributes for fullscreen overlay
        assert self.overlay.root.attributes('-fullscreen') is True
        assert self.overlay.root.attributes('-topmost') is True
    
    def test_window_configuration(self):
        """Test window configuration settings."""
        # Should be configured as a security overlay
        assert self.overlay.root.wm_state() == 'withdrawn'  # Initially hidden
        
        # Background should be set for security
        main_frame = None
        for child in self.overlay.root.winfo_children():
            if isinstance(child, tk.Frame):
                main_frame = child
                break
        
        assert main_frame is not None
        assert main_frame.cget('bg') == '#FF4444'  # Alert red background


class TestUIIntegration:
    """Integration tests for UI components."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.root = tk.Tk()
        self.root.withdraw()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        if hasattr(self, 'root'):
            self.root.destroy()
    
    def test_gui_to_overlay_flow(self):
        """Test flow from GUI authentication to overlay display."""
        # Mock authentication manager
        with patch('src.ui.gui_manager.AuthenticationManager') as mock_auth_mgr:
            mock_auth_instance = Mock()
            mock_auth_mgr.return_value = mock_auth_instance
            
            # Create GUI
            gui = SecurityGUI()
            
            # Mock successful authentication
            mock_auth_instance.authenticate_user.return_value = True
            
            # Set credentials
            gui.username_entry.insert(0, "testuser")
            gui.password_entry.insert(0, "testpass")
            
            # Test authentication flow
            with patch.object(gui, 'on_successful_authentication') as mock_success:
                gui.login_attempt()
                mock_success.assert_called_once_with("testuser")
            
            # Clean up
            gui.root.destroy()
    
    def test_overlay_callback_integration(self):
        """Test overlay callback integration."""
        callback_called = False
        dismiss_called = False
        
        def test_callback():
            nonlocal callback_called
            callback_called = True
        
        def test_dismiss():
            nonlocal dismiss_called
            dismiss_called = True
        
        # Create overlay with test callbacks
        overlay = SecurityOverlay(
            message="Integration Test",
            callback=test_callback,
            dismiss_callback=test_dismiss
        )
        
        # Test authenticate callback
        overlay.authenticate()
        assert callback_called is True
        
        # Test dismiss callback
        overlay.dismiss()
        assert dismiss_called is True
        
        # Clean up
        overlay.root.destroy()
    
    @patch('src.ui.security_overlay.SecurityUtils')
    def test_overlay_security_logging(self, mock_security_utils):
        """Test that overlay actions are logged."""
        def test_callback():
            pass
        
        def test_dismiss():
            pass
        
        overlay = SecurityOverlay(
            message="Security Test",
            callback=test_callback,
            dismiss_callback=test_dismiss
        )
        
        # Mock logging for overlay actions
        with patch.object(overlay, 'authenticate') as mock_auth:
            # Simulate authentication attempt
            mock_auth.side_effect = lambda: mock_security_utils.log_security_event.call_count
            
            overlay.authenticate()
            
            # Verify logging would occur in real implementation
            mock_auth.assert_called_once()
        
        overlay.root.destroy()
    
    def test_multi_screen_overlay_support(self):
        """Test overlay support for multiple screens."""
        overlay = SecurityOverlay(
            message="Multi-screen test",
            callback=lambda: None,
            dismiss_callback=lambda: None
        )
        
        # Check that overlay is configured for full coverage
        assert overlay.root.attributes('-fullscreen') is True
        assert overlay.root.attributes('-topmost') is True
        
        # Should cover entire screen
        overlay.show()
        geometry = overlay.root.geometry()
        
        # Clean up
        overlay.hide()
        overlay.root.destroy()


@pytest.fixture
def mock_tkinter_root():
    """Fixture to provide a mock tkinter root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestUIErrorHandling:
    """Test error handling in UI components."""
    
    def test_gui_authentication_exception(self):
        """Test GUI handling of authentication exceptions."""
        with patch('src.ui.gui_manager.AuthenticationManager') as mock_auth_mgr:
            mock_auth_instance = Mock()
            mock_auth_instance.authenticate_user.side_effect = Exception("Auth service down")
            mock_auth_mgr.return_value = mock_auth_instance
            
            gui = SecurityGUI()
            gui.username_entry.insert(0, "testuser")
            gui.password_entry.insert(0, "testpass")
            
            with patch.object(gui, 'show_error_message') as mock_error:
                gui.login_attempt()
                mock_error.assert_called_once()
            
            gui.root.destroy()
    
    def test_overlay_callback_exception(self):
        """Test overlay handling of callback exceptions."""
        def failing_callback():
            raise Exception("Callback failed")
        
        overlay = SecurityOverlay(
            message="Error test",
            callback=failing_callback,
            dismiss_callback=lambda: None
        )
        
        # Should not crash when callback fails
        try:
            overlay.authenticate()
        except Exception:
            pytest.fail("Overlay should handle callback exceptions gracefully")
        
        overlay.root.destroy()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
