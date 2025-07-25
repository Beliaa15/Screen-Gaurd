"""
Main Authentication Manager
"""

import queue
import threading
import tkinter as tk
from typing import Optional, Tuple, Dict, Any

from ..core.config import Config
from ..utils.security_utils import SecurityUtils
from .ldap_auth import LDAPAuthenticator
from .biometric_auth import BiometricAuthenticator
from .session_manager import SessionManager


class AuthenticationManager:
    """Main authentication manager coordinating all authentication methods."""
    
    def __init__(self):
        self.ldap_auth = LDAPAuthenticator(Config())
        self.biometric_auth = BiometricAuthenticator()
        self.session_manager = SessionManager()
        self.monitoring_thread = None
        self.stop_monitoring = False
        
    def require_authentication(self) -> bool:
        """Main method to require authentication before device access."""
        if not Config.AUTHENTICATION_REQUIRED:
            return True
        
        # Check if there's a valid existing session
        if self.session_manager.load_session() and self.session_manager.is_session_valid():
            SecurityUtils.log_security_event("SESSION_VALID", 
                                           f"Valid session found for {self.session_manager.current_session['username']}")
            self.start_session_monitoring()
            return True
        
        # Try GUI authentication first, fall back to console if it fails
        try:
            return self._try_gui_authentication()
        except Exception as e:
            SecurityUtils.log_security_event("GUI_AUTH_FAILED", f"GUI authentication failed: {e}")
            print(f"⚠️  GUI authentication unavailable: {e}")
            print("Falling back to console authentication...")
            return self._try_console_authentication()
    
    def _try_gui_authentication(self) -> bool:
        """Try GUI-based authentication with timeout."""
        
        # Use a queue to get result from GUI thread
        result_queue = queue.Queue()
        
        def gui_auth_thread():
            try:
                # Create a simpler, non-blocking authentication dialog
                auth_result = self._show_simple_auth_dialog()
                result_queue.put(auth_result)
            except Exception as e:
                result_queue.put(None)
        
        # Start GUI authentication in thread
        gui_thread = threading.Thread(target=gui_auth_thread, daemon=True)
        gui_thread.start()
        
        # Wait for result with timeout
        try:
            auth_result = result_queue.get(timeout=30)  # 30 second timeout
            if auth_result:
                self.start_session_monitoring()
                return True
            return False
        except queue.Empty:
            print("⚠️  GUI authentication timed out")
            return False
    
    def _show_simple_auth_dialog(self):
        """Show a simple, non-blocking authentication dialog."""
        from tkinter import simpledialog, messagebox
        
        # Create a simple root window
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        
        try:
            # Simple email input
            email = simpledialog.askstring("Authentication", "Enter your email:", parent=root)
            if not email:
                return None
                
            # Simple password input
            password = simpledialog.askstring("Authentication", "Enter your password:", show='*', parent=root)
            if not password:
                return None
            
            # Try LDAP authentication
            success, result = self.ldap_auth.authenticate({
                'username': email.split('@')[0],  # Extract username from email
                'password': password
            })
            
            if success:
                if isinstance(result, dict):
                    username = result['username']
                    role = result['role']
                else:
                    username = email.split('@')[0]
                    role = 'user'
                
                # Create session
                self.session_manager.create_session(username, 'email_password', role)
                messagebox.showinfo("Success", f"Authentication successful!\nWelcome, {username}", parent=root)
                return True
            else:
                messagebox.showerror("Error", f"Authentication failed: {result}", parent=root)
                return False
                
        finally:
            root.destroy()
    
    def _try_console_authentication(self) -> bool:
        """Console-based authentication as fallback."""
        print("\n🔐 CONSOLE AUTHENTICATION")
        print("Available methods: Email & Password")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            print(f"\nAttempt {attempt + 1}/{max_attempts}")
            
            try:
                username = input("Username: ").strip()
                if not username:
                    continue
                
                import getpass
                password = getpass.getpass("Password: ")
                
                # Check if user is locked out
                if self.session_manager.is_user_locked_out(username):
                    remaining = self.session_manager.get_lockout_remaining_time(username)
                    print(f"❌ User locked out. Try again in {remaining} seconds.")
                    continue
                
                # Try LDAP authentication
                success, result = self.ldap_auth.authenticate({
                    'username': username,
                    'password': password
                })
                
                if success:
                    if isinstance(result, dict):
                        role = result['role']
                    else:
                        role = 'user'
                    
                    # Create session
                    self.session_manager.create_session(username, 'email_password', role)
                    print(f"✅ Authentication successful! Welcome, {username}")
                    self.start_session_monitoring()
                    return True
                else:
                    print(f"❌ Authentication failed: {result}")
                    self.session_manager.add_failed_attempt(username)
                    
            except KeyboardInterrupt:
                print("\n🛑 Authentication cancelled by user")
                return False
            except Exception as e:
                print(f"❌ Authentication error: {e}")
        
        print("❌ Maximum authentication attempts exceeded")
        return False
    
    def start_session_monitoring(self):
        """Start monitoring user session."""
        self.session_manager.start_session_monitoring()
        
        if not self.stop_monitoring:
            self.monitoring_thread = threading.Thread(target=self._session_monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def _session_monitoring_loop(self):
        """Monitor session for security events."""
        while not self.stop_monitoring and self.session_manager.current_session:
            try:
                # Check session validity
                if not self.session_manager.is_session_valid():
                    SecurityUtils.log_security_event("SESSION_INVALID", "Session became invalid during monitoring")
                    break
                
                # Add additional monitoring logic here
                threading.Event().wait(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Session monitoring error: {e}")
                break
    
    def stop_session_monitoring(self):
        """Stop session monitoring."""
        self.stop_monitoring = True
        self.session_manager.stop_session_monitoring()
    
    def logout(self):
        """Logout current user."""
        self.stop_session_monitoring()
        self.session_manager.clear_session()
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated."""
        return (self.session_manager.current_session is not None and 
                self.session_manager.is_session_valid())
    
    def update_activity(self):
        """Update user activity timestamp."""
        self.session_manager.update_activity()
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user."""
        if self.session_manager.current_session:
            return self.session_manager.current_session.get('username')
        return None
    
    def get_current_role(self) -> Optional[str]:
        """Get current user's role."""
        if self.session_manager.current_session:
            return self.session_manager.current_session.get('role')
        return None
    
    def register_user_face(self, username: str, image_path: str = None) -> bool:
        """Register a user's face for biometric authentication."""
        return self.biometric_auth.register_face(username, image_path)
    
    def authenticate_with_method(self, method: str, credentials: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Authenticate using a specific method."""
        if method == 'ldap' or method == 'email_password':
            return self.ldap_auth.authenticate(credentials)
        elif method == 'biometric':
            return self.biometric_auth.authenticate(credentials)
        else:
            return False, f"Unknown authentication method: {method}"
