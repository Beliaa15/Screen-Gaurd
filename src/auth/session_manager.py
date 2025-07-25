"""
Session Management Module
"""

import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

from ..core.config import Config
from ..utils.security_utils import SecurityUtils


class SessionManager:
    """Manages user sessions and security state."""
    
    def __init__(self):
        self.current_session = None
        self.session_file = Path("current_session.json")
        self.failed_attempts = {}  # Track failed login attempts
        self.monitoring_active = False
        self.monitoring_thread = None
        
    def create_session(self, username: str, auth_method: str, user_role: str = "user") -> Dict[str, Any]:
        """Create a new user session."""
        session_data = {
            'username': username,
            'role': user_role,
            'auth_method': auth_method,
            'login_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'session_timeout': Config.SESSION_TIMEOUT,
            'is_locked': False
        }
        
        self.current_session = session_data
        self.save_session()
        
        SecurityUtils.log_security_event("SESSION_CREATED", 
                                       f"New session created for {username} using {auth_method}")
        
        return session_data
    
    def save_session(self):
        """Save current session to file."""
        if self.current_session:
            try:
                with open(self.session_file, 'w') as f:
                    json.dump(self.current_session, f, indent=2)
            except Exception as e:
                print(f"Error saving session: {e}")
    
    def load_session(self) -> bool:
        """Load session from file."""
        try:
            if self.session_file.exists():
                with open(self.session_file, 'r') as f:
                    self.current_session = json.load(f)
                return True
        except Exception as e:
            print(f"Error loading session: {e}")
        
        return False
    
    def update_activity(self):
        """Update last activity timestamp."""
        if self.current_session:
            self.current_session['last_activity'] = datetime.now().isoformat()
            self.save_session()
    
    def is_session_valid(self) -> bool:
        """Check if current session is valid."""
        if not self.current_session:
            return False
        
        if self.current_session.get('is_locked', False):
            return False
        
        try:
            last_activity = datetime.fromisoformat(self.current_session['last_activity'])
            session_timeout = self.current_session.get('session_timeout', Config.SESSION_TIMEOUT)
            
            # Check if session has expired
            if (datetime.now() - last_activity).total_seconds() > session_timeout:
                SecurityUtils.log_security_event("SESSION_EXPIRED", 
                                               f"Session expired for {self.current_session['username']}")
                return False
            
            return True
            
        except Exception as e:
            print(f"Error checking session validity: {e}")
            return False
    
    def lock_session(self):
        """Lock the current session."""
        if self.current_session:
            self.current_session['is_locked'] = True
            self.current_session['lock_time'] = datetime.now().isoformat()
            self.save_session()
            SecurityUtils.log_security_event("SESSION_LOCKED", 
                                           f"Session locked for {self.current_session['username']}")
    
    def unlock_session(self) -> bool:
        """Unlock the current session."""
        if self.current_session and self.current_session.get('is_locked', False):
            self.current_session['is_locked'] = False
            self.current_session['unlock_time'] = datetime.now().isoformat()
            self.update_activity()
            SecurityUtils.log_security_event("SESSION_UNLOCKED", 
                                           f"Session unlocked for {self.current_session['username']}")
            return True
        return False
    
    def clear_session(self):
        """Clear the current session."""
        if self.current_session:
            username = self.current_session.get('username', 'unknown')
            SecurityUtils.log_security_event("SESSION_CLEARED", f"Session cleared for {username}")
        
        self.current_session = None
        if self.session_file.exists():
            try:
                self.session_file.unlink()
            except Exception as e:
                print(f"Error deleting session file: {e}")
    
    def add_failed_attempt(self, username: str):
        """Record a failed login attempt."""
        now = datetime.now()
        
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {
                'count': 0,
                'last_attempt': now,
                'lockout_until': None
            }
        
        self.failed_attempts[username]['count'] += 1
        self.failed_attempts[username]['last_attempt'] = now
        
        # Check if user should be locked out
        if self.failed_attempts[username]['count'] >= Config.MAX_LOGIN_ATTEMPTS:
            lockout_until = now + timedelta(seconds=Config.LOGIN_LOCKOUT_DURATION)
            self.failed_attempts[username]['lockout_until'] = lockout_until
            
            SecurityUtils.log_security_event("USER_LOCKED_OUT", 
                                           f"User {username} locked out due to {Config.MAX_LOGIN_ATTEMPTS} failed attempts")
    
    def is_user_locked_out(self, username: str) -> bool:
        """Check if a user is currently locked out."""
        if username not in self.failed_attempts:
            return False
        
        lockout_until = self.failed_attempts[username].get('lockout_until')
        if lockout_until and datetime.now() < lockout_until:
            return True
        
        # Clear lockout if time has passed
        if lockout_until and datetime.now() >= lockout_until:
            self.failed_attempts[username]['count'] = 0
            self.failed_attempts[username]['lockout_until'] = None
        
        return False
    
    def get_lockout_remaining_time(self, username: str) -> int:
        """Get remaining lockout time in seconds."""
        if username not in self.failed_attempts:
            return 0
        
        lockout_until = self.failed_attempts[username].get('lockout_until')
        if lockout_until and datetime.now() < lockout_until:
            return int((lockout_until - datetime.now()).total_seconds())
        
        return 0
    
    def start_session_monitoring(self):
        """Start monitoring session for expiry and inactivity."""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def stop_session_monitoring(self):
        """Stop session monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
    
    def _monitoring_loop(self):
        """Session monitoring loop."""
        while self.monitoring_active:
            try:
                if self.current_session and not self.is_session_valid():
                    SecurityUtils.log_security_event("SESSION_AUTO_EXPIRED", 
                                                   "Session automatically expired due to inactivity")
                    self.clear_session()
                
                time.sleep(Config.SESSION_CHECK_INTERVAL)
                
            except Exception as e:
                print(f"Session monitoring error: {e}")
                time.sleep(5)  # Brief pause before retrying
    
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """Get current session information."""
        if not self.current_session:
            return None
        
        session_info = self.current_session.copy()
        
        # Add computed fields
        if 'login_time' in session_info:
            login_time = datetime.fromisoformat(session_info['login_time'])
            session_info['session_duration'] = str(datetime.now() - login_time)
        
        if 'last_activity' in session_info:
            last_activity = datetime.fromisoformat(session_info['last_activity'])
            session_info['time_since_activity'] = str(datetime.now() - last_activity)
        
        return session_info
