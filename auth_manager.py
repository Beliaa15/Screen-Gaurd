"""
Advanced Authentication Manager for Physical Security System

This module provides comprehensive authentication services including:
- LDAP email/password authentication
- Windows Hello fingerprint authentication
- Face recognition authentication
- Session management and security overlay
"""

import os
import time
import json
import pickle
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Any
import tkinter as tk
from tkinter import messagebox, simpledialog
import cv2
import numpy as np

# Import authentication libraries
try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False
    print("Face recognition not available. Install face-recognition library.")

try:
    import win32security
    import win32api
    import win32con
    WINDOWS_AUTH_AVAILABLE = True
except ImportError:
    WINDOWS_AUTH_AVAILABLE = False
    print("Windows authentication not available. Install pywin32 library.")

from config import Config
from security_utils import SecurityUtils, LDAPAuthenticator


class BiometricAuthenticator:
    """Handles biometric authentication (face and fingerprint)."""
    
    def __init__(self):
        self.face_encodings_db = {}
        self.face_data_dir = Path(Config.FACE_IMAGES_DIR)
        self.face_data_dir.mkdir(exist_ok=True)
        self.load_face_encodings()
        
    def load_face_encodings(self):
        """Load face encodings from database."""
        encoding_file = self.face_data_dir / "face_encodings.pkl"
        if encoding_file.exists():
            try:
                with open(encoding_file, 'rb') as f:
                    self.face_encodings_db = pickle.load(f)
                SecurityUtils.log_security_event("FACE_DB_LOADED", f"Loaded {len(self.face_encodings_db)} face encodings")
            except Exception as e:
                SecurityUtils.log_security_event("FACE_DB_LOAD_ERROR", f"Error loading face encodings: {e}")
                self.face_encodings_db = {}
    
    def save_face_encodings(self):
        """Save face encodings to database."""
        encoding_file = self.face_data_dir / "face_encodings.pkl"
        try:
            with open(encoding_file, 'wb') as f:
                pickle.dump(self.face_encodings_db, f)
            SecurityUtils.log_security_event("FACE_DB_SAVED", f"Saved {len(self.face_encodings_db)} face encodings")
        except Exception as e:
            SecurityUtils.log_security_event("FACE_DB_SAVE_ERROR", f"Error saving face encodings: {e}")
    
    def register_face(self, username: str, image_path: str = None) -> bool:
        """Register a new face for a user."""
        if not FACE_RECOGNITION_AVAILABLE:
            return False
            
        try:
            if image_path:
                image = face_recognition.load_image_file(image_path)
            else:
                # Capture from camera
                image = self.capture_face_from_camera()
                if image is None:
                    return False
            
            face_encodings = face_recognition.face_encodings(image, model=Config.FACE_ENCODING_MODEL)
            
            if len(face_encodings) == 0:
                SecurityUtils.log_security_event("FACE_REGISTRATION_FAILED", f"No face detected for user {username}")
                return False
            
            if len(face_encodings) > 1:
                SecurityUtils.log_security_event("FACE_REGISTRATION_FAILED", f"Multiple faces detected for user {username}")
                return False
            
            # Store the face encoding
            self.face_encodings_db[username] = face_encodings[0]
            self.save_face_encodings()
            
            SecurityUtils.log_security_event("FACE_REGISTERED", f"Face registered successfully for user {username}")
            return True
            
        except Exception as e:
            SecurityUtils.log_security_event("FACE_REGISTRATION_ERROR", f"Error registering face for {username}: {e}")
            return False
    
    def capture_face_from_camera(self) -> Optional[np.ndarray]:
        """Capture face image from camera for registration."""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        
        print("Look at the camera and press SPACE to capture your face, ESC to cancel")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
                
            # Display the frame
            cv2.imshow('Face Registration - Press SPACE to capture, ESC to cancel', frame)
            
            key = cv2.waitKey(1) & 0xFF
            if key == 32:  # Space key
                # Convert BGR to RGB for face_recognition
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                cap.release()
                cv2.destroyAllWindows()
                return rgb_frame
            elif key == 27:  # Escape key
                break
        
        cap.release()
        cv2.destroyAllWindows()
        return None
    
    def authenticate_face(self, timeout: int = 30) -> Optional[str]:
        """Authenticate user using face recognition."""
        if not FACE_RECOGNITION_AVAILABLE or not self.face_encodings_db:
            return None
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            SecurityUtils.log_security_event("FACE_AUTH_FAILED", "Camera not available for face authentication")
            return None
        
        start_time = time.time()
        SecurityUtils.log_security_event("FACE_AUTH_STARTED", "Face authentication started")
        
        try:
            while time.time() - start_time < timeout:
                ret, frame = cap.read()
                if not ret:
                    continue
                
                # Convert BGR to RGB
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
                # Find face locations and encodings
                face_locations = face_recognition.face_locations(rgb_frame)
                if not face_locations:
                    continue
                
                face_encodings = face_recognition.face_encodings(rgb_frame, face_locations, model=Config.FACE_ENCODING_MODEL)
                
                for face_encoding in face_encodings:
                    # Compare with stored encodings
                    for username, stored_encoding in self.face_encodings_db.items():
                        matches = face_recognition.compare_faces([stored_encoding], face_encoding, tolerance=Config.FACE_RECOGNITION_TOLERANCE)
                        
                        if matches[0]:
                            cap.release()
                            cv2.destroyAllWindows()
                            SecurityUtils.log_security_event("FACE_AUTH_SUCCESS", f"Face authentication successful for user {username}")
                            return username
                
                # Display frame with face detection
                for (top, right, bottom, left) in face_locations:
                    cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
                
                cv2.imshow('Face Authentication - Look at camera', frame)
                if cv2.waitKey(1) & 0xFF == 27:  # Escape key
                    break
            
        except Exception as e:
            SecurityUtils.log_security_event("FACE_AUTH_ERROR", f"Error during face authentication: {e}")
        finally:
            cap.release()
            cv2.destroyAllWindows()
        
        SecurityUtils.log_security_event("FACE_AUTH_FAILED", "Face authentication failed or timed out")
        return None
    
    def authenticate_fingerprint(self) -> Optional[str]:
        """Authenticate user using Windows Hello fingerprint."""
        if not WINDOWS_AUTH_AVAILABLE:
            SecurityUtils.log_security_event("FINGERPRINT_AUTH_UNAVAILABLE", "Windows authentication not available")
            return None
        
        try:
            SecurityUtils.log_security_event("FINGERPRINT_AUTH_STARTED", "Fingerprint authentication started")
            
            # Use Windows Hello API for fingerprint authentication
            # This is a simplified implementation - in production, you'd use Windows Biometric Framework
            result = messagebox.askyesno(
                "Fingerprint Authentication",
                "Please use your fingerprint reader to authenticate.\n\nClick Yes after successful fingerprint scan, No to cancel."
            )
            
            if result:
                # In a real implementation, you would:
                # 1. Interface with Windows Biometric Framework
                # 2. Get the authenticated user from Windows
                # 3. Map it to your user database
                
                # For now, we'll simulate successful fingerprint auth
                # and return the current Windows user
                current_user = win32api.GetUserName()
                SecurityUtils.log_security_event("FINGERPRINT_AUTH_SUCCESS", f"Fingerprint authentication successful for user {current_user}")
                return current_user
            else:
                SecurityUtils.log_security_event("FINGERPRINT_AUTH_CANCELLED", "Fingerprint authentication cancelled by user")
                return None
                
        except Exception as e:
            SecurityUtils.log_security_event("FINGERPRINT_AUTH_ERROR", f"Error during fingerprint authentication: {e}")
            return None


class SessionManager:
    """Manages user sessions and security overlay."""
    
    def __init__(self):
        self.current_session = None
        self.session_start_time = None
        self.last_activity_time = None
        self.session_file = Path("current_session.json")
        self.is_locked = True
        self.failed_attempts = {}
        self.lockout_times = {}
        
    def create_session(self, username: str, auth_method: str, user_role: str = "user") -> Dict[str, Any]:
        """Create a new authenticated session."""
        session_id = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()[:16]
        
        self.current_session = {
            'session_id': session_id,
            'username': username,
            'auth_method': auth_method,
            'user_role': user_role,
            'login_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'is_active': True
        }
        
        self.session_start_time = time.time()
        self.last_activity_time = time.time()
        self.is_locked = False
        
        # Save session to file
        self.save_session()
        
        SecurityUtils.log_security_event("SESSION_CREATED", f"Session created for {username} using {auth_method}")
        return self.current_session
    
    def save_session(self):
        """Save current session to file."""
        if self.current_session:
            try:
                with open(self.session_file, 'w') as f:
                    json.dump(self.current_session, f, indent=2)
            except Exception as e:
                SecurityUtils.log_security_event("SESSION_SAVE_ERROR", f"Error saving session: {e}")
    
    def load_session(self) -> bool:
        """Load session from file if valid."""
        if not self.session_file.exists():
            return False
        
        try:
            with open(self.session_file, 'r') as f:
                session_data = json.load(f)
            
            # Check if session is still valid
            login_time = datetime.fromisoformat(session_data['login_time'])
            if datetime.now() - login_time > timedelta(seconds=Config.SESSION_TIMEOUT):
                SecurityUtils.log_security_event("SESSION_EXPIRED", f"Session expired for {session_data['username']}")
                self.clear_session()
                return False
            
            self.current_session = session_data
            self.session_start_time = time.time()
            self.last_activity_time = time.time()
            self.is_locked = False
            
            SecurityUtils.log_security_event("SESSION_RESTORED", f"Session restored for {session_data['username']}")
            return True
            
        except Exception as e:
            SecurityUtils.log_security_event("SESSION_LOAD_ERROR", f"Error loading session: {e}")
            return False
    
    def update_activity(self):
        """Update last activity time."""
        if self.current_session:
            self.last_activity_time = time.time()
            self.current_session['last_activity'] = datetime.now().isoformat()
            self.save_session()
    
    def is_session_valid(self) -> bool:
        """Check if current session is valid."""
        if not self.current_session or self.is_locked:
            return False
        
        current_time = time.time()
        
        # Check session timeout
        if current_time - self.session_start_time > Config.SESSION_TIMEOUT:
            SecurityUtils.log_security_event("SESSION_TIMEOUT", f"Session timed out for {self.current_session['username']}")
            self.clear_session()
            return False
        
        # Check idle timeout
        if current_time - self.last_activity_time > Config.IDLE_TIMEOUT:
            SecurityUtils.log_security_event("SESSION_IDLE_TIMEOUT", f"Session idle timeout for {self.current_session['username']}")
            self.lock_session()
            return False
        
        return True
    
    def lock_session(self):
        """Lock the current session due to inactivity."""
        self.is_locked = True
        if self.current_session:
            SecurityUtils.log_security_event("SESSION_LOCKED", f"Session locked for {self.current_session['username']}")
    
    def unlock_session(self) -> bool:
        """Unlock session - requires re-authentication."""
        if not self.current_session:
            return False
        
        # This would trigger re-authentication
        self.is_locked = False
        self.last_activity_time = time.time()
        SecurityUtils.log_security_event("SESSION_UNLOCKED", f"Session unlocked for {self.current_session['username']}")
        return True
    
    def clear_session(self):
        """Clear current session."""
        if self.current_session:
            SecurityUtils.log_security_event("SESSION_CLEARED", f"Session cleared for {self.current_session['username']}")
        
        self.current_session = None
        self.session_start_time = None
        self.last_activity_time = None
        self.is_locked = True
        
        # Remove session file
        if self.session_file.exists():
            self.session_file.unlink()
    
    def add_failed_attempt(self, username: str):
        """Record a failed login attempt."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = 0
        
        self.failed_attempts[username] += 1
        
        if self.failed_attempts[username] >= Config.MAX_LOGIN_ATTEMPTS:
            self.lockout_times[username] = time.time()
            SecurityUtils.log_security_event("USER_LOCKOUT", f"User {username} locked out after {Config.MAX_LOGIN_ATTEMPTS} failed attempts")
    
    def is_user_locked_out(self, username: str) -> bool:
        """Check if user is currently locked out."""
        if username not in self.lockout_times:
            return False
        
        lockout_time = self.lockout_times[username]
        if time.time() - lockout_time > Config.LOGIN_LOCKOUT_DURATION:
            # Lockout expired
            del self.lockout_times[username]
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            return False
        
        return True
    
    def get_lockout_remaining_time(self, username: str) -> int:
        """Get remaining lockout time in seconds."""
        if username not in self.lockout_times:
            return 0
        
        elapsed = time.time() - self.lockout_times[username]
        remaining = Config.LOGIN_LOCKOUT_DURATION - elapsed
        return max(0, int(remaining))


class AuthenticationUI:
    """User interface for authentication."""
    
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.root = None
        self.auth_window = None
        
    def create_root(self):
        """Create root window."""
        if self.root is None:
            self.root = tk.Tk()
            self.root.withdraw()
    
    def show_login_screen(self) -> Optional[Tuple[str, str, str]]:
        """Show login screen and return (username, auth_method, role) if successful."""
        self.create_root()
        
        # Create fullscreen login window
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title("Security Authentication Required")
        self.auth_window.attributes("-fullscreen", True)
        self.auth_window.attributes("-topmost", True)
        self.auth_window.configure(bg='navy')
        self.auth_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing
        
        # Center frame
        center_frame = tk.Frame(self.auth_window, bg='navy')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="🔐 SECURITY AUTHENTICATION REQUIRED 🔐",
            fg="white",
            bg="navy",
            font=("Helvetica", 28, "bold")
        )
        title_label.pack(pady=(50, 30))
        
        # Subtitle
        subtitle_label = tk.Label(
            center_frame,
            text="Please authenticate to access this secured device",
            fg="lightgray",
            bg="navy",
            font=("Helvetica", 16)
        )
        subtitle_label.pack(pady=(0, 40))
        
        # Authentication methods frame
        methods_frame = tk.Frame(center_frame, bg='navy')
        methods_frame.pack(pady=20)
        
        # Email/Password button
        email_btn = tk.Button(
            methods_frame,
            text="📧 Email & Password",
            command=lambda: self.handle_email_password_auth(),
            font=("Helvetica", 18, "bold"),
            bg="darkblue",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        email_btn.pack(pady=10)
        
        # Fingerprint button (if available)
        if WINDOWS_AUTH_AVAILABLE:
            fingerprint_btn = tk.Button(
                methods_frame,
                text="👆 Fingerprint",
                command=lambda: self.handle_fingerprint_auth(),
                font=("Helvetica", 18, "bold"),
                bg="darkgreen",
                fg="white",
                width=20,
                height=3,
                relief="raised",
                bd=3
            )
            fingerprint_btn.pack(pady=10)
        
        # Face recognition button (if available)
        if FACE_RECOGNITION_AVAILABLE:
            face_btn = tk.Button(
                methods_frame,
                text="😊 Face Recognition",
                command=lambda: self.handle_face_auth(),
                font=("Helvetica", 18, "bold"),
                bg="darkred",
                fg="white",
                width=20,
                height=3,
                relief="raised",
                bd=3
            )
            face_btn.pack(pady=10)
        
        # System info
        sys_info = SecurityUtils.get_system_info()
        info_text = f"Device: {sys_info['computer_name']} | IP: {sys_info['ip_address']} | Time: {sys_info['timestamp']}"
        info_label = tk.Label(
            center_frame,
            text=info_text,
            fg="gray",
            bg="navy",
            font=("Courier", 12)
        )
        info_label.pack(pady=(60, 20))
        
        # Result storage
        self.auth_result = None
        
        # Make the window modal and wait for result instead of mainloop
        self.auth_window.transient(self.root)
        self.auth_window.grab_set()
        
        # Wait for authentication to complete
        self.auth_window.wait_window()
        
        return self.auth_result
    
    def handle_email_password_auth(self):
        """Handle email/password authentication."""
        dialog = EmailPasswordDialog(self.auth_window, self.auth_manager)
        result = dialog.show()
        
        if result:
            self.auth_result = result
            self.close_auth_window()
    
    def handle_fingerprint_auth(self):
        """Handle fingerprint authentication."""
        username = self.auth_manager.biometric_auth.authenticate_fingerprint()
        if username:
            # Verify user exists in LDAP
            success, role = self.auth_manager.ldap_auth.authenticate(username, "")
            if success or role != "authentication_failed":  # User exists in LDAP
                self.auth_result = (username, "fingerprint", role if success else "user")
                self.close_auth_window()
            else:
                messagebox.showerror("Authentication Failed", "Fingerprint recognized but user not found in organization database.")
        else:
            messagebox.showerror("Authentication Failed", "Fingerprint authentication failed.")
    
    def handle_face_auth(self):
        """Handle face recognition authentication."""
        if not FACE_RECOGNITION_AVAILABLE:
            messagebox.showerror("Face Recognition Unavailable", 
                               "Face recognition is not available.\n\n" +
                               "To enable face recognition:\n" +
                               "1. Install required libraries: pip install face-recognition dlib\n" +
                               "2. Or use Windows Subsystem for Linux (WSL)\n" +
                               "3. Or install via conda: conda install -c conda-forge face_recognition\n\n" +
                               "Please use Email & Password or Fingerprint authentication.")
            return
            
        username = self.auth_manager.biometric_auth.authenticate_face()
        if username:
            # Verify user exists in LDAP
            success, role = self.auth_manager.ldap_auth.authenticate(username, "")
            if success or role != "authentication_failed":  # User exists in LDAP
                self.auth_result = (username, "face", role if success else "user")
                self.close_auth_window()
            else:
                messagebox.showerror("Authentication Failed", "Face recognized but user not found in organization database.")
        else:
            messagebox.showerror("Authentication Failed", "Face authentication failed or timed out.")
    
    def close_auth_window(self):
        """Close authentication window."""
        if self.auth_window:
            self.auth_window.destroy()
            self.auth_window = None


class EmailPasswordDialog:
    """Dialog for email/password authentication."""
    
    def __init__(self, parent, auth_manager):
        self.parent = parent
        self.auth_manager = auth_manager
        self.result = None
        self.dialog_destroyed = False
        
    def show(self) -> Optional[Tuple[str, str, str]]:
        """Show email/password dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Email & Password Authentication")
        self.dialog.configure(bg='darkblue')
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        self.dialog.attributes("-topmost", True)
        self.dialog.protocol("WM_DELETE_WINDOW", self.cancel)
        
        # Center the dialog
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Title
        title_label = tk.Label(
            self.dialog,
            text="Organization Login",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=20)
        
        # Email field
        tk.Label(self.dialog, text="Email:", fg="white", bg="darkblue", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.email_entry = tk.Entry(self.dialog, font=("Helvetica", 12), width=30)
        self.email_entry.pack(pady=5)
        self.email_entry.focus_set()
        
        # Password field
        tk.Label(self.dialog, text="Password:", fg="white", bg="darkblue", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.password_entry = tk.Entry(self.dialog, show="*", font=("Helvetica", 12), width=30)
        self.password_entry.pack(pady=5)
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.authenticate())
        
        # Buttons
        button_frame = tk.Frame(self.dialog, bg='darkblue')
        button_frame.pack(pady=30)
        
        login_btn = tk.Button(
            button_frame,
            text="Login",
            command=self.authenticate,
            font=("Helvetica", 14, "bold"),
            bg="green",
            fg="white",
            width=12
        )
        login_btn.pack(side="left", padx=10)
        
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self.cancel,
            font=("Helvetica", 14, "bold"),
            bg="red",
            fg="white",
            width=12
        )
        cancel_btn.pack(side="left", padx=10)
        
        # Wait for dialog to complete
        self.dialog.wait_window()
        return self.result
    
    def authenticate(self):
        """Authenticate with email/password."""
        # Check if dialog was already destroyed
        if self.dialog_destroyed:
            return
            
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not email or not password:
            messagebox.showerror("Error", "Please enter both email and password.")
            return
        
        # Extract username from email
        username = email.split('@')[0] if '@' in email else email
        
        # Check if user is locked out
        if self.auth_manager.session_manager.is_user_locked_out(username):
            remaining = self.auth_manager.session_manager.get_lockout_remaining_time(username)
            messagebox.showerror(
                "Account Locked", 
                f"Too many failed attempts. Please try again in {remaining} seconds."
            )
            return
        
        # Authenticate with LDAP
        success, role = self.auth_manager.ldap_auth.authenticate(username, password)
        
        if success:
            self.result = (username, "email_password", role)
            self.dialog_destroyed = True
            try:
                if self.dialog and self.dialog.winfo_exists():
                    self.dialog.destroy()
            except tk.TclError:
                # Dialog already destroyed, ignore
                pass
        else:
            self.auth_manager.session_manager.add_failed_attempt(username)
            remaining_attempts = Config.MAX_LOGIN_ATTEMPTS - self.auth_manager.session_manager.failed_attempts.get(username, 0)
            
            if remaining_attempts <= 0:
                messagebox.showerror("Account Locked", "Too many failed attempts. Account has been locked.")
            else:
                messagebox.showerror("Authentication Failed", f"Invalid credentials. {remaining_attempts} attempts remaining.")
            
            # Clear password field only if dialog still exists and not destroyed
            if not self.dialog_destroyed:
                try:
                    if self.password_entry and self.password_entry.winfo_exists():
                        self.password_entry.delete(0, tk.END)
                except tk.TclError:
                    # Widget has been destroyed, ignore the error
                    pass
    
    def cancel(self):
        """Cancel authentication."""
        if not self.dialog_destroyed:
            self.dialog_destroyed = True
            try:
                if self.dialog and self.dialog.winfo_exists():
                    self.dialog.destroy()
            except tk.TclError:
                # Dialog already destroyed, ignore
                pass


class AuthenticationManager:
    """Main authentication manager coordinating all authentication methods."""
    
    def __init__(self):
        self.ldap_auth = LDAPAuthenticator(Config())
        self.biometric_auth = BiometricAuthenticator()
        self.session_manager = SessionManager()
        self.auth_ui = AuthenticationUI(self)
        self.monitoring_thread = None
        self.stop_monitoring = False
        
    def require_authentication(self) -> bool:
        """Main method to require authentication before device access."""
        if not Config.AUTHENTICATION_REQUIRED:
            return True
        
        # Check if there's a valid existing session
        """if self.session_manager.load_session() and self.session_manager.is_session_valid():
            SecurityUtils.log_security_event("SESSION_VALID", f"Valid session found for {self.session_manager.current_session['username']}")
            self.start_session_monitoring()
            return True"""
        
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
        import threading
        import queue
        
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
                username, auth_method, role = auth_result
                session = self.session_manager.create_session(username, auth_method, role)
                if session:
                    SecurityUtils.log_security_event("AUTHENTICATION_SUCCESS", f"User {username} authenticated via {auth_method} with role {role}")
                    self.start_session_monitoring()
                    return True
            return False
        except queue.Empty:
            print("⚠️  GUI authentication timed out")
            return False
    
    def _show_simple_auth_dialog(self):
        """Show a simple, non-blocking authentication dialog."""
        import tkinter as tk
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
            
            # Extract username from email
            username = email.split('@')[0] if '@' in email else email
            
            # Authenticate with LDAP
            success, role = self.ldap_auth.authenticate(username, password)
            
            if success:
                messagebox.showinfo("Success", f"Welcome, {username}!", parent=root)
                return (username, "email_password", role)
            else:
                messagebox.showerror("Authentication Failed", "Invalid credentials", parent=root)
                return None
                
        finally:
            root.destroy()
    
    def _try_console_authentication(self) -> bool:
        """Console-based authentication as fallback."""
        print("\n🔐 CONSOLE AUTHENTICATION")
        print("Available methods: Email & Password")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                email = input(f"Enter email (attempt {attempt + 1}/{max_attempts}): ").strip()
                import getpass
                password = getpass.getpass("Enter password: ")
                
                if not email or not password:
                    print("❌ Please enter both email and password")
                    continue
                
                # Extract username from email
                username = email.split('@')[0] if '@' in email else email
                
                # Check if user is locked out
                if self.session_manager.is_user_locked_out(username):
                    remaining = self.session_manager.get_lockout_remaining_time(username)
                    print(f"❌ Account locked. Try again in {remaining} seconds.")
                    return False
                
                # Authenticate with LDAP
                success, role = self.ldap_auth.authenticate(username, password)
                
                if success:
                    # Create session
                    session = self.session_manager.create_session(username, "email_password", role)
                    if session:
                        SecurityUtils.log_security_event("AUTHENTICATION_SUCCESS", f"User {username} authenticated via console with role {role}")
                        self.start_session_monitoring()
                        print(f"✅ Authentication successful! Welcome, {username} ({role})")
                        return True
                    else:
                        SecurityUtils.log_security_event("SESSION_CREATION_FAILED", f"Failed to create session for {username}")
                        print("❌ Failed to create session")
                else:
                    self.session_manager.add_failed_attempt(username)
                    remaining_attempts = max_attempts - (attempt + 1)
                    if remaining_attempts > 0:
                        print(f"❌ Invalid credentials. {remaining_attempts} attempts remaining.")
                    else:
                        print("❌ Maximum attempts reached. Access denied.")
                        SecurityUtils.log_security_event("AUTHENTICATION_FAILED", f"Max attempts reached for {username}")
                        return False
                        
            except KeyboardInterrupt:
                print("\n❌ Authentication cancelled by user")
                SecurityUtils.log_security_event("AUTHENTICATION_CANCELLED", "User cancelled authentication")
                return False
            except Exception as e:
                print(f"❌ Authentication error: {e}")
                SecurityUtils.log_security_event("AUTHENTICATION_ERROR", f"Error during authentication: {e}")
        
        return False
    
    def start_session_monitoring(self):
        """Start background session monitoring."""
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            self.stop_monitoring = False
            self.monitoring_thread = threading.Thread(target=self._session_monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def _session_monitoring_loop(self):
        """Background session monitoring loop."""
        while not self.stop_monitoring:
            try:
                if not self.session_manager.is_session_valid():
                    SecurityUtils.log_security_event("SESSION_INVALID", "Session became invalid - requiring re-authentication")
                    # This would trigger re-authentication in the main application
                    break
                
                time.sleep(Config.SESSION_CHECK_INTERVAL)
                
            except Exception as e:
                SecurityUtils.log_security_event("SESSION_MONITORING_ERROR", f"Error in session monitoring: {e}")
                time.sleep(Config.SESSION_CHECK_INTERVAL)
    
    def stop_session_monitoring(self):
        """Stop session monitoring."""
        self.stop_monitoring = True
    
    def logout(self):
        """Logout current user."""
        self.stop_session_monitoring()
        self.session_manager.clear_session()
        SecurityUtils.log_security_event("USER_LOGOUT", "User logged out")
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated."""
        return self.session_manager.is_session_valid()
    
    def update_activity(self):
        """Update user activity timestamp."""
        if self.session_manager.current_session:
            self.session_manager.update_activity()
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user."""
        if self.session_manager.current_session:
            return self.session_manager.current_session['username']
        return None
    
    def get_current_role(self) -> Optional[str]:
        """Get current user role."""
        if self.session_manager.current_session:
            return self.session_manager.current_session['user_role']
        return None
    
    def register_user_face(self, username: str, image_path: str = None) -> bool:
        """Register face for a user (admin function)."""
        return self.biometric_auth.register_face(username, image_path)


# Example usage and testing
if __name__ == "__main__":
    # Initialize authentication manager
    auth_manager = AuthenticationManager()
    
    # Test authentication
    if auth_manager.require_authentication():
        print(f"Welcome, {auth_manager.get_current_user()}!")
        print(f"Role: {auth_manager.get_current_role()}")
        
        # Simulate some activity
        time.sleep(5)
        auth_manager.update_activity()
        
        # Logout
        input("Press Enter to logout...")
        auth_manager.logout()
    else:
        print("Authentication failed. Access denied.")
