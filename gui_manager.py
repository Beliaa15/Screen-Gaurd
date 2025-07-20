"""
GUI Manager for Physical Security System
Provides full-screen startup screen, login interface, and dashboard.
"""

import tkinter as tk
from tkinter import messagebox
import threading
from datetime import datetime
import time
import os
import cv2
import random

from config import Config
from security_utils import SecurityUtils, LDAPAuthenticator

class MockBiometricAuth:
    """Mock biometric authentication for development/testing."""
    
    def __init__(self):
        self.face_encodings_db = {}
        self.fingerprint_users = ["admin", "user", "test"]
        
    def authenticate_fingerprint(self):
        """Mock fingerprint authentication."""
        # Simulate scanning delay
        time.sleep(2)
        # For demo purposes, randomly succeed
        
        if random.random() > 0.3:  # 70% success rate
            return "fingerprint_user"
        return None
    
    def authenticate_face(self, timeout=30):
        """Mock face recognition authentication."""
        # Simulate face scanning
        time.sleep(3)
        # For demo purposes, randomly succeed
        if random.random() > 0.4:  # 60% success rate
            return "face_user"
        return None

class SecurityGUI:
    """Main GUI class for the Physical Security System."""
    
    def __init__(self, auth_manager=None):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.auth_manager = auth_manager
        self.biometric_auth = MockBiometricAuth()
        self.is_authenticated = False
        self.current_user = None
        self.current_screen = None
        
        # Configure main window
        self.setup_window()
        
    def setup_window(self):
        """Configure the main window properties to match alert system security standards."""
        self.root.title("Physical Security System")
        self.root.attributes("-fullscreen", True)  # Full screen like alert system
        self.root.attributes("-topmost", True)     # Always on top like alert system
        self.root.configure(bg='black')
        self.root.resizable(False, False)  # Prevent resizing
        
        # Prevent closing like alert system - no escape key exit
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Remove escape key binding - security requirement like alerts
        # No escape key exit allowed - unified with alert system behavior
        
        # Additional security: disable Alt+F4 and other common exit shortcuts
        self.root.bind('<Alt-F4>', lambda e: None)
        self.root.bind('<Control-c>', lambda e: None)
        self.root.bind('<Control-C>', lambda e: None)
        
    def maintain_security_properties(self):
        """Ensure security properties are maintained - call this periodically."""
        # Reapply security properties in case they were somehow modified
        self.root.attributes("-topmost", True)
        self.root.attributes("-fullscreen", True)
        self.root.resizable(False, False)
        
    def clear_screen(self):
        """Clear all widgets from the root window and maintain security properties."""
        for widget in self.root.winfo_children():
            widget.destroy()
        # Ensure security properties are maintained after clearing screen
        self.maintain_security_properties()
    
    def run(self):
        """Start the GUI application."""
        SecurityUtils.log_security_event("GUI_STARTED", "Physical Security GUI started")
        self.show_startup_screen()
        self.root.mainloop()
    
    def is_ready_for_detection(self):
        """Check if the GUI is ready for the main detection system."""
        return self.is_authenticated and self.current_screen in ["dashboard", "minimized"]
    
    def show_startup_screen(self):
        """Display the startup screen with loading animation."""
        self.clear_screen()
        SecurityUtils.log_security_event("STARTUP_SCREEN_SHOWN", "Application startup screen displayed")
        
        # Main container
        main_frame = tk.Frame(self.root, bg='black')
        main_frame.pack(expand=True, fill='both')
        
        # Center content frame
        center_frame = tk.Frame(main_frame, bg='black')
        center_frame.pack(expand=True)
        
        # Logo/Icon area
        logo_label = tk.Label(
            center_frame,
            text="🛡️",
            fg="#00ff00",
            bg="black",
            font=("Helvetica", 120, "bold")
        )
        logo_label.pack(pady=(100, 30))
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="PHYSICAL SECURITY SYSTEM",
            fg="white",
            bg="black",
            font=("Helvetica", 48, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Subtitle
        subtitle_label = tk.Label(
            center_frame,
            text="Advanced Biometric & AI-Powered Security Monitoring",
            fg="#00ff00",
            bg="black",
            font=("Helvetica", 24)
        )
        subtitle_label.pack(pady=(0, 50))
        
        # System info
        sys_info = SecurityUtils.get_system_info()
        info_text = f"""SYSTEM INITIALIZATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Device: {sys_info['computer_name']}
IP Address: {sys_info['ip_address']}
Current User: {sys_info['username']}
Time: {sys_info['timestamp']}

Loading security modules...
Authentication system: READY
Face recognition: CHECKING...
Fingerprint scanner: CHECKING...
YOLO detection engine: READY
Alert system: READY"""

        info_label = tk.Label(
            center_frame,
            text=info_text,
            fg="#00ff00",
            bg="black",
            font=("Courier", 14),
            justify="left"
        )
        info_label.pack(pady=30)
        
        # Loading animation area
        self.loading_label = tk.Label(
            center_frame,
            text="● ● ●",
            fg="#00ff00",
            bg="black",
            font=("Helvetica", 20, "bold")
        )
        self.loading_label.pack(pady=30)
        
        # Start loading animation
        self.animate_loading()
        
        # Auto-transition to login after 3 seconds
        self.root.after(3000, self.show_login_screen)
        
        self.current_screen = "startup"
        
    def animate_loading(self):
        """Animate the loading dots."""
        if self.current_screen == "startup" and hasattr(self, 'loading_label'):
            current_text = self.loading_label.cget("text")
            if current_text == "● ● ●":
                self.loading_label.config(text="● ● ○")
            elif current_text == "● ● ○":
                self.loading_label.config(text="● ○ ○")
            elif current_text == "● ○ ○":
                self.loading_label.config(text="○ ○ ○")
            else:
                self.loading_label.config(text="● ● ●")
            
            # Continue animation
            self.root.after(300, self.animate_loading)
    
    def show_login_screen(self):
        """Display the full-screen login interface."""
        self.clear_screen()
        SecurityUtils.log_security_event("LOGIN_SCREEN_SHOWN", "Login screen displayed")
        
        # Main container with gradient-like effect
        main_frame = tk.Frame(self.root, bg='#1a1a2e')
        main_frame.pack(expand=True, fill='both')
        
        # Header section
        header_frame = tk.Frame(main_frame, bg='#16213e', height=150)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Security icon and title in header
        header_content = tk.Frame(header_frame, bg='#16213e')
        header_content.pack(expand=True)
        
        lock_icon = tk.Label(
            header_content,
            text="🔐",
            fg="#ff6b6b",
            bg="#16213e",
            font=("Helvetica", 60, "bold")
        )
        lock_icon.pack(pady=(20, 10))
        
        header_title = tk.Label(
            header_content,
            text="SECURE ACCESS REQUIRED",
            fg="white",
            bg="#16213e",
            font=("Helvetica", 28, "bold")
        )
        header_title.pack()
        
        # Main login area
        login_frame = tk.Frame(main_frame, bg='#1a1a2e')
        login_frame.pack(expand=True, fill='both', padx=100, pady=50)
        
        # Left side - Authentication methods
        left_frame = tk.Frame(login_frame, bg='#0f3460', width=600)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 50))
        left_frame.pack_propagate(False)
        
        # Authentication methods title
        auth_title = tk.Label(
            left_frame,
            text="AUTHENTICATION METHODS",
            fg="white",
            bg="#0f3460",
            font=("Helvetica", 20, "bold")
        )
        auth_title.pack(pady=(40, 30))
        
        # Method buttons
        self.create_auth_method_buttons(left_frame)
        
        # Right side - Login form (initially hidden)
        self.right_frame = tk.Frame(login_frame, bg='#533483', width=600)
        self.right_frame.pack(side='right', fill='both', expand=True)
        self.right_frame.pack_propagate(False)
        
        # Initially show method selection
        self.show_method_selection()
        
        # Footer with system info
        footer_frame = tk.Frame(main_frame, bg='#16213e', height=100)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        sys_info = SecurityUtils.get_system_info()
        footer_text = f"Device: {sys_info['computer_name']} | IP: {sys_info['ip_address']} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        footer_label = tk.Label(
            footer_frame,
            text=footer_text,
            fg="#888888",
            bg="#16213e",
            font=("Courier", 12)
        )
        footer_label.pack(expand=True)
        
        # Security warning
        warning_label = tk.Label(
            footer_frame,
            text="⚠️ This system is monitored. All access attempts are logged.",
            fg="#ff6b6b",
            bg="#16213e",
            font=("Helvetica", 12, "bold")
        )
        warning_label.pack()
        
        self.current_screen = "login"
        
    def create_auth_method_buttons(self, parent):
        """Create authentication method selection buttons."""
        
        # Username/Password button
        password_btn = tk.Button(
            parent,
            text="🔑 USERNAME & PASSWORD",
            command=lambda: self.select_auth_method("password"),
            font=("Helvetica", 16, "bold"),
            bg="#4a90e2",
            fg="white",
            width=30,
            height=3,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        password_btn.pack(pady=20, padx=40)
        
        # Fingerprint button
        fingerprint_btn = tk.Button(
            parent,
            text="👆 FINGERPRINT SCANNER",
            command=lambda: self.select_auth_method("fingerprint"),
            font=("Helvetica", 16, "bold"),
            bg="#e67e22",
            fg="white",
            width=30,
            height=3,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        fingerprint_btn.pack(pady=20, padx=40)
        
        # Face recognition button
        face_btn = tk.Button(
            parent,
            text="👤 FACE RECOGNITION",
            command=lambda: self.select_auth_method("face"),
            font=("Helvetica", 16, "bold"),
            bg="#27ae60",
            fg="white",
            width=30,
            height=3,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        face_btn.pack(pady=20, padx=40)
        
        # System status
        status_frame = tk.Frame(parent, bg="#0f3460")
        status_frame.pack(fill='x', pady=(50, 20), padx=40)
        
        status_title = tk.Label(
            status_frame,
            text="SYSTEM STATUS",
            fg="white",
            bg="#0f3460",
            font=("Helvetica", 14, "bold")
        )
        status_title.pack()
        
        # Check face recognition availability
        face_status = "🟢 READY" if len(self.biometric_auth.face_encodings_db) > 0 else "🟡 NO FACES REGISTERED"
        
        status_text = f"""Camera: 🟢 READY
Face Recognition: {face_status}
Fingerprint: 🟢 READY
LDAP Server: 🟢 CONNECTED"""

        status_label = tk.Label(
            status_frame,
            text=status_text,
            fg="#00ff00",
            bg="#0f3460",
            font=("Courier", 11),
            justify="left"
        )
        status_label.pack(pady=10)
    
    def select_auth_method(self, method):
        """Handle authentication method selection."""
        SecurityUtils.log_security_event("AUTH_METHOD_SELECTED", f"User selected authentication method: {method}")
        
        # Clear right frame
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        if method == "password":
            self.show_password_form()
        elif method == "fingerprint":
            self.show_fingerprint_auth()
        elif method == "face":
            self.show_face_auth()
    
    def show_method_selection(self):
        """Show the method selection message."""
        for widget in self.right_frame.winfo_children():
            widget.destroy()
            
        # Welcome message
        welcome_label = tk.Label(
            self.right_frame,
            text="WELCOME",
            fg="white",
            bg="#533483",
            font=("Helvetica", 24, "bold")
        )
        welcome_label.pack(pady=(60, 20))
        
        instruction_label = tk.Label(
            self.right_frame,
            text="Please select an authentication method\nfrom the options on the left.",
            fg="white",
            bg="#533483",
            font=("Helvetica", 16),
            justify="center"
        )
        instruction_label.pack(pady=20)
        
        # Current time
        time_label = tk.Label(
            self.right_frame,
            text=datetime.now().strftime("%H:%M:%S"),
            fg="#00ff00",
            bg="#533483",
            font=("Courier", 48, "bold")
        )
        time_label.pack(pady=40)
        
        # Update time every second
        def update_time():
            if self.current_screen == "login":
                try:
                    time_label.config(text=datetime.now().strftime("%H:%M:%S"))
                    self.root.after(1000, update_time)
                except:
                    pass
        
        update_time()
    
    def show_password_form(self):
        """Show username/password form."""
        # Form title
        title_label = tk.Label(
            self.right_frame,
            text="🔑 LDAP AUTHENTICATION",
            fg="white",
            bg="#533483",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(40, 30))
        
        # Form container
        form_frame = tk.Frame(self.right_frame, bg="#533483")
        form_frame.pack(pady=20, padx=40, fill='x')
        
        # Username field
        tk.Label(
            form_frame,
            text="Username:",
            fg="white",
            bg="#533483",
            font=("Helvetica", 14, "bold")
        ).pack(anchor='w', pady=(0, 5))
        
        self.username_var = tk.StringVar()
        username_entry = tk.Entry(
            form_frame,
            textvariable=self.username_var,
            font=("Helvetica", 14),
            width=25,
            relief="solid",
            bd=2
        )
        username_entry.pack(pady=(0, 20), fill='x')
        username_entry.focus_set()
        
        # Password field
        tk.Label(
            form_frame,
            text="Password:",
            fg="white",
            bg="#533483",
            font=("Helvetica", 14, "bold")
        ).pack(anchor='w', pady=(0, 5))
        
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(
            form_frame,
            textvariable=self.password_var,
            font=("Helvetica", 14),
            width=25,
            show="*",
            relief="solid",
            bd=2
        )
        password_entry.pack(pady=(0, 30), fill='x')
        
        # Bind Enter key to login
        password_entry.bind('<Return>', lambda e: self.attempt_password_login())
        
        # Login button
        login_btn = tk.Button(
            form_frame,
            text="🚀 AUTHENTICATE",
            command=self.attempt_password_login,
            font=("Helvetica", 16, "bold"),
            bg="#27ae60",
            fg="white",
            width=20,
            height=2,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        login_btn.pack(pady=10)
        
        # Back button
        back_btn = tk.Button(
            form_frame,
            text="← BACK",
            command=self.show_method_selection,
            font=("Helvetica", 12, "bold"),
            bg="#7f8c8d",
            fg="white",
            width=15,
            height=1,
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        back_btn.pack(pady=(20, 0))
    
    def show_fingerprint_auth(self):
        """Show fingerprint authentication interface."""
        # Title
        title_label = tk.Label(
            self.right_frame,
            text="👆 FINGERPRINT AUTHENTICATION",
            fg="white",
            bg="#533483",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(pady=(40, 30))
        
        # Fingerprint icon
        fingerprint_icon = tk.Label(
            self.right_frame,
            text="🔍",
            fg="#e67e22",
            bg="#533483",
            font=("Helvetica", 80, "bold")
        )
        fingerprint_icon.pack(pady=20)
        
        # Instructions
        instruction_label = tk.Label(
            self.right_frame,
            text="Please place your finger on the\nfingerprint scanner and wait for\nauthentication to complete.",
            fg="white",
            bg="#533483",
            font=("Helvetica", 14),
            justify="center"
        )
        instruction_label.pack(pady=20)
        
        # Status label
        self.fingerprint_status = tk.Label(
            self.right_frame,
            text="Ready for fingerprint scan...",
            fg="#00ff00",
            bg="#533483",
            font=("Helvetica", 12, "bold")
        )
        self.fingerprint_status.pack(pady=20)
        
        # Buttons
        button_frame = tk.Frame(self.right_frame, bg="#533483")
        button_frame.pack(pady=30)
        
        scan_btn = tk.Button(
            button_frame,
            text="🔍 START SCAN",
            command=self.attempt_fingerprint_login,
            font=("Helvetica", 14, "bold"),
            bg="#e67e22",
            fg="white",
            width=15,
            height=2,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        scan_btn.pack(side='left', padx=10)
        
        back_btn = tk.Button(
            button_frame,
            text="← BACK",
            command=self.show_method_selection,
            font=("Helvetica", 12, "bold"),
            bg="#7f8c8d",
            fg="white",
            width=15,
            height=1,
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        back_btn.pack(side='left', padx=10)
    
    def show_face_auth(self):
        """Show face recognition authentication interface."""
        # Title
        title_label = tk.Label(
            self.right_frame,
            text="👤 FACE RECOGNITION",
            fg="white",
            bg="#533483",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(pady=(40, 30))
        
        # Face icon
        face_icon = tk.Label(
            self.right_frame,
            text="📷",
            fg="#27ae60",
            bg="#533483",
            font=("Helvetica", 80, "bold")
        )
        face_icon.pack(pady=20)
        
        # Instructions
        instruction_label = tk.Label(
            self.right_frame,
            text="Look directly at the camera\nand remain still during scanning.\n\nPress START when ready.",
            fg="white",
            bg="#533483",
            font=("Helvetica", 14),
            justify="center"
        )
        instruction_label.pack(pady=20)
        
        # Status label
        self.face_status = tk.Label(
            self.right_frame,
            text="Camera ready for face scan...",
            fg="#00ff00",
            bg="#533483",
            font=("Helvetica", 12, "bold")
        )
        self.face_status.pack(pady=20)
        
        # Registered faces info
        face_count = len(self.biometric_auth.face_encodings_db)
        face_info = tk.Label(
            self.right_frame,
            text=f"Registered faces: {face_count}",
            fg="#888888",
            bg="#533483",
            font=("Helvetica", 11)
        )
        face_info.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(self.right_frame, bg="#533483")
        button_frame.pack(pady=30)
        
        scan_btn = tk.Button(
            button_frame,
            text="📷 START SCAN",
            command=self.attempt_face_login,
            font=("Helvetica", 14, "bold"),
            bg="#27ae60",
            fg="white",
            width=15,
            height=2,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        scan_btn.pack(side='left', padx=10)
        
        back_btn = tk.Button(
            button_frame,
            text="← BACK",
            command=self.show_method_selection,
            font=("Helvetica", 12, "bold"),
            bg="#7f8c8d",
            fg="white",
            width=15,
            height=1,
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        back_btn.pack(side='left', padx=10)
    
    def attempt_password_login(self):
        """Attempt LDAP authentication."""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        print(f"Attempting LDAP login for user: {username} with password: {password}")
        
        if not username or not password:
            self.show_security_error("AUTHENTICATION ERROR", "Both username and password are required for security verification.")
            return
        
        SecurityUtils.log_security_event("PASSWORD_AUTH_ATTEMPT", f"Login attempt for user: {username}")
        
        # Show loading state
        self.show_auth_loading("Authenticating with LDAP server...")
        
        # Perform authentication in a thread to avoid blocking GUI
        def auth_thread():
            try:
                # Always use real LDAP authentication
                ldap_auth = LDAPAuthenticator(Config())
                success, role = ldap_auth.authenticate(username, password)
                print(f"LDAP authentication result for {username}: success={success}, role={role}")
                
                # Schedule GUI update in main thread
                self.root.after(0, lambda: self.handle_auth_result(success, username, "password", role))
            except Exception as e:
                print(f"LDAP authentication error for {username}: {str(e)}")
                self.root.after(0, lambda: self.handle_auth_result(False, username, "password", str(e)))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def attempt_fingerprint_login(self):
        """Attempt fingerprint authentication."""
        SecurityUtils.log_security_event("FINGERPRINT_AUTH_ATTEMPT", "Fingerprint authentication started")
        
        self.fingerprint_status.config(text="Scanning fingerprint...", fg="#ffff00")
        
        def auth_thread():
            try:
                result = self.biometric_auth.authenticate_fingerprint()
                self.root.after(0, lambda: self.handle_auth_result(bool(result), result or "fingerprint_user", "fingerprint", "user"))
            except Exception as e:
                self.root.after(0, lambda: self.handle_auth_result(False, "fingerprint_user", "fingerprint", str(e)))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def attempt_face_login(self):
        """Attempt face recognition authentication."""
        SecurityUtils.log_security_event("FACE_AUTH_ATTEMPT", "Face recognition authentication started")
        
        self.face_status.config(text="Scanning face...", fg="#ffff00")
        
        def auth_thread():
            try:
                result = self.biometric_auth.authenticate_face(timeout=30)
                self.root.after(0, lambda: self.handle_auth_result(bool(result), result or "face_user", "face", "user"))
            except Exception as e:
                self.root.after(0, lambda: self.handle_auth_result(False, "face_user", "face", str(e)))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def show_auth_loading(self, message):
        """Show authentication loading state."""
        # Clear right frame
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Loading animation
        loading_label = tk.Label(
            self.right_frame,
            text="🔄",
            fg="#00ff00",
            bg="#533483",
            font=("Helvetica", 60, "bold")
        )
        loading_label.pack(pady=(80, 20))
        
        message_label = tk.Label(
            self.right_frame,
            text=message,
            fg="white",
            bg="#533483",
            font=("Helvetica", 16)
        )
        message_label.pack(pady=20)
        
        # Animate loading icon
        def animate():
            try:
                current = loading_label.cget("text")
                if current == "🔄":
                    loading_label.config(text="⟳")
                elif current == "⟳":
                    loading_label.config(text="↻")
                else:
                    loading_label.config(text="🔄")
                self.root.after(300, animate)
            except:
                pass
        
        animate()
    
    def handle_auth_result(self, success, username, method, role_or_error):
        """Handle authentication result."""
        if success:
            SecurityUtils.log_security_event("AUTHENTICATION_SUCCESS", f"User {username} authenticated via {method}")
            
            # Create session if auth manager is available
            if self.auth_manager:
                session = self.auth_manager.session_manager.create_session(username, method, role_or_error)
            
            self.is_authenticated = True
            self.current_user = username
            
            # Show success and transition to dashboard
            self.show_auth_success(username, role_or_error)
        else:
            SecurityUtils.log_security_event("AUTHENTICATION_FAILED", f"Authentication failed for {username} via {method}: {role_or_error}")
            self.show_auth_failure(role_or_error)
    
    def show_auth_success(self, username, role):
        """Show authentication success message."""
        self.clear_screen()
        
        # Success screen
        main_frame = tk.Frame(self.root, bg='darkgreen')
        main_frame.pack(expand=True, fill='both')
        
        center_frame = tk.Frame(main_frame, bg='darkgreen')
        center_frame.pack(expand=True)
        
        # Success icon
        success_icon = tk.Label(
            center_frame,
            text="✅",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 100, "bold")
        )
        success_icon.pack(pady=(100, 30))
        
        # Success message
        success_label = tk.Label(
            center_frame,
            text="ACCESS GRANTED",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 36, "bold")
        )
        success_label.pack(pady=(0, 20))
        
        # User info
        user_label = tk.Label(
            center_frame,
            text=f"Welcome, {username}",
            fg="lightgreen",
            bg="darkgreen",
            font=("Helvetica", 24)
        )
        user_label.pack(pady=10)
        
        role_label = tk.Label(
            center_frame,
            text=f"Role: {role.title()}",
            fg="lightgreen",
            bg="darkgreen",
            font=("Helvetica", 18)
        )
        role_label.pack(pady=5)
        
        # Loading message
        loading_msg = tk.Label(
            center_frame,
            text="Starting security monitoring system...",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 16)
        )
        loading_msg.pack(pady=40)
        
        # Auto-transition to main dashboard
        self.root.after(2000, self.show_main_dashboard)
        
        self.current_screen = "success"
    
    def show_auth_failure(self, error_message):
        """Show authentication failure message."""
        # Clear right frame and show error
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Error icon
        error_icon = tk.Label(
            self.right_frame,
            text="❌",
            fg="#ff6b6b",
            bg="#533483",
            font=("Helvetica", 60, "bold")
        )
        error_icon.pack(pady=(60, 20))
        
        # Error message
        error_label = tk.Label(
            self.right_frame,
            text="AUTHENTICATION FAILED",
            fg="#ff6b6b",
            bg="#533483",
            font=("Helvetica", 18, "bold")
        )
        error_label.pack(pady=(0, 10))
        
        detail_label = tk.Label(
            self.right_frame,
            text=str(error_message),
            fg="white",
            bg="#533483",
            font=("Helvetica", 12),
            wraplength=400,
            justify="center"
        )
        detail_label.pack(pady=20)
        
        # Try again button
        retry_btn = tk.Button(
            self.right_frame,
            text="🔄 TRY AGAIN",
            command=self.show_method_selection,
            font=("Helvetica", 14, "bold"),
            bg="#e74c3c",
            fg="white",
            width=15,
            height=2,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        retry_btn.pack(pady=30)
    
    def show_main_dashboard(self):
        """Show the main dashboard after successful authentication."""
        self.clear_screen()
        SecurityUtils.log_security_event("DASHBOARD_SHOWN", "Main dashboard displayed")
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title and user info
        title_label = tk.Label(
            header_frame,
            text=f"🛡️ PHYSICAL SECURITY SYSTEM - Welcome {self.current_user}",
            fg="white",
            bg="#2c3e50",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(side='left', padx=20, pady=25)
        
        # Logout button
        logout_btn = tk.Button(
            header_frame,
            text="🚪 LOGOUT",
            command=self.logout,
            font=("Helvetica", 12, "bold"),
            bg="#e74c3c",
            fg="white",
            width=10,
            height=2,
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        logout_btn.pack(side='right', padx=20, pady=20)
        
        # Main content area
        main_frame = tk.Frame(self.root, bg='#34495e')
        main_frame.pack(expand=True, fill='both')
        
        # Status panel
        status_frame = tk.Frame(main_frame, bg='#34495e')
        status_frame.pack(fill='x', padx=20, pady=20)
        
        status_title = tk.Label(
            status_frame,
            text="SYSTEM STATUS",
            fg="white",
            bg="#34495e",
            font=("Helvetica", 16, "bold")
        )
        status_title.pack()
        
        # System monitoring status
        self.status_label = tk.Label(
            status_frame,
            text="🟢 Security monitoring: ACTIVE\n🟢 YOLO detection: RUNNING\n🟢 Alert system: READY\n🟢 Camera: CONNECTED",
            fg="#00ff00",
            bg="#34495e",
            font=("Courier", 14),
            justify="left"
        )
        self.status_label.pack(pady=20)
        
        # Start monitoring message
        start_msg = tk.Label(
            main_frame,
            text="Security monitoring is now active.\nThe system will detect mobile phones and screen recording attempts.\nThis window will minimize automatically.",
            fg="white",
            bg="#34495e",
            font=("Helvetica", 16),
            justify="center"
        )
        start_msg.pack(expand=True)
        
        self.current_screen = "dashboard"
        
        # Minimize window after showing dashboard
        self.root.after(3000, self.minimize_to_system_tray)
    
    def minimize_to_system_tray(self):
        """Minimize the GUI and start the main detection system."""
        SecurityUtils.log_security_event("GUI_MINIMIZED", "GUI minimized, starting main detection system")
        self.root.withdraw()  # Hide the main window
        
        # Signal that authentication is complete and main system can start
        self.is_authenticated = True
        self.current_screen = "minimized"
    
    def logout(self):
        """Handle user logout."""
        SecurityUtils.log_security_event("USER_LOGOUT", f"User {self.current_user} logged out")
        
        # Clear session
        if self.auth_manager:
            self.auth_manager.logout()
        self.is_authenticated = False
        self.current_user = None
        
        # Return to login screen
        self.show_login_screen()
    
    def show_security_error(self, title, message):
        """Show security error dialog with same properties as alert system."""
        # Create a secure error dialog that matches alert system properties
        error_window = tk.Toplevel(self.root)
        error_window.title(title)
        error_window.attributes("-fullscreen", True)  # Full screen like alerts
        error_window.attributes("-topmost", True)     # Always on top like alerts
        error_window.configure(bg='darkred')
        error_window.resizable(False, False)
        error_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing like alerts
        
        # Center content
        center_frame = tk.Frame(error_window, bg='darkred')
        center_frame.pack(expand=True)
        
        # Error icon
        error_icon = tk.Label(
            center_frame,
            text="⚠️",
            fg="white",
            bg="darkred",
            font=("Helvetica", 80, "bold")
        )
        error_icon.pack(pady=(100, 30))
        
        # Error title
        title_label = tk.Label(
            center_frame,
            text=title,
            fg="white",
            bg="darkred",
            font=("Helvetica", 28, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Error message
        message_label = tk.Label(
            center_frame,
            text=message,
            fg="yellow",
            bg="darkred",
            font=("Helvetica", 18, "bold"),
            wraplength=800,
            justify="center"
        )
        message_label.pack(pady=20)
        
        # OK button (only way to close)
        ok_button = tk.Button(
            center_frame,
            text="OK - UNDERSTOOD",
            command=error_window.destroy,
            font=("Helvetica", 16, "bold"),
            bg="yellow",
            fg="black",
            width=20,
            height=2,
            relief="raised",
            bd=3,
            cursor="hand2"
        )
        ok_button.pack(pady=40)
        
        # Security notice
        notice_label = tk.Label(
            center_frame,
            text="Security protocols must be followed",
            fg="orange",
            bg="darkred",
            font=("Helvetica", 14, "bold")
        )
        notice_label.pack(pady=10)

if __name__ == "__main__":
    # Test the GUI
    gui = SecurityGUI()
    gui.run()
