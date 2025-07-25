"""
GUI Manager for Physical Security System
Provides full-screen startup screen, login interface, and dashboard.
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time
from datetime import datetime

from ..core.config import Config
from ..utils.security_utils import SecurityUtils
from ..auth.ldap_auth import LDAPAuthenticator
from ..auth.biometric_auth import BiometricAuthenticator


class SecurityGUI:
    """Main GUI class for the Physical Security System."""
    
    def __init__(self, auth_manager=None):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.auth_manager = auth_manager
        self.biometric_auth = BiometricAuthenticator()
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
        """Run the GUI main loop."""
        self.show_startup_screen()
        self.root.mainloop()
    
    def is_ready_for_detection(self):
        """Check if GUI is ready for detection system to start."""
        return self.is_authenticated
    
    def show_startup_screen(self):
        """Show the startup screen with loading animation."""
        self.clear_screen()
        self.current_screen = "startup"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='black')
        main_frame.pack(expand=True, fill='both')
        
        # Center frame for vertical centering
        center_frame = tk.Frame(main_frame, bg='black')
        center_frame.pack(expand=True)
        
        # Logo/Icon
        logo_label = tk.Label(
            center_frame,
            text="🔒",
            fg="cyan",
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
            font=("Helvetica", 32, "bold")
        )
        title_label.pack(pady=(0, 10))
        
        # Subtitle
        subtitle_label = tk.Label(
            center_frame,
            text="Advanced Object Detection & Access Control",
            fg="gray",
            bg="black",
            font=("Helvetica", 16)
        )
        subtitle_label.pack(pady=(0, 50))
        
        # Loading label
        self.loading_label = tk.Label(
            center_frame,
            text="Initializing System...",
            fg="cyan",
            bg="black",
            font=("Helvetica", 14)
        )
        self.loading_label.pack(pady=(0, 20))
        
        # Progress dots
        self.progress_label = tk.Label(
            center_frame,
            text="",
            fg="cyan",
            bg="black",
            font=("Helvetica", 20)
        )
        self.progress_label.pack()
        
        # Start loading animation
        self.animate_loading()
        
        # Auto-proceed to login after 3 seconds
        self.root.after(3000, self.show_login_screen)
        
    def animate_loading(self):
        """Animate loading dots."""
        def update_dots():
            for i in range(4):
                if self.current_screen != "startup":
                    return
                dots = "." * i
                self.progress_label.config(text=dots)
                self.root.update_idletasks()
                time.sleep(0.5)
        
        threading.Thread(target=update_dots, daemon=True).start()
    
    def show_login_screen(self):
        """Show the login/authentication screen."""
            
        self.clear_screen()
        self.current_screen = "login"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkblue')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg='darkblue', height=100)
        header_frame.pack(fill='x', padx=20, pady=20)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔐 SYSTEM AUTHENTICATION",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack(expand=True)
        
        # Center authentication frame
        auth_frame = tk.Frame(main_frame, bg='darkblue')
        auth_frame.pack(expand=True)
        
        # Welcome message
        welcome_label = tk.Label(
            auth_frame,
            text="Please authenticate to access the security system",
            fg="lightgray",
            bg="darkblue",
            font=("Helvetica", 16)
        )
        welcome_label.pack(pady=(0, 40))
        
        # Authentication method buttons
        self.create_auth_method_buttons(auth_frame)
        
        # Footer with system info
        footer_frame = tk.Frame(main_frame, bg='darkblue', height=80)
        footer_frame.pack(fill='x', side='bottom', padx=20, pady=10)
        footer_frame.pack_propagate(False)
        
        sys_info = SecurityUtils.get_system_info()
        footer_text = f"System: {sys_info['computer_name']} | User: {sys_info['username']} | IP: {sys_info['ip_address']}"
        footer_label = tk.Label(
            footer_frame,
            text=footer_text,
            fg="gray",
            bg="darkblue",
            font=("Courier", 10)
        )
        footer_label.pack(expand=True)
        
    def create_auth_method_buttons(self, parent):
        """Create authentication method selection buttons."""
        methods_frame = tk.Frame(parent, bg='darkblue')
        methods_frame.pack(pady=20)
        
        # Email & Password button
        email_btn = tk.Button(
            methods_frame,
            text="📧 Email & Password",
            command=lambda: self.select_auth_method("email_password"),
            font=("Helvetica", 16, "bold"),
            bg="green",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        email_btn.pack(pady=10)
        
        # Fingerprint button
        fingerprint_btn = tk.Button(
            methods_frame,
            text="👆 Fingerprint",
            command=lambda: self.select_auth_method("fingerprint"),
            font=("Helvetica", 16, "bold"),
            bg="blue",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        fingerprint_btn.pack(pady=10)
        
        # Face Recognition button
        face_btn = tk.Button(
            methods_frame,
            text="👤 Face Recognition",
            command=lambda: self.select_auth_method("face"),
            font=("Helvetica", 16, "bold"),
            bg="purple",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        face_btn.pack(pady=10)
    
    def select_auth_method(self, method):
        """Handle authentication method selection."""
        if method == "email_password":  # Keep the same method name for compatibility
            self.show_domain_auth_form()
        elif method == "fingerprint":
            self.show_fingerprint_auth()
        elif method == "face":
            self.show_face_auth()
    
    def show_method_selection(self):
        """Show method selection screen."""
        self.show_login_screen()
    
    def show_domain_auth_form(self):
        """Show domain authentication form."""
        self.clear_screen()
        self.current_screen = "password_form"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkgreen')
        main_frame.pack(expand=True, fill='both')
        
        # Center frame
        center_frame = tk.Frame(main_frame, bg='darkgreen')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="📧 EMAIL & PASSWORD AUTHENTICATION",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(50, 30))
        
        # Form frame
        form_frame = tk.Frame(center_frame, bg='darkgreen')
        form_frame.pack(pady=20)
        
        # Username field (with domain format example)
        username_label = tk.Label(
            form_frame, 
            text="Username:", 
            fg="white", 
            bg="darkgreen", 
            font=("Helvetica", 14)
        )
        username_label.pack(anchor='w')
        
        self.email_entry = tk.Entry(form_frame, font=("Helvetica", 12), width=35)
        self.email_entry.pack(pady=(5, 15))
        self.email_entry.focus_set()
        
        # Password field
        tk.Label(form_frame, text="Password:", fg="white", bg="darkgreen", font=("Helvetica", 14)).pack(anchor='w')
        self.password_entry = tk.Entry(form_frame, show="*", font=("Helvetica", 12), width=35)
        self.password_entry.pack(pady=(5, 20))
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.attempt_password_login())
        
        # Buttons frame
        buttons_frame = tk.Frame(center_frame, bg='darkgreen')
        buttons_frame.pack(pady=20)
        
        # Login button
        login_btn = tk.Button(
            buttons_frame,
            text="✓ Login",
            command=self.attempt_password_login,
            font=("Helvetica", 14, "bold"),
            bg="green",
            fg="white",
            width=15,
            height=2
        )
        login_btn.pack(side='left', padx=10)
        
        # Back button
        back_btn = tk.Button(
            buttons_frame,
            text="← Back",
            command=self.show_method_selection,
            font=("Helvetica", 14, "bold"),
            bg="gray",
            fg="white",
            width=15,
            height=2
        )
        back_btn.pack(side='left', padx=10)
    
    def show_fingerprint_auth(self):
        """Show fingerprint authentication screen."""
        self.clear_screen()
        self.current_screen = "fingerprint"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkblue')
        main_frame.pack(expand=True, fill='both')
        
        # Center frame
        center_frame = tk.Frame(main_frame, bg='darkblue')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="👆 FINGERPRINT AUTHENTICATION",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(50, 30))
        
        # Fingerprint icon (animated)
        self.fingerprint_icon = tk.Label(
            center_frame,
            text="👆",
            fg="cyan",
            bg="darkblue",
            font=("Helvetica", 80)
        )
        self.fingerprint_icon.pack(pady=20)
        
        # Instructions
        instructions_label = tk.Label(
            center_frame,
            text="Place your finger on the sensor\nand wait for authentication",
            fg="lightgray",
            bg="darkblue",
            font=("Helvetica", 16),
            justify='center'
        )
        instructions_label.pack(pady=20)
        
        # Status label
        self.fingerprint_status = tk.Label(
            center_frame,
            text="Initializing sensor...",
            fg="yellow",
            bg="darkblue",
            font=("Helvetica", 14)
        )
        self.fingerprint_status.pack(pady=10)
        
        # Cancel button
        cancel_btn = tk.Button(
            center_frame,
            text="← Cancel",
            command=self.show_method_selection,
            font=("Helvetica", 12, "bold"),
            bg="red",
            fg="white",
            width=15,
            height=2
        )
        cancel_btn.pack(pady=30)
        
        # Start authentication process
        self.root.after(1000, self.attempt_fingerprint_login)
    
    def show_face_auth(self):
        """Show face recognition authentication screen."""
        self.clear_screen()
        self.current_screen = "face"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='purple')
        main_frame.pack(expand=True, fill='both')
        
        # Center frame
        center_frame = tk.Frame(main_frame, bg='purple')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="👤 FACE RECOGNITION AUTHENTICATION",
            fg="white",
            bg="purple",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(50, 30))
        
        # Face icon
        self.face_icon = tk.Label(
            center_frame,
            text="👤",
            fg="white",
            bg="purple",
            font=("Helvetica", 80)
        )
        self.face_icon.pack(pady=20)
        
        # Instructions
        instructions_label = tk.Label(
            center_frame,
            text="Look directly at the camera\nEnsure your face is well-lit and visible",
            fg="lightgray",
            bg="purple",
            font=("Helvetica", 16),
            justify='center'
        )
        instructions_label.pack(pady=20)
        
        # Status label
        self.face_status = tk.Label(
            center_frame,
            text="Initializing camera...",
            fg="yellow",
            bg="purple",
            font=("Helvetica", 14)
        )
        self.face_status.pack(pady=10)
        
        # Cancel button
        cancel_btn = tk.Button(
            center_frame,
            text="← Cancel",
            command=self.show_method_selection,
            font=("Helvetica", 12, "bold"),
            bg="red",
            fg="white",
            width=15,
            height=2
        )
        cancel_btn.pack(pady=30)
        
        # Start authentication process
        self.root.after(1000, self.attempt_face_login)
    
    def attempt_password_login(self):
        """Attempt domain/password authentication."""
        username_input = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not username_input or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        # Validate domain\username format
        if '\\' not in username_input:
            username_input = f"{Config.LDAP_DOMAIN}\\{username_input}"

        # Extract domain and username
        try:
            domain, username = username_input.split('\\', 1)
            if not domain or not username:
                raise ValueError("Invalid format")
        except ValueError:
            messagebox.showerror("Error", "Invalid username format. Use domain\\username")
            return
        
        self.show_auth_loading("Authenticating with domain server...")
        
        # Simulate authentication delay
        def auth_thread():
            time.sleep(2)
            
            # Real LDAP/NTLM authentication
            try:
                ldap_auth = LDAPAuthenticator(Config())
                success, result = ldap_auth.authenticate({
                    'username': username_input,  # Pass full domain\username
                    'password': password,
                    'domain': domain
                })
                
                if success:
                    # Extract role from LDAP result
                    role = result.get('role', 'user') if isinstance(result, dict) else 'user'
                    # Use just the username part for display
                    display_username = username
                    self.root.after(0, lambda: self.handle_auth_result(True, display_username, "domain_auth", role))
                else:
                    error_msg = result if isinstance(result, str) else "Authentication failed"
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "domain_auth", error_msg))
            except Exception as e:
                error_msg = f"Domain authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "domain_auth", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def attempt_fingerprint_login(self):
        """Attempt fingerprint authentication."""
        if self.current_screen != "fingerprint":
            return
            
        self.fingerprint_status.config(text="Please place finger on sensor...")
        
        def auth_thread():
            try:
                result = self.biometric_auth.authenticate_fingerprint()
                if result:
                    self.root.after(0, lambda: self.handle_auth_result(True, result, "fingerprint", "user"))
                else:
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "fingerprint", "Fingerprint not recognized"))
            except Exception as e:
                error_msg = f"Fingerprint authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "fingerprint", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def attempt_face_login(self):
        """Attempt face recognition authentication."""
        if self.current_screen != "face":
            return
            
        self.face_status.config(text="Scanning face...")
        
        def auth_thread():
            try:
                result = self.biometric_auth.authenticate_face(timeout=30)
                if result:
                    self.root.after(0, lambda: self.handle_auth_result(True, result, "face", "user"))
                else:
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "face", "Face not recognized"))
            except Exception as e:
                error_msg = f"Face recognition error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "face", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def show_auth_loading(self, message):
        """Show authentication loading screen."""
        self.clear_screen()
        self.current_screen = "loading"
        
        # Center frame
        center_frame = tk.Frame(self.root, bg='black')
        center_frame.pack(expand=True)
        
        # Loading spinner
        spinner_label = tk.Label(
            center_frame,
            text="⟳",
            fg="cyan",
            bg="black",
            font=("Helvetica", 60)
        )
        spinner_label.pack(pady=50)
        
        # Loading message
        message_label = tk.Label(
            center_frame,
            text=message,
            fg="white",
            bg="black",
            font=("Helvetica", 18)
        )
        message_label.pack(pady=20)
    
    def handle_auth_result(self, success, username, method, role_or_error):
        """Handle authentication result."""
        if success:
            self.show_auth_success(username, role_or_error)
        else:
            self.show_auth_failure(role_or_error)
    
    def show_auth_success(self, username, role):
        """Show authentication success screen."""
        self.is_authenticated = True
        self.current_user = username
        
        SecurityUtils.log_security_event("GUI_AUTH_SUCCESS", f"GUI authentication successful for user: {username}")
        
        self.clear_screen()
        self.current_screen = "success"
        
        # Center frame
        center_frame = tk.Frame(self.root, bg='darkgreen')
        center_frame.pack(expand=True, fill='both')
        
        # Success icon
        success_icon = tk.Label(
            center_frame,
            text="✅",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 100)
        )
        success_icon.pack(pady=(100, 30))
        
        # Success message
        success_label = tk.Label(
            center_frame,
            text="AUTHENTICATION SUCCESSFUL",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 24, "bold")
        )
        success_label.pack(pady=(0, 20))
        
        # User info
        user_info = tk.Label(
            center_frame,
            text=f"Welcome, {username}\nRole: {role}",
            fg="lightgray",
            bg="darkgreen",
            font=("Helvetica", 16),
            justify='center'
        )
        user_info.pack(pady=20)
        
        # Status message
        status_label = tk.Label(
            center_frame,
            text="Starting security monitoring system...",
            fg="yellow",
            bg="darkgreen",
            font=("Helvetica", 14)
        )
        status_label.pack(pady=30)
        
        # Auto-proceed to dashboard after 3 seconds
        self.root.after(3000, self.show_main_dashboard)
    
    def show_auth_failure(self, error_message):
        """Show authentication failure screen."""
        SecurityUtils.log_security_event("GUI_AUTH_FAILED", f"GUI authentication failed: {error_message}")
        
        self.clear_screen()
        self.current_screen = "failure"
        
        # Center frame
        center_frame = tk.Frame(self.root, bg='darkred')
        center_frame.pack(expand=True, fill='both')
        
        # Failure icon
        failure_icon = tk.Label(
            center_frame,
            text="❌",
            fg="white",
            bg="darkred",
            font=("Helvetica", 100)
        )
        failure_icon.pack(pady=(100, 30))
        
        # Failure message
        failure_label = tk.Label(
            center_frame,
            text="AUTHENTICATION FAILED",
            fg="white",
            bg="darkred",
            font=("Helvetica", 24, "bold")
        )
        failure_label.pack(pady=(0, 20))
        
        # Error details
        error_label = tk.Label(
            center_frame,
            text=error_message,
            fg="lightgray",
            bg="darkred",
            font=("Helvetica", 16)
        )
        error_label.pack(pady=20)
        
        # Retry button
        retry_btn = tk.Button(
            center_frame,
            text="🔄 Retry Authentication",
            command=self.show_method_selection,
            font=("Helvetica", 14, "bold"),
            bg="red",
            fg="white",
            width=20,
            height=2
        )
        retry_btn.pack(pady=30)
    
    def show_main_dashboard(self):
        """Show main system dashboard."""
        self.clear_screen()
        self.current_screen = "dashboard"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='navy')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg='darkblue', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title and user info
        title_label = tk.Label(
            header_frame,
            text="🔒 PHYSICAL SECURITY SYSTEM - ACTIVE",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        user_label = tk.Label(
            header_frame,
            text=f"User: {self.current_user} | Status: AUTHENTICATED",
            fg="lightgreen",
            bg="darkblue",
            font=("Helvetica", 12)
        )
        user_label.pack(side='right', padx=20, pady=20)
        
        # Content area
        content_frame = tk.Frame(main_frame, bg='navy')
        content_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Status message
        status_label = tk.Label(
            content_frame,
            text="✅ Authentication Complete\n🔍 Object Detection System Starting...\n📹 Camera Monitoring Active\n🔒 Security Overlay Ready",
            fg="white",
            bg="navy",
            font=("Helvetica", 16),
            justify='left'
        )
        status_label.pack(pady=50)
        
        # Minimize to tray button
        minimize_btn = tk.Button(
            content_frame,
            text="⬇ Minimize to System Tray",
            command=self.minimize_to_system_tray,
            font=("Helvetica", 12, "bold"),
            bg="gray",
            fg="white",
            width=25,
            height=2
        )
        minimize_btn.pack(pady=20)
        
        # Logout button
        logout_btn = tk.Button(
            content_frame,
            text="🚪 Logout",
            command=self.logout,
            font=("Helvetica", 12, "bold"),
            bg="red",
            fg="white",
            width=25,
            height=2
        )
        logout_btn.pack(pady=10)
    
    def minimize_to_system_tray(self):
        """Minimize GUI to system tray."""
        self.root.iconify()
        print("GUI minimized to system tray. Detection system continues running.")
    
    def logout(self):
        """Logout and return to authentication screen."""
        self.is_authenticated = False
        self.current_user = None
        SecurityUtils.log_security_event("GUI_LOGOUT", "User logged out from GUI")
        self.show_login_screen()
    
    def show_security_error(self, title, message):
        """Show security error dialog."""
        messagebox.showerror(title, message, parent=self.root)


if __name__ == "__main__":
    # Test the GUI
    gui = SecurityGUI()
    gui.run()
