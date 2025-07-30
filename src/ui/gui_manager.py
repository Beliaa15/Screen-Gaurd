"""
GUI Manager for Physical Security System
Provides full-screen startup screen, login interface, and dashboard.
"""

import mttkinter.mtTkinter as tk
import threading
import time
from datetime import datetime
import subprocess
import sys
from pathlib import Path

from ..core.config import Config
from ..utils.security_utils import SecurityUtils
from ..auth.ldap_auth import LDAPAuthenticator
from ..auth.deepface_auth import DeepFaceAuthenticator


class SecurityGUI:
    """Main GUI class for the Physical Security System."""
    
    def __init__(self, auth_manager=None, detector_service=None):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.auth_manager = auth_manager
        self.deepface_auth = DeepFaceAuthenticator()
        self.detector_service = detector_service  # Reference to detection service
        self.is_authenticated = False
        self.current_user = None
        self.current_role = None
        self.current_screen = None
        self.is_minimized = False
        self.detection_running = False
        
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
        
        # Setup window event handlers for minimize/restore detection
        self.setup_window_events()
        
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
    
    def show_custom_dialog(self, title, message, dialog_type="info", input_field=False, password=False, callback=None):
        """Show a custom dialog within the GUI."""
        # Create overlay
        self.dialog_overlay = tk.Frame(self.root, bg='black')
        self.dialog_overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self.dialog_overlay.configure(bg='black')
        self.dialog_overlay.attributes = lambda: None  # Prevent attribute errors
        
        # Center the dialog
        dialog_frame = tk.Frame(self.dialog_overlay, bg='darkblue', bd=3, relief='raised')
        dialog_frame.place(relx=0.5, rely=0.5, anchor='center', width=500, height=300)
        
        # Title
        title_label = tk.Label(
            dialog_frame,
            text=title,
            fg="white",
            bg="darkblue",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=20)
        
        # Message
        message_label = tk.Label(
            dialog_frame,
            text=message,
            fg="lightgray",
            bg="darkblue",
            font=("Helvetica", 12),
            wraplength=400,
            justify='center'
        )
        message_label.pack(pady=10)
        
        # Input field if needed
        self.dialog_input = None
        if input_field:
            self.dialog_input = tk.Entry(
                dialog_frame,
                font=("Helvetica", 12),
                width=30,
                show="*" if password else ""
            )
            self.dialog_input.pack(pady=20)
            self.dialog_input.focus_set()
        
        # Buttons frame
        buttons_frame = tk.Frame(dialog_frame, bg='darkblue')
        buttons_frame.pack(pady=20)
        
        if dialog_type == "yesno":
            # Yes button
            yes_btn = tk.Button(
                buttons_frame,
                text="Yes",
                command=lambda: self._close_dialog_with_result(True, callback),
                font=("Helvetica", 12, "bold"),
                bg="green",
                fg="white",
                width=10
            )
            yes_btn.pack(side='left', padx=10)
            
            # No button
            no_btn = tk.Button(
                buttons_frame,
                text="No",
                command=lambda: self._close_dialog_with_result(False, callback),
                font=("Helvetica", 12, "bold"),
                bg="red",
                fg="white",
                width=10
            )
            no_btn.pack(side='left', padx=10)
        elif input_field:
            # OK button for input
            ok_btn = tk.Button(
                buttons_frame,
                text="OK",
                command=lambda: self._close_dialog_with_input(callback),
                font=("Helvetica", 12, "bold"),
                bg="blue",
                fg="white",
                width=10
            )
            ok_btn.pack(side='left', padx=10)
            
            # Cancel button for input
            cancel_btn = tk.Button(
                buttons_frame,
                text="Cancel",
                command=lambda: self._close_dialog_with_result(None, callback),
                font=("Helvetica", 12, "bold"),
                bg="gray",
                fg="white",
                width=10
            )
            cancel_btn.pack(side='left', padx=10)
            
            # Bind Enter key
            if self.dialog_input:
                self.dialog_input.bind('<Return>', lambda e: self._close_dialog_with_input(callback))
        else:
            # OK button for info/error
            ok_btn = tk.Button(
                buttons_frame,
                text="OK",
                command=lambda: self._close_dialog_with_result(True, callback),
                font=("Helvetica", 12, "bold"),
                bg="blue",
                fg="white",
                width=15
            )
            ok_btn.pack()
    
    def _close_dialog_with_result(self, result, callback):
        """Close dialog and execute callback with result."""
        if hasattr(self, 'dialog_overlay'):
            self.dialog_overlay.destroy()
        if callback:
            callback(result)
    
    def _close_dialog_with_input(self, callback):
        """Close dialog and execute callback with input value."""
        value = self.dialog_input.get() if self.dialog_input else None
        if hasattr(self, 'dialog_overlay'):
            self.dialog_overlay.destroy()
        if callback:
            callback(value)

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
        
        # DeepFace Recognition button (Advanced)
        deepface_btn = tk.Button(
            methods_frame,
            text="🧠 Face Recognition",
            command=lambda: self.select_auth_method("deepface"),
            font=("Helvetica", 16, "bold"),
            bg="darkviolet",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        deepface_btn.pack(pady=10)
    
    def select_auth_method(self, method):
        """Handle authentication method selection."""
        if method == "email_password":  # Keep the same method name for compatibility
            self.show_domain_auth_form()
        elif method == "fingerprint":
            self.show_fingerprint_auth()
        elif method == "deepface":
            self.show_deepface_auth()
    
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
    
    def attempt_password_login(self):
        """Attempt domain/password authentication."""
        username_input = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not username_input or not password:
            self.show_custom_dialog("Error", "Please enter both username and password", "error")
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
            self.show_custom_dialog("Error", "Invalid username format. Use domain\\username", "error")
            return
        
        self.show_auth_loading("Authenticating with domain server...")
        
        # Simulate authentication delay
        def auth_thread():
            try:
                ldap_auth = LDAPAuthenticator(Config())
                success, result = ldap_auth.authenticate({
                    'username': username_input,
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
    
    def show_deepface_auth(self):
        """Show DeepFace authentication screen."""
        self.clear_screen()
        self.current_screen = "deepface"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkviolet')
        main_frame.pack(expand=True, fill='both')
        
        # Center frame
        center_frame = tk.Frame(main_frame, bg='darkviolet')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="🧠 ADVANCED FACE RECOGNITION",
            fg="white",
            bg="darkviolet",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(50, 30))
        
        # DeepFace icon (animated brain)
        self.deepface_icon = tk.Label(
            center_frame,
            text="🧠",
            fg="cyan",
            bg="darkviolet",
            font=("Helvetica", 80)
        )
        self.deepface_icon.pack(pady=20)
        
        # Instructions
        instructions_label = tk.Label(
            center_frame,
            text="Look directly at the camera\nAdvanced AI processing - please be patient\nEnsure good lighting and clear face visibility",
            fg="lightgray",
            bg="darkviolet",
            font=("Helvetica", 16),
            justify='center'
        )
        instructions_label.pack(pady=20)
        
        # Status label
        self.deepface_status = tk.Label(
            center_frame,
            text="Initializing AI models...",
            fg="yellow",
            bg="darkviolet",
            font=("Helvetica", 14)
        )
        self.deepface_status.pack(pady=10)
        
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
        self.root.after(2000, self.attempt_deepface_login)
    
    def attempt_deepface_login(self):
        """Attempt DeepFace authentication."""
        if self.current_screen != "deepface":
            return
            
        self.deepface_status.config(text="Scanning with AI models...")
        
        def auth_thread():
            try:
                result = self.deepface_auth.authenticate_face(timeout=30)
                if result:
                    username = result['username']
                    role = result.get('role', 'user')
                    
                    # Check if password is required for LDAP authentication
                    if result.get('requires_password') or (result.get('password_hash') and result.get('salt')):
                        # Face recognized, now need password for LDAP
                        self.root.after(0, lambda: self.prompt_password_for_ldap(username, result))
                    else:
                        # Face authentication only (no stored password)
                        self.root.after(0, lambda: self.handle_auth_result(True, username, "deepface", role))
                else:
                    self.root.after(0, lambda: self.handle_auth_result(False, None, "deepface", "Face not recognized by AI"))
            except Exception as e:
                error_msg = f"DeepFace authentication error: {str(e)}"
                self.root.after(0, lambda: self.handle_auth_result(False, None, "deepface", error_msg))
        
        threading.Thread(target=auth_thread, daemon=True).start()
    
    def prompt_password_for_ldap(self, username, face_result):
        """Prompt for password after successful face recognition for LDAP authentication."""
        self.clear_screen()
        self.current_screen = "password_prompt"
        
        # Center frame
        center_frame = tk.Frame(self.root, bg='black')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text=f"Face Recognized: {username}",
            fg="cyan",
            bg="black",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack(pady=30)
        
        # Subtitle
        subtitle_label = tk.Label(
            center_frame,
            text="Enter password for domain authentication",
            fg="white",
            bg="black",
            font=("Helvetica", 14)
        )
        subtitle_label.pack(pady=10)
        
        # Password entry
        password_frame = tk.Frame(center_frame, bg='black')
        password_frame.pack(pady=30)
        
        password_entry = tk.Entry(
            password_frame,
            font=("Helvetica", 16),
            width=25,
            show="*",
            bg="white",
            fg="black",
            insertbackground="black"
        )
        password_entry.pack(pady=10)
        password_entry.focus()
        
        # Status label
        status_label = tk.Label(
            center_frame,
            text="",
            fg="red",
            bg="black",
            font=("Helvetica", 12)
        )
        status_label.pack(pady=10)
        
        # Buttons frame
        button_frame = tk.Frame(center_frame, bg='black')
        button_frame.pack(pady=20)
        
        def authenticate_with_password():
            password = password_entry.get().strip()
            if not password:
                status_label.config(text="Password cannot be empty")
                return
            
            status_label.config(text="Authenticating with domain...", fg="yellow")
            
            def ldap_auth_thread():
                try:
                    result = self.deepface_auth.authenticate_user_with_stored_password(username, password)
                    if result:
                        role = result.get('role', 'user')
                        self.root.after(0, lambda: self.handle_auth_result(True, username, "face_and_ldap", role))
                    else:
                        self.root.after(0, lambda: status_label.config(text="Invalid password or domain authentication failed", fg="red"))
                except Exception as e:
                    error_msg = f"Authentication error: {str(e)}"
                    self.root.after(0, lambda: status_label.config(text=error_msg, fg="red"))
            
            threading.Thread(target=ldap_auth_thread, daemon=True).start()
        
        def cancel_auth():
            self.show_method_selection()
        
        # Login button
        login_btn = tk.Button(
            button_frame,
            text="Authenticate",
            command=authenticate_with_password,
            font=("Helvetica", 14, "bold"),
            bg="green",
            fg="white",
            padx=20,
            pady=10
        )
        login_btn.pack(side=tk.LEFT, padx=10)
        
        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=cancel_auth,
            font=("Helvetica", 14),
            bg="red",
            fg="white",
            padx=20,
            pady=10
        )
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        # Bind Enter key to authenticate
        password_entry.bind('<Return>', lambda e: authenticate_with_password())
    
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
        self.current_role = role
        
        SecurityUtils.log_security_event("GUI_AUTH_SUCCESS", f"GUI authentication successful for user: {username}")
        
        # Show quick success message then go to dashboard
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
            text=f"Welcome, {username}",
            fg="lightgray",
            bg="darkgreen",
            font=("Helvetica", 16),
            justify='center'
        )
        user_info.pack(pady=20)
        
        # Auto-proceed to dashboard after 2 seconds
        self.root.after(2000, self.show_dashboard)
    
    def show_dashboard(self):
        """Show the main dashboard after successful authentication."""
        self.clear_screen()
        self.current_screen = "dashboard"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkblue')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg='navy', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title and user info
        title_label = tk.Label(
            header_frame,
            text="🔒 PHYSICAL SECURITY SYSTEM - DASHBOARD",
            fg="white",
            bg="navy",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        user_info = f"User: {self.current_user}"
        if self.current_role:
            user_info += f" | Role: {self.current_role.upper()}"
        user_info += " | Status: AUTHENTICATED"
        
        user_label = tk.Label(
            header_frame,
            text=user_info,
            fg="lightgreen",
            bg="navy",
            font=("Helvetica", 12)
        )
        user_label.pack(side='right', padx=20, pady=20)
        
        # Content area
        content_frame = tk.Frame(main_frame, bg='darkblue')
        content_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Welcome section
        welcome_frame = tk.Frame(content_frame, bg='darkblue')
        welcome_frame.pack(fill='x', pady=(0, 30))
        
        welcome_label = tk.Label(
            welcome_frame,
            text=f"Welcome, {self.current_user}!",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 24, "bold")
        )
        welcome_label.pack()
        
        # Dynamic status based on detection state
        detection_status = "🔍 Detection: Inactive (GUI active)" if not self.detection_running else "🔍 Detection: Active"
        camera_status = "📹 Camera: Available for Face Registration" if not self.detection_running else "📹 Camera: In use by Detection"
        
        status_label = tk.Label(
            welcome_frame,
            text=f"✅ Authentication Complete\n{detection_status}\n{camera_status}\n💡 Minimize window to start detection\n⌨️  Press Ctrl+Shift+R to restore from tray",
            fg="lightgray",
            bg="darkblue",
            font=("Helvetica", 14),
            justify='center'
        )
        status_label.pack(pady=10)
        
        # Control buttons section
        controls_frame = tk.Frame(content_frame, bg='darkblue')
        controls_frame.pack(fill='both', pady=(0, 10))
        
        # Admin controls (only show for admin users)
        if self.current_role and self.current_role.lower() in ['admin', 'administrator']:
            admin_frame = tk.LabelFrame(controls_frame, text="Administrator Controls", 
                                       font=("Helvetica", 14, "bold"), fg="gold", bg="darkblue")
            admin_frame.pack(pady=10, padx=20, fill='x')
            
            # User Management button
            user_mgmt_btn = tk.Button(
                admin_frame,
                text="👥 User Management",
                command=self.show_user_management,
                font=("Helvetica", 14, "bold"),
                bg="gold",
                fg="black",
                width=20,
                height=2,
                relief="raised",
                bd=3
            )
            user_mgmt_btn.pack(pady=10, padx=10, side='left')

            # View Logs button
            logs_btn = tk.Button(
                admin_frame,
                text="📋 View Security Logs",
                command=self.show_security_logs,
                font=("Helvetica", 14, "bold"),
                bg="blue",
                fg="white",
                width=20,
                height=2,
                relief="raised",
                bd=3
            )
            logs_btn.pack(pady=10, padx=10, side='left')
        
        # Common controls
        common_frame = tk.LabelFrame(controls_frame, text="System Controls", 
                                   font=("Helvetica", 14, "bold"), fg="lightblue", bg="darkblue")
        common_frame.pack(pady=10, padx=20, fill='x')

        # Bottom controls
        bottom_frame = tk.Frame(content_frame, bg='darkblue')
        bottom_frame.pack(side='bottom', fill='x', pady=10)

        # Logout button
        logout_btn = tk.Button(
            bottom_frame,
            text="🚪 Logout",
            command=self.logout,
            font=("Helvetica", 12, "bold"),
            bg="red",
            fg="white",
            width=15,
            height=2
        )
        logout_btn.pack(side='right', padx=10)

        # Minimize to tray button (right beside logout)
        minimize_btn = tk.Button(
            bottom_frame,
            text="⬇ Minimize & Start Detection",
            command=self.minimize_to_system_tray,
            font=("Helvetica", 12, "bold"),
            bg="darkgreen",
            fg="white",
            width=25,
            height=2
        )
        minimize_btn.pack(side='right', padx=10)
        
        # System info
        info_label = tk.Label(
            bottom_frame,
            text="Physical Security System v2.0 | Status: Active",
            fg="lightgray",
            bg="darkblue",
            font=("Helvetica", 10)
        )
        info_label.pack(side='left', padx=20)
    
    def show_user_management(self):
        """Show the user management interface within the GUI."""
        self.clear_screen()
        self.current_screen = "user_management"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkblue')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg='navy', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title and back button
        title_label = tk.Label(
            header_frame,
            text="👥 USER MANAGEMENT",
            fg="white",
            bg="navy",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        back_btn = tk.Button(
            header_frame,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            font=("Helvetica", 12, "bold"),
            bg="gray",
            fg="white",
            width=20,
            height=2
        )
        back_btn.pack(side='right', padx=20, pady=15)
        
        # Content area
        content_frame = tk.Frame(main_frame, bg='darkblue')
        content_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Face Registration Section
        face_frame = tk.LabelFrame(content_frame, text="Face Registration (DeepFace)", 
                                  font=("Helvetica", 12, "bold"), fg="gold", bg="darkblue")
        face_frame.pack(fill='x', pady=10)
        
        tk.Button(
            face_frame,
            text="📷 Register Face (Camera)",
            command=self.register_face_camera,
            font=("Helvetica", 11, "bold"),
            bg="darkgreen",
            fg="white",
            width=25,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            face_frame,
            text="🖼️ Register Face (Image)",
            command=self.register_face_image,
            font=("Helvetica", 11, "bold"),
            bg="darkblue",
            fg="white",
            width=25,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        # LDAP User Creation Section
        ldap_frame = tk.LabelFrame(content_frame, text="LDAP User + Face Registration", 
                                  font=("Helvetica", 12, "bold"), fg="cyan", bg="darkblue")
        ldap_frame.pack(fill='x', pady=10)
        
        tk.Button(
            ldap_frame,
            text="🆕 Create LDAP User (Camera)",
            command=self.create_ldap_user_camera,
            font=("Helvetica", 11, "bold"),
            bg="darkslategray",
            fg="white",
            width=25,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            ldap_frame,
            text="🆕 Create LDAP User (Image)",
            command=self.create_ldap_user_image,
            font=("Helvetica", 11, "bold"),
            bg="steelblue",
            fg="white",
            width=25,
            height=2
        ).pack(pady=10, padx=10, side='left')

        # User Management Section
        user_frame = tk.LabelFrame(content_frame, text="User Management", 
                                  font=("Helvetica", 12, "bold"), fg="lightblue", bg="darkblue")
        user_frame.pack(fill='x', pady=10)
        
        tk.Button(
            user_frame,
            text="📋 List Users",
            command=self.list_registered_users,
            font=("Helvetica", 11, "bold"),
            bg="purple",
            fg="white",
            width=20,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            user_frame,
            text="🗑️ Delete User",
            command=self.delete_user_face,
            font=("Helvetica", 11, "bold"),
            bg="darkred",
            fg="white",
            width=20,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        # Authentication Testing Section
        test_frame = tk.LabelFrame(content_frame, text="Authentication Testing", 
                                  font=("Helvetica", 12, "bold"), fg="orange", bg="darkblue")
        test_frame.pack(fill='x', pady=10)
        
        tk.Button(
            test_frame,
            text="🧠 Test DeepFace",
            command=self.test_deepface_auth,
            font=("Helvetica", 11, "bold"),
            bg="darkviolet",
            fg="white",
            width=20,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            test_frame,
            text="🔐 Test LDAP",
            command=self.test_ldap_auth,
            font=("Helvetica", 11, "bold"),
            bg="orange",
            fg="white",
            width=20,
            height=2
        ).pack(pady=10, padx=10, side='left')
        
        # Output area
        output_frame = tk.LabelFrame(content_frame, text="Output", 
                                    font=("Helvetica", 12, "bold"), fg="white", bg="darkblue")
        output_frame.pack(fill='both', expand=True, pady=10)
        
        # Create text widget with scrollbar
        text_frame = tk.Frame(output_frame, bg='darkblue')
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.user_mgmt_output = tk.Text(
            text_frame,
            height=15,
            font=("Courier", 10),
            bg='black',
            fg='lightgreen',
            wrap=tk.WORD
        )
        self.user_mgmt_output.pack(side='left', fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, command=self.user_mgmt_output.yview)
        scrollbar.pack(side='right', fill='y')
        self.user_mgmt_output.config(yscrollcommand=scrollbar.set)
        
        self.log_user_mgmt_output("User Management interface loaded. Select an operation above.")
        
        # Show camera/detection status
        if self.detection_running:
            self.log_user_mgmt_output("⚠️  WARNING: Detection system is currently running")
            self.log_user_mgmt_output("📹 Camera is being used by detection system")
            self.log_user_mgmt_output("💡 Face registration from camera may fail")
            self.log_user_mgmt_output("🔧 Consider using 'Register Face (Image)' instead")
        else:
            self.log_user_mgmt_output("✅ Camera available for face registration")
            self.log_user_mgmt_output("📹 Detection system inactive - GUI mode active")
    
    def show_security_logs(self):
        """Show the security logs interface within the GUI."""
        self.clear_screen()
        self.current_screen = "security_logs"
        
        # Main container
        main_frame = tk.Frame(self.root, bg='darkblue')
        main_frame.pack(expand=True, fill='both')
        
        # Header
        header_frame = tk.Frame(main_frame, bg='navy', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Title and back button
        title_label = tk.Label(
            header_frame,
            text="📋 SECURITY LOGS",
            fg="white",
            bg="navy",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        back_btn = tk.Button(
            header_frame,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            font=("Helvetica", 12, "bold"),
            bg="gray",
            fg="white",
            width=20,
            height=2
        )
        back_btn.pack(side='right', padx=20, pady=15)
        
        # Content area
        content_frame = tk.Frame(main_frame, bg='darkblue')
        content_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Controls section
        controls_frame = tk.Frame(content_frame, bg='darkblue')
        controls_frame.pack(fill='x', pady=(0, 10))
        
        tk.Button(
            controls_frame,
            text="🔄 Refresh Logs",
            command=self.refresh_security_logs,
            font=("Helvetica", 11, "bold"),
            bg="green",
            fg="white",
            width=15,
            height=2
        ).pack(side='left', padx=10)
        
        tk.Button(
            controls_frame,
            text="📅 Today's Logs",
            command=lambda: self.filter_logs_by_date("today"),
            font=("Helvetica", 11, "bold"),
            bg="blue",
            fg="white",
            width=15,
            height=2
        ).pack(side='left', padx=10)
        
        tk.Button(
            controls_frame,
            text="🗂️ All Logs",
            command=lambda: self.filter_logs_by_date("all"),
            font=("Helvetica", 11, "bold"),
            bg="purple",
            fg="white",
            width=15,
            height=2
        ).pack(side='left', padx=10)
        
        # Log display area
        log_frame = tk.LabelFrame(content_frame, text="Security Log Entries", 
                                 font=("Helvetica", 12, "bold"), fg="white", bg="darkblue")
        log_frame.pack(fill='both', expand=True)
        
        # Create text widget with scrollbar
        text_frame = tk.Frame(log_frame, bg='darkblue')
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.logs_output = tk.Text(
            text_frame,
            font=("Courier", 9),
            bg='black',
            fg='lightgreen',
            wrap=tk.WORD
        )
        self.logs_output.pack(side='left', fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, command=self.logs_output.yview)
        scrollbar.pack(side='right', fill='y')
        self.logs_output.config(yscrollcommand=scrollbar.set)
        
        # Load initial logs
        self.refresh_security_logs()
    
    def open_user_management(self):
        """Deprecated - replaced by show_user_management."""
        self.show_user_management()
    
    def view_security_logs(self):
        """Deprecated - replaced by show_security_logs."""
        self.show_security_logs()
    
    def log_user_mgmt_output(self, message: str):
        """Log message to user management output area."""
        if hasattr(self, 'user_mgmt_output'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}\n"
            self.user_mgmt_output.insert(tk.END, formatted_message)
            self.user_mgmt_output.see(tk.END)
            self.root.update_idletasks()
    
    def register_face_camera(self):
        """Register face from camera."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                self.log_user_mgmt_output(f"Starting face registration for user: {username}")
                self.log_user_mgmt_output("⚠️  Important: If detection system is running, camera access may conflict")
                self.log_user_mgmt_output("📷 Attempting to access camera for face capture...")
                
                def registration_thread():
                    try:
                        # Show warning about potential camera conflicts
                        self.root.after(0, lambda: self.log_user_mgmt_output("🔄 Checking camera availability..."))
                        
                        success = self.deepface_auth.register_face(username, first_name="", last_name="", 
                                                                 email="", role="user", image_path=None, password=password)
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Face registered successfully for {username}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Success", 
                                f"Face registered successfully for {username}!\n\nThe user can now authenticate using face recognition.", "info"))
                        else:
                            error_msg = f"Face registration failed for {username}"
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("💡 Troubleshooting tips:"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Ensure camera is not being used by detection system"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Check camera permissions"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   - Try using image registration instead"))
                            
                            detailed_error = """Face registration failed. 
                            Ensure good lighting and clear face visibility"""
                            
                            self.root.after(0, lambda: self.show_custom_dialog("Registration Failed", detailed_error, "error"))
                    except Exception as e:
                        error_msg = f"Error during face registration: {str(e)}"
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                        
                        # Provide specific guidance based on the error
                        if "cannot access camera" in str(e).lower() or "msmf" in str(e).lower():
                            self.root.after(0, lambda: self.log_user_mgmt_output("🔧 Camera access error detected"))
                            self.root.after(0, lambda: self.log_user_mgmt_output("   This usually means another process is using the camera"))
                            troubleshoot_msg = """Camera Access Error

The camera is likely being used by:
• Object detection system
• Another application
• System monitoring
"""
                        else:
                            troubleshoot_msg = f"Face Registration Error\n\nError: {str(e)}\n\nPlease try again or use image registration instead."
                        
                        self.root.after(0, lambda: self.show_custom_dialog("Error", troubleshoot_msg, "error"))
                
                threading.Thread(target=registration_thread, daemon=True).start()
            
            self.show_custom_dialog("Password", f"Enter password for {username}:", "info", input_field=True, password=True, callback=on_password_input)

        # Show initial warning about camera usage
        def proceed_with_registration():
            self.show_custom_dialog("Username", "Enter username for face registration:", "info", input_field=True, callback=on_username_input)
        
        warning_msg = """⚠️ Important Notes
• Press SPACE to capture your face
• Press ESC to cancel
• Ensure good lighting for best results
"""
        
        self.show_custom_dialog("Camera Registration", warning_msg, "yesno", callback=lambda confirmed: proceed_with_registration() if confirmed else None)

    def register_face_image(self):
        """Register face from image file."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                # Show file selection dialog within the GUI
                self.show_file_selection_dialog("Select face image", [("Image files", "*.jpg *.jpeg *.png *.bmp")], 
                                               lambda image_path: self._process_image_registration(username, password, image_path))
            
            self.show_custom_dialog("Password", "Enter password for LDAP authentication:", "info", input_field=True, callback=on_password_input, password=True)
        
        self.show_custom_dialog("Username", "Enter username for face registration:", "info", input_field=True, callback=on_username_input)
    
    def show_file_selection_dialog(self, title, filetypes, callback):
        """Show file selection dialog within GUI."""
        # For now, we'll use a simple text input for the file path
        # In a full implementation, you could create a file browser within the GUI
        def on_path_input(file_path):
            if file_path and callback:
                callback(file_path)
        
        self.show_custom_dialog("File Path", f"{title}\nEnter full path to image file:", "info", input_field=True, callback=on_path_input)
    
    def _process_image_registration(self, username, password, image_path):
        """Process image registration with given username, password and path."""
        if not image_path:
            return
        
        self.log_user_mgmt_output(f"Registering face from image for user: {username}")
        self.log_user_mgmt_output(f"Image path: {image_path}")
        
        def registration_thread():
            try:
                success = self.deepface_auth.register_face(username, image_path, password=password)
                if success:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Face registered successfully for {username}"))
                    self.root.after(0, lambda: self.show_custom_dialog("Success", f"Face registered successfully for {username}", "info"))
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Face registration failed for {username}"))
                    self.root.after(0, lambda: self.show_custom_dialog("Error", f"Face registration failed for {username}", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error during face registration: {e}"))
                self.root.after(0, lambda: self.show_custom_dialog("Error", f"Face registration error: {e}", "error"))
        
        threading.Thread(target=registration_thread, daemon=True).start()
    
    def list_registered_users(self):
        """List all registered users."""
        self.log_user_mgmt_output("Retrieving list of registered users...")
        
        def list_thread():
            try:
                users = self.deepface_auth.list_registered_faces()
                if users:
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ Found {len(users)} registered users:"))
                    for user in users:
                        if isinstance(user, dict):
                            user_info = f"  - {user.get('first_name', '')} {user.get('last_name', '')} ({user.get('username', 'N/A')})"
                            if user.get('email'):
                                user_info += f" - {user['email']}"
                            if user.get('role'):
                                user_info += f" [{user['role']}]"
                            # Fix closure issue by capturing user_info in a new scope
                            self.root.after(0, self._log_user_info, user_info)
                        else:
                            user_info = f"  - {user}"
                            self.root.after(0, self._log_user_info, user_info)
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output("No registered users found."))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error retrieving users: {e}"))
        
        threading.Thread(target=list_thread, daemon=True).start()
    
    def _log_user_info(self, user_info):
        """Helper method to log user info (fixes closure issues)."""
        self.log_user_mgmt_output(user_info)
    
    def delete_user_face(self):
        """Delete a user's face registration."""
        def on_username_input(username):
            if not username:
                return
            
            def on_confirmation(confirmed):
                if not confirmed:
                    return
                
                self.log_user_mgmt_output(f"Deleting user registration for: {username}")
                
                def delete_thread():
                    try:
                        success = self.deepface_auth.delete_face(username)
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ User {username} deleted successfully"))
                            self.root.after(0, lambda: self.show_custom_dialog("Success", f"User {username} deleted successfully", "info"))
                        else:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Failed to delete user {username}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Error", f"Failed to delete user {username}", "error"))
                    except Exception as e:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ Error deleting user: {e}"))
                        self.root.after(0, lambda: self.show_custom_dialog("Error", f"Error deleting user: {e}", "error"))
                
                threading.Thread(target=delete_thread, daemon=True).start()
            
            self.show_custom_dialog("Confirm Deletion", f"Are you sure you want to delete user '{username}'?", "yesno", callback=on_confirmation)
        
        self.show_custom_dialog("Delete User", "Enter username to delete:", "info", input_field=True, callback=on_username_input)
    
    def test_deepface_auth(self):
        """Test DeepFace recognition authentication."""
        self.log_user_mgmt_output("Starting DeepFace recognition test...")
        
        def test_thread():
            try:
                result = self.deepface_auth.authenticate_face(timeout=30)
                if result:
                    user_info = f"{result.get('first_name', '')} {result.get('last_name', '')} ({result.get('username', 'N/A')})"
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ DeepFace authentication successful for user: {user_info}"))
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Role: {result.get('role', 'N/A')}"))
                    self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Email: {result.get('email', 'N/A')}"))
                    if 'euclidean_distance' in result:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Euclidean Distance: {result['euclidean_distance']:.4f}"))
                    if 'cosine_similarity' in result:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"   - Cosine Similarity: {result['cosine_similarity']:.4f}"))
                    success_msg = f"DeepFace authentication successful!\nUser: {user_info}\nRole: {result.get('role', 'N/A')}"
                    self.root.after(0, lambda: self.show_custom_dialog("Success", success_msg, "info"))
                else:
                    self.root.after(0, lambda: self.log_user_mgmt_output("❌ DeepFace authentication failed or timed out"))
                    self.root.after(0, lambda: self.show_custom_dialog("Failed", "DeepFace authentication failed or timed out", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ DeepFace authentication error: {e}"))
                self.root.after(0, lambda: self.show_custom_dialog("Error", f"DeepFace authentication error: {e}", "error"))
        
        threading.Thread(target=test_thread, daemon=True).start()
    
    def test_ldap_auth(self):
        """Test LDAP authentication."""
        def on_username_input(username):
            if not username:
                return
            
            def on_password_input(password):
                if not password:
                    return
                
                self.log_user_mgmt_output(f"Testing LDAP authentication for user: {username}")
                
                def test_thread():
                    try:
                        ldap_auth = LDAPAuthenticator(Config())
                        success, result = ldap_auth.authenticate({
                            'username': username,
                            'password': password
                        })
                        
                        if success:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ LDAP authentication successful for {username}"))
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"User info: {result}"))
                            role = result.get('role', 'Unknown') if isinstance(result, dict) else 'User'
                            success_msg = f"LDAP authentication successful!\nUser: {username}\nRole: {role}"
                            self.root.after(0, lambda: self.show_custom_dialog("Success", success_msg, "info"))
                        else:
                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ LDAP authentication failed: {result}"))
                            self.root.after(0, lambda: self.show_custom_dialog("Error", f"LDAP authentication failed: {result}", "error"))
                    except Exception as e:
                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ LDAP authentication error: {e}"))
                        self.root.after(0, lambda: self.show_custom_dialog("Error", f"LDAP authentication error: {e}", "error"))
                
                threading.Thread(target=test_thread, daemon=True).start()
            
            self.show_custom_dialog("LDAP Test", "Enter password:", "info", input_field=True, password=True, callback=on_password_input)
        
        self.show_custom_dialog("LDAP Test", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def create_ldap_user_camera(self):
        """Create LDAP user and register face from camera."""
        def on_username_input(username):
            if not username:
                return
            
            def on_first_name_input(first_name):
                def on_last_name_input(last_name):
                    def on_email_input(email):
                        def on_role_selection(role):
                            if not role:
                                role = "user"
                            
                            self.log_user_mgmt_output(f"Creating LDAP user with face registration: {username}")
                            self.log_user_mgmt_output(f"Name: {first_name} {last_name}, Role: {role}, Email: {email}")
                            
                            def creation_thread():
                                try:
                                    success, message = self.deepface_auth.create_ldap_user_with_face(
                                        username=username,
                                        first_name=first_name or "",
                                        last_name=last_name or "",
                                        email=email or "",
                                        role=role,
                                        image_path=None  # Camera capture
                                    )
                                    
                                    if success:
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ {message}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Success", message, "info"))
                                    else:
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {message}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Error", message, "error"))
                                except Exception as e:
                                    error_msg = f"Error creating LDAP user with face: {e}"
                                    self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                                    self.root.after(0, lambda: self.show_custom_dialog("Error", error_msg, "error"))
                            
                            threading.Thread(target=creation_thread, daemon=True).start()
                        
                        # Role selection dialog
                        role_options = ["user", "operator", "admin"]
                        self.show_selection_dialog("Select Role", "Choose user role:", role_options, on_role_selection)
                    
                    self.show_custom_dialog("Email", "Enter email address (optional):", "info", input_field=True, callback=on_email_input)
                
                self.show_custom_dialog("Last Name", "Enter last name (optional):", "info", input_field=True, callback=on_last_name_input)
            
            self.show_custom_dialog("First Name", "Enter first name (optional):", "info", input_field=True, callback=on_first_name_input)
        
        self.show_custom_dialog("Create LDAP User", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def create_ldap_user_image(self):
        """Create LDAP user and register face from image file."""
        def on_username_input(username):
            if not username:
                return
            
            def on_first_name_input(first_name):
                def on_last_name_input(last_name):
                    def on_email_input(email):
                        def on_role_selection(role):
                            if not role:
                                role = "user"
                            
                            def on_image_path_input(image_path):
                                if not image_path:
                                    return
                                
                                self.log_user_mgmt_output(f"Creating LDAP user with face registration: {username}")
                                self.log_user_mgmt_output(f"Name: {first_name} {last_name}, Role: {role}, Email: {email}")
                                self.log_user_mgmt_output(f"Image path: {image_path}")
                                
                                def creation_thread():
                                    try:
                                        success, message = self.deepface_auth.create_ldap_user_with_face(
                                            username=username,
                                            first_name=first_name or "",
                                            last_name=last_name or "",
                                            email=email or "",
                                            role=role,
                                            image_path=image_path
                                        )
                                        
                                        if success:
                                            self.root.after(0, lambda: self.log_user_mgmt_output(f"✅ {message}"))
                                            self.root.after(0, lambda: self.show_custom_dialog("Success", message, "info"))
                                        else:
                                            self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {message}"))
                                            self.root.after(0, lambda: self.show_custom_dialog("Error", message, "error"))
                                    except Exception as e:
                                        error_msg = f"Error creating LDAP user with face: {e}"
                                        self.root.after(0, lambda: self.log_user_mgmt_output(f"❌ {error_msg}"))
                                        self.root.after(0, lambda: self.show_custom_dialog("Error", error_msg, "error"))
                                
                                threading.Thread(target=creation_thread, daemon=True).start()
                            
                            self.show_custom_dialog("Image Path", "Enter full path to image file:", "info", input_field=True, callback=on_image_path_input)
                        
                        # Role selection dialog
                        role_options = ["user", "operator", "admin"]
                        self.show_selection_dialog("Select Role", "Choose user role:", role_options, on_role_selection)
                    
                    self.show_custom_dialog("Email", "Enter email address (optional):", "info", input_field=True, callback=on_email_input)
                
                self.show_custom_dialog("Last Name", "Enter last name (optional):", "info", input_field=True, callback=on_last_name_input)
            
            self.show_custom_dialog("First Name", "Enter first name (optional):", "info", input_field=True, callback=on_first_name_input)
        
        self.show_custom_dialog("Create LDAP User", "Enter username:", "info", input_field=True, callback=on_username_input)
    
    def show_selection_dialog(self, title, message, options, callback):
        """Show a selection dialog with multiple options."""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("300x250")
        dialog.configure(bg='#0f1419')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Message label
        msg_label = tk.Label(
            dialog,
            text=message,
            fg='white',
            bg='#0f1419',
            font=("Segoe UI", 11),
            wraplength=280
        )
        msg_label.pack(pady=20)
        
        # Selection variable
        selection = tk.StringVar(value=options[0] if options else "")
        
        # Radio buttons for options
        for option in options:
            rb = tk.Radiobutton(
                dialog,
                text=option.title(),
                variable=selection,
                value=option,
                fg='white',
                bg='#0f1419',
                selectcolor='#4299e1',
                activebackground='#1a2332',
                activeforeground='white',
                font=("Segoe UI", 10)
            )
            rb.pack(anchor='w', padx=40, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#0f1419')
        btn_frame.pack(pady=20)
        
        def on_confirm():
            selected = selection.get()
            dialog.destroy()
            if callback:
                callback(selected)
        
        def on_cancel():
            dialog.destroy()
            if callback:
                callback(None)
        
        confirm_btn = tk.Button(
            btn_frame, 
            text="Confirm", 
            command=on_confirm,
            font=("Segoe UI", 10, "bold"),
            bg='#4299e1', 
            fg='white',
            width=10,
            height=1,
            relief='flat',
            borderwidth=0
        )
        confirm_btn.pack(side='left', padx=10)
        
        cancel_btn = tk.Button(
            btn_frame, 
            text="Cancel", 
            command=on_cancel,
            font=("Segoe UI", 10, "bold"),
            bg='#e53e3e', 
            fg='white',
            width=10,
            height=1,
            relief='flat',
            borderwidth=0
        )
        cancel_btn.pack(side='left', padx=10)

        # Add hover effects
        def on_enter_confirm(e):
            confirm_btn.config(bg='#3182ce')
        def on_leave_confirm(e):
            confirm_btn.config(bg='#4299e1')
        def on_enter_cancel(e):
            cancel_btn.config(bg='#c53030')
        def on_leave_cancel(e):
            cancel_btn.config(bg='#e53e3e')
            
        confirm_btn.bind("<Enter>", on_enter_confirm)
        confirm_btn.bind("<Leave>", on_leave_confirm)
        cancel_btn.bind("<Enter>", on_enter_cancel)
        cancel_btn.bind("<Leave>", on_leave_cancel)

    def refresh_security_logs(self):
        """Refresh and display security logs."""
        self.logs_output.delete(1.0, tk.END)
        self.logs_output.insert(tk.END, "Loading security logs...\n")
        self.logs_output.update_idletasks()
        
        def load_logs_thread():
            try:
                logs_dir = Path("logs")
                if not logs_dir.exists():
                    self.root.after(0, lambda: self.display_log_message("❌ Logs directory not found."))
                    return
                
                log_files = sorted(logs_dir.glob("security_log_*.txt"), reverse=True)
                if not log_files:
                    self.root.after(0, lambda: self.display_log_message("❌ No security log files found."))
                    return
                
                all_logs = []
                for log_file in log_files:
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                            for line in lines:
                                all_logs.append(line.strip())
                    except Exception as e:
                        all_logs.append(f"❌ Error reading {log_file.name}: {e}")
                
                # Sort logs by timestamp (most recent first)
                all_logs.reverse()
                
                self.root.after(0, lambda: self.display_logs(all_logs))
                
            except Exception as e:
                self.root.after(0, lambda: self.display_log_message(f"❌ Error loading logs: {e}"))
        
        threading.Thread(target=load_logs_thread, daemon=True).start()
    
    def filter_logs_by_date(self, filter_type):
        """Filter logs by date."""
        if filter_type == "today":
            today = datetime.now().strftime("%Y-%m-%d")
            self.logs_output.delete(1.0, tk.END)
            self.logs_output.insert(tk.END, f"Loading logs for {today}...\n")
        else:
            self.refresh_security_logs()
            return
        
        def filter_logs_thread():
            try:
                logs_dir = Path("logs")
                today_file = logs_dir / f"security_log_{today}.txt"
                
                if not today_file.exists():
                    self.root.after(0, lambda: self.display_log_message(f"❌ No logs found for {today}."))
                    return
                
                with open(today_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    logs = [line.strip() for line in lines if line.strip()]
                
                logs.reverse()  # Most recent first
                self.root.after(0, lambda: self.display_logs(logs))
                
            except Exception as e:
                self.root.after(0, lambda: self.display_log_message(f"❌ Error filtering logs: {e}"))
        
        threading.Thread(target=filter_logs_thread, daemon=True).start()
    
    def display_logs(self, logs):
        """Display logs in the text widget."""
        self.logs_output.delete(1.0, tk.END)
        
        if not logs:
            self.logs_output.insert(tk.END, "No log entries found.\n")
            return
        
        self.logs_output.insert(tk.END, f"📋 Security Log Entries ({len(logs)} entries)\n")
        self.logs_output.insert(tk.END, "=" * 80 + "\n\n")
        
        for log_entry in logs:
            if log_entry:
                # Color code different types of events
                if "AUTH_SUCCESS" in log_entry:
                    self.logs_output.insert(tk.END, f"✅ {log_entry}\n", "success")
                elif "AUTH_FAILED" in log_entry or "FAILED" in log_entry:
                    self.logs_output.insert(tk.END, f"❌ {log_entry}\n", "error")
                elif "SYSTEM_START" in log_entry:
                    self.logs_output.insert(tk.END, f"🚀 {log_entry}\n", "system")
                elif "LOGOUT" in log_entry:
                    self.logs_output.insert(tk.END, f"🚪 {log_entry}\n", "logout")
                else:
                    self.logs_output.insert(tk.END, f"ℹ️ {log_entry}\n")
                self.logs_output.insert(tk.END, "\n")
        
        # Configure tags for colored text
        self.logs_output.tag_config("success", foreground="lightgreen")
        self.logs_output.tag_config("error", foreground="lightcoral")
        self.logs_output.tag_config("system", foreground="lightblue")
        self.logs_output.tag_config("logout", foreground="yellow")
        
        self.logs_output.see(tk.END)
    
    def display_log_message(self, message):
        """Display a simple message in the logs output."""
        self.logs_output.delete(1.0, tk.END)
        self.logs_output.insert(tk.END, message + "\n")
    
    def minimize_to_system_tray(self):
        """Minimize GUI to system tray and start detection system."""
        self.is_minimized = True
        self.root.iconify()
        
        # Start detection system when GUI is minimized
        if self.detector_service and not self.detection_running:
            self.start_detection_system()
        
        SecurityUtils.log_security_event("GUI_MINIMIZED", f"User {self.current_user} minimized GUI to system tray - detection started")
        print("🔽 GUI minimized to system tray. Detection system started.")
    
    def restore_from_tray(self):
        """Restore GUI from system tray and stop detection system."""
        self.is_minimized = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        
        # Stop detection system when GUI is restored
        if self.detector_service and self.detection_running:
            self.stop_detection_system()
        
        SecurityUtils.log_security_event("GUI_RESTORED", f"User {self.current_user} restored GUI from system tray - detection stopped")
        print("🔼 GUI restored from system tray. Detection system stopped.")
    
    def start_detection_system(self):
        """Start the detection system in a separate thread."""
        if self.detection_running:
            print("⚠️ Detection system already running")
            return
        
        def detection_thread():
            try:
                self.detection_running = True
                print("🎥 Starting detection system...")
                SecurityUtils.log_security_event("DETECTION_STARTED", "Detection system started from GUI")
                
                # Start detection with camera source
                self.detector_service.inference(source=0, view_img=False, save_img=False)
                
            except Exception as e:
                print(f"❌ Detection system error: {e}")
                SecurityUtils.log_security_event("DETECTION_ERROR", f"Detection system error: {e}")
            finally:
                self.detection_running = False
        
        # Start detection in daemon thread
        detection_thread_obj = threading.Thread(target=detection_thread, daemon=True)
        detection_thread_obj.start()
    
    def stop_detection_system(self):
        """Stop the detection system."""
        if not self.detection_running:
            print("⚠️ Detection system not running")
            return
        
        try:
            print("🛑 Stopping detection system...")
            SecurityUtils.log_security_event("DETECTION_STOPPED", "Detection system stopped from GUI")
            
            # Signal detection to stop
            if hasattr(self.detector_service, 'stop_detection'):
                self.detector_service.stop_detection()
            else:
                # Fallback: set running flag to False
                self.detection_running = False
                
        except Exception as e:
            print(f"❌ Error stopping detection: {e}")
            SecurityUtils.log_security_event("DETECTION_STOP_ERROR", f"Error stopping detection: {e}")
    
    def setup_window_events(self):
        """Setup window event handlers for minimize/restore detection."""
        # Bind window state events
        self.root.bind('<Unmap>', self.on_window_minimize)
        self.root.bind('<Map>', self.on_window_restore)
        
        # Add global hotkey for restoring window (Ctrl+Shift+R)
        self.root.bind_all('<Control-Shift-R>', lambda e: self.restore_from_tray())
        
        # Override the minimize button behavior
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # Keep security requirement
    
    def on_window_minimize(self, event):
        """Handle window minimize event."""
        if event.widget == self.root:
            if not self.is_minimized:  # Avoid duplicate calls
                self.minimize_to_system_tray()
    
    def on_window_restore(self, event):
        """Handle window restore event."""
        if event.widget == self.root:
            if self.is_minimized:  # Only if actually minimized
                self.restore_from_tray()
    
    def logout(self):
        """Logout and return to authentication screen."""
        def on_confirmation(confirmed):
            if confirmed:
                self.is_authenticated = False
                current_user_temp = self.current_user  # Store for logging
                self.current_user = None
                self.current_role = None
                
                if self.auth_manager:
                    self.auth_manager.logout()
                
                SecurityUtils.log_security_event("GUI_LOGOUT", f"User {current_user_temp} logged out")
                
                # Return to login screen
                self.show_login_screen()
        
        self.show_custom_dialog("Logout", "Are you sure you want to logout?", "yesno", callback=on_confirmation)
    
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
    
    def show_security_error(self, title, message):
        """Show security error dialog."""
        self.show_custom_dialog(title, message, "error")


if __name__ == "__main__":
    # Test the GUI
    gui = SecurityGUI()
    gui.run()
