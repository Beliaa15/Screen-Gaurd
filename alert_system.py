"""
Alert system for displaying security warnings and notifications.
"""

import tkinter as tk
from tkinter import messagebox
import time
from config import Config
from security_utils import SecurityUtils

class AlertSystem:
    """Manages all security alert windows and dialogs."""
    
    def __init__(self):
        self.root = None
        self.alert_window = None
        self.alert_active = False
        self.ok_button = None  # Initialize ok_button
        self.camera_alert_window = None
        self.camera_alert_active = False
        self.recording_alert_window = None
        self.recording_alert_active = False
        self.password_entry_window = None
        self.password_entry = None
        self.retry_button = None  # Initialize retry_button
        self.tools_label = None  # Initialize tools_label
        self.attempts_label = None  # Initialize attempts_label
        self.security_utils = SecurityUtils()
        
    def create_root(self):
        """Create the Tkinter root window."""
        if self.root is None:
            self.root = tk.Tk()
            self.root.withdraw()  # Hide the root window initially

    def show_mobile_alert(self):
        """Display a big alert dialog to the user for mobile phone detection."""
        self.create_root()

        if self.alert_window is None:
            # Get system information
            sys_info = SecurityUtils.get_system_info()
            
            # Create a centered window
            self.alert_window = tk.Toplevel(self.root)
            self.alert_window.title("Screen Guard")
            self.alert_window.attributes("-fullscreen", True)
            self.alert_window.attributes("-topmost", True)  # Keep on top
            
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.alert_window.geometry(f"{screen_width}x{screen_height}+0+0")
            self.alert_window.configure(bg='red')
            self.alert_window.resizable(False, False)

            # Main alert message in Arabic
            main_label = tk.Label(
                self.alert_window, 
                text=" تم ايقاف النظام لدواعى امنية برجاء التحقق من عدم وجود هاتف محمول امام الشاشة ", 
                fg="white", 
                bg="red", 
                font=("Helvetica", 25, "bold"),
                wraplength=screen_width - 100
            )
            main_label.pack(expand=True, pady=(50, 20))

            # System information display
            info_text = f"""COMPUTER DETAILS:
        Computer: {sys_info['computer_name']}
        IP Address: {sys_info['ip_address']}
        User: {sys_info['username']}
        Time: {sys_info['timestamp']}

System locked due to mobile phone detection"""

            info_label = tk.Label(
                self.alert_window,
                text=info_text,
                fg="yellow",
                bg="red",
                font=("Courier", 20, "bold"),
                justify="left"
            )
            info_label.pack(pady=20)

            # Button to close the alert
            self.ok_button = tk.Button(
                self.alert_window, 
                text="OK (Mobile Detected - Cannot Close)",
                state="disabled", 
                command=self.hide_mobile_alert, 
                font=("Helvetica", 20, "bold"),
                bg="white",
                fg="red",
                wraplength=600
            )
            self.ok_button.pack(pady=50)

        # Show the alert window
        self.alert_window.deiconify()
        self.alert_window.lift()  # Bring to front
        self.alert_window.attributes("-topmost", True)
        self.alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.alert_active = True
        
        # Log alert creation
        SecurityUtils.log_security_event("SECURITY_ALERT_CREATED", f"Full-screen security alert created and displayed")

    def hide_mobile_alert(self):
        """Hide the mobile alert window only if mobile is not detected for consecutive frames."""
        if self.alert_window is not None:
            self.alert_window.withdraw()  # Hide the alert window
            self.alert_window.attributes("-topmost", False)  # Remove topmost attribute
            self.alert_active = False
            SecurityUtils.log_security_event("SECURITY_ALERT_CLOSED", f"Alert closed by user after {Config.CONSECUTIVE_MAX_DETECTIONS} consecutive clear frames")
            print("Alert closed - no mobile detected for 3 consecutive frames")

    def show_mobile_alert_in_thread(self):
        """Show mobile alert in a thread-safe manner."""
        if self.alert_active:
            return  # Already active
        if self.alert_window is not None and self.alert_window.winfo_exists():
            try:
                if self.alert_window.state() == "withdrawn":
                    # If the window exists and is hidden, just show it again
                    self.alert_window.deiconify()
                    self.alert_window.lift()
                    self.alert_window.attributes("-topmost", True)
                    self.alert_active = True
                    SecurityUtils.log_security_event("SECURITY_ALERT_REAPPEARED", "Alert window reappeared - mobile phone detected again")
            except tk.TclError:
                # Window doesn't exist anymore, create new one
                self.alert_window = None
                self.show_mobile_alert()
        else:
            # Create and show the alert window
            self.show_mobile_alert()

    def update_mobile_alert_button(self, consecutive_misses):
        """Update the mobile alert button based on consecutive misses."""
        if hasattr(self, 'ok_button') and self.ok_button is not None:
            if consecutive_misses >= Config.CONSECUTIVE_MAX_DETECTIONS:
                self.ok_button.config(state='normal', text='OK (No Mobile Detected - Safe to Close)')
            elif consecutive_misses > 0:
                remaining = Config.CONSECUTIVE_MAX_DETECTIONS - consecutive_misses
                self.ok_button.config(state='disabled', text=f'OK ({remaining} more needed)')
            else:
                self.ok_button.config(state='disabled', text='OK (Mobile Detected)')

    def show_camera_alert(self):
        """Display camera unavailable alert."""
        self.create_root()

        if self.camera_alert_window is None:
            sys_info = SecurityUtils.get_system_info()
            
            self.camera_alert_window = tk.Toplevel(self.root)
            self.camera_alert_window.title("Camera Required")
            self.camera_alert_window.attributes("-fullscreen", True)
            self.camera_alert_window.attributes("-topmost", True)
            
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.camera_alert_window.geometry(f"{screen_width}x{screen_height}+0+0")
            self.camera_alert_window.configure(bg='orange')
            self.camera_alert_window.resizable(False, False)

            # Main alert message
            main_label = tk.Label(
                self.camera_alert_window,
                text="CAMERA ACCESS REQUIRED",
                fg="white",
                bg="orange",
                font=("Helvetica", 30, "bold")
            )
            main_label.pack(expand=True, pady=(50, 20))

            # Instructions
            instruction_text = """Please ensure your camera is:
• Connected and powered on
• Not being used by another application
• Granted permission to this application

System monitoring requires camera access for security compliance."""

            instruction_label = tk.Label(
                self.camera_alert_window,
                text=instruction_text,
                fg="black",
                bg="orange",
                font=("Arial", 18),
                justify="left"
            )
            instruction_label.pack(pady=20)

            # System info
            info_text = f"""SYSTEM INFORMATION:
Computer: {sys_info['computer_name']}
IP Address: {sys_info['ip_address']}
User: {sys_info['username']}
Time: {sys_info['timestamp']}"""

            info_label = tk.Label(
                self.camera_alert_window,
                text=info_text,
                fg="darkred",
                bg="orange",
                font=("Courier", 14, "bold"),
                justify="left"
            )
            info_label.pack(pady=20)

            # Retry button - callback will be set by the calling code
            self.retry_button = tk.Button(
                self.camera_alert_window,
                text="Retry Camera Connection",
                font=("Helvetica", 16, "bold"),
                bg="green",
                fg="white",
                width=25
            )
            self.retry_button.pack(pady=30)

        self.camera_alert_window.deiconify()
        self.camera_alert_window.lift()
        self.camera_alert_window.attributes("-topmost", True)
        self.camera_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.camera_alert_active = True
        
        SecurityUtils.log_security_event("CAMERA_ALERT_SHOWN", "Camera unavailable alert displayed")

    def hide_camera_alert(self):
        """Hide camera alert."""
        if self.camera_alert_window is not None:
            self.camera_alert_window.withdraw()
            self.camera_alert_window.attributes("-topmost", False)
            self.camera_alert_active = False
            SecurityUtils.log_security_event("CAMERA_ALERT_CLOSED", "Camera alert closed - camera available")

    def show_recording_alert(self, detected_tools):
        """Display an alert for screen recording tool detection."""
        self.create_root()

        if self.recording_alert_window is None:
            sys_info = SecurityUtils.get_system_info()
            
            self.recording_alert_window = tk.Toplevel(self.root)
            self.recording_alert_window.title("Recording Detection Alert")
            self.recording_alert_window.attributes("-fullscreen", True)
            self.recording_alert_window.attributes("-topmost", True)
            
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.recording_alert_window.geometry(f"{screen_width}x{screen_height}+0+0")
            self.recording_alert_window.configure(bg='darkred')
            self.recording_alert_window.resizable(False, False)

            # Main alert message
            main_label = tk.Label(
                self.recording_alert_window,
                text="⚠️ SCREEN RECORDING DETECTED ⚠️",
                fg="white",
                bg="darkred",
                font=("Helvetica", 32, "bold")
            )
            main_label.pack(expand=True, pady=(50, 20))

            # Secondary message in Arabic
            arabic_label = tk.Label(
                self.recording_alert_window,
                text="تم اكتشاف تطبيق تسجيل الشاشة - الرجاء إغلاق جميع تطبيقات التسجيل",
                fg="yellow",
                bg="darkred",
                font=("Helvetica", 24, "bold"),
                wraplength=screen_width - 100
            )
            arabic_label.pack(pady=20)

            # Detected tools display
            tools_text = f"Detected Tools: {', '.join(detected_tools)}"
            self.tools_label = tk.Label(
                self.recording_alert_window,
                text=tools_text,
                fg="orange",
                bg="darkred",
                font=("Courier", 18, "bold"),
                wraplength=screen_width - 100
            )
            self.tools_label.pack(pady=20)

            # System information
            info_text = f"""SECURITY VIOLATION DETECTED:
Computer: {sys_info['computer_name']}
IP Address: {sys_info['ip_address']}
User: {sys_info['username']}
Time: {sys_info['timestamp']}"""

            info_label = tk.Label(
                self.recording_alert_window,
                text=info_text,
                fg="white",
                bg="darkred",
                font=("Courier", 16, "bold"),
                justify="left"
            )
            info_label.pack(pady=20)

            # Close button - now requires password
            close_button = tk.Button(
                self.recording_alert_window,
                text="Enter Security Password to Continue",
                command=self.show_password_entry_dialog,
                font=("Helvetica", 18, "bold"),
                bg="yellow",
                fg="black",
                width=35,
                height=2
            )
            close_button.pack(pady=30)
            
            # Warning about password
            password_warning = tk.Label(
                self.recording_alert_window,
                text="⚠️ Security password required to dismiss this alert ⚠️",
                fg="yellow",
                bg="darkred",
                font=("Helvetica", 16, "bold")
            )
            password_warning.pack(pady=10)

        # Show the recording alert window
        self.recording_alert_window.deiconify()
        self.recording_alert_window.lift()
        self.recording_alert_window.attributes("-topmost", True)
        self.recording_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.recording_alert_active = True
        
        SecurityUtils.log_security_event("RECORDING_ALERT_SHOWN", f"Screen recording alert displayed for tools: {', '.join(detected_tools)}")

    def hide_recording_alert(self):
        """Hide the recording alert window after password verification."""
        if self.recording_alert_window is not None:
            self.recording_alert_window.withdraw()
            self.recording_alert_window.attributes("-topmost", False)
            self.recording_alert_active = False
            SecurityUtils.log_security_event("RECORDING_ALERT_CLOSED", "Recording alert closed after password verification")

    def show_password_entry_dialog(self):
        """Show password entry dialog for recording alert dismissal"""
        if self.password_entry_window is not None:
            return  # Already showing
            
        self.create_root()
        
        self.password_entry_window = tk.Toplevel(self.root)
        self.password_entry_window.title("Security Verification Required")
        self.password_entry_window.attributes("-topmost", True)
        self.password_entry_window.attributes("-fullscreen", True)
        self.password_entry_window.configure(bg='black')
        self.password_entry_window.resizable(False, False)
        self.password_entry_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing
        
        # Center the dialog content
        main_frame = tk.Frame(self.password_entry_window, bg='black')
        main_frame.pack(expand=True)
        
        # Security warning
        warning_label = tk.Label(
            main_frame,
            text="🔒 SECURITY VERIFICATION REQUIRED 🔒",
            fg="red",
            bg="black",
            font=("Helvetica", 36, "bold")
        )
        warning_label.pack(pady=(50, 30))
        
        # Violation message
        violation_text = """SECURITY VIOLATION DETECTED
Screen recording/capture attempt blocked
Administrator password required to continue"""
        
        violation_label = tk.Label(
            main_frame,
            text=violation_text,
            fg="white",
            bg="black",
            font=("Helvetica", 20, "bold"),
            justify="center"
        )
        violation_label.pack(pady=20)
        
        # Attempts remaining
        attempts_remaining = Config.MAX_PASSWORD_ATTEMPTS - self.security_utils.password_attempts
        self.attempts_label = tk.Label(
            main_frame,
            text=f"Attempts remaining: {attempts_remaining}",
            fg="yellow",
            bg="black",
            font=("Helvetica", 18, "bold")
        )
        self.attempts_label.pack(pady=10)
        
        # Password entry frame
        password_frame = tk.Frame(main_frame, bg='black')
        password_frame.pack(pady=30)
        
        password_label = tk.Label(
            password_frame,
            text="Security Password:",
            fg="white",
            bg="black",
            font=("Helvetica", 18, "bold")
        )
        password_label.pack(pady=10)
        
        self.password_entry = tk.Entry(
            password_frame,
            show="*",
            font=("Helvetica", 16),
            width=30,
            justify="center"
        )
        self.password_entry.pack(pady=10)
        self.password_entry.focus_set()
        
        # Bind Enter key to password verification
        self.password_entry.bind('<Return>', lambda e: self.verify_password_and_close())
        
        # Buttons frame
        button_frame = tk.Frame(main_frame, bg='black')
        button_frame.pack(pady=30)
        
        verify_button = tk.Button(
            button_frame,
            text="Verify Password",
            command=self.verify_password_and_close,
            font=("Helvetica", 16, "bold"),
            bg="green",
            fg="white",
            width=15,
            height=2
        )
        verify_button.pack(side="left", padx=10)
        
        hint_button = tk.Button(
            button_frame,
            text="Show Hint",
            command=self.show_password_hint,
            font=("Helvetica", 16, "bold"),
            bg="blue",
            fg="white",
            width=15,
            height=2
        )
        hint_button.pack(side="left", padx=10)
        
        # System info
        sys_info = SecurityUtils.get_system_info()
        info_text = f"""SYSTEM LOCKED:
Computer: {sys_info['computer_name']} | IP: {sys_info['ip_address']}
User: {sys_info['username']} | Time: {sys_info['timestamp']}"""
        
        info_label = tk.Label(
            main_frame,
            text=info_text,
            fg="gray",
            bg="black",
            font=("Courier", 12),
            justify="center"
        )
        info_label.pack(pady=(50, 20))
        
        SecurityUtils.log_security_event("PASSWORD_DIALOG_SHOWN", "Security password dialog displayed")

    def verify_password_and_close(self):
        """Verify entered password and close dialog if correct"""
        if not hasattr(self, 'password_entry') or self.password_entry is None:
            return
            
        entered_password = self.password_entry.get()
        self.security_utils.password_attempts += 1
        
        if self.security_utils.verify_password(entered_password):
            # Correct password
            SecurityUtils.log_security_event("PASSWORD_VERIFIED", "Security password verified successfully")
            self.close_password_dialog()
            self.hide_recording_alert()
            self.security_utils.password_attempts = 0  # Reset attempts
        else:
            # Incorrect password
            attempts_remaining = Config.MAX_PASSWORD_ATTEMPTS - self.security_utils.password_attempts
            
            if attempts_remaining <= 0:
                # Maximum attempts reached
                SecurityUtils.log_security_event("PASSWORD_MAX_ATTEMPTS", "Maximum password attempts reached - system locked")
                self.handle_max_password_attempts()
            else:
                # Flash red and show remaining attempts
                self.password_entry_window.configure(bg='darkred')
                self.password_entry.delete(0, tk.END)
                
                # Update attempts remaining label
                self.attempts_label.config(text=f"Attempts remaining: {attempts_remaining}", fg="red")
                
                # Flash back to black
                self.root.after(1000, lambda: self.password_entry_window.configure(bg='black'))

    def show_password_hint(self):
        """Show encrypted password hint"""
        hint = self.security_utils.get_security_password_hint()
        
        hint_window = tk.Toplevel(self.password_entry_window)
        hint_window.title("Password Hint")
        hint_window.attributes("-topmost", True)
        hint_window.configure(bg='darkblue')
        hint_window.geometry("600x300")
        hint_window.resizable(False, False)
        
        hint_label = tk.Label(
            hint_window,
            text="PASSWORD HINT:",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 16, "bold")
        )
        hint_label.pack(pady=20)
        
        hint_text_label = tk.Label(
            hint_window,
            text=hint,
            fg="yellow",
            bg="darkblue",
            font=("Helvetica", 12),
            wraplength=550,
            justify="center"
        )
        hint_text_label.pack(pady=20)
        
        close_hint_button = tk.Button(
            hint_window,
            text="Close Hint",
            command=hint_window.destroy,
            font=("Helvetica", 12, "bold"),
            bg="white",
            fg="darkblue"
        )
        close_hint_button.pack(pady=20)
        
        SecurityUtils.log_security_event("PASSWORD_HINT_REQUESTED", "User requested password hint")

    def handle_max_password_attempts(self):
        """Handle maximum password attempts reached"""
        # Update the dialog to show system locked
        if self.password_entry_window:
            for widget in self.password_entry_window.winfo_children():
                widget.destroy()
            
            # Show locked message
            locked_label = tk.Label(
                self.password_entry_window,
                text="🔒 SYSTEM PERMANENTLY LOCKED 🔒",
                fg="red",
                bg="black",
                font=("Helvetica", 48, "bold")
            )
            locked_label.pack(expand=True)
            
            message_label = tk.Label(
                self.password_entry_window,
                text="Maximum password attempts exceeded\nContact system administrator immediately\nAll activities are being logged",
                fg="white",
                bg="black",
                font=("Helvetica", 20, "bold"),
                justify="center"
            )
            message_label.pack(pady=50)
        
        # Log critical security event
        SecurityUtils.log_security_event("CRITICAL_SECURITY_BREACH", "Maximum password attempts exceeded - system locked permanently")

    def close_password_dialog(self):
        """Close the password entry dialog"""
        if self.password_entry_window is not None:
            self.password_entry_window.destroy()
            self.password_entry_window = None
            self.password_entry = None

    def update_recording_tools_display(self, tools):
        """Update the detected tools display in recording alert."""
        if hasattr(self, 'tools_label') and self.tools_label is not None:
            self.tools_label.config(text=f"Detected Tools: {', '.join(tools)}")

    def update_tkinter(self):
        """Update Tkinter to keep GUI responsive."""
        if self.root is not None:
            try:
                self.root.update()
            except tk.TclError:
                pass  # Prevent crash if window closed
