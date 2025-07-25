"""
Alert system for displaying security warnings and notifications.
"""

import time
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
from typing import List, Optional

from ..core.config import Config
from ..core.base import BaseAlert
from ..utils.security_utils import SecurityUtils
from ..auth.ldap_auth import LDAPAuthenticator


class AlertSystem(BaseAlert):
    """Manages all security alert windows and dialogs."""
    
    def __init__(self, config):
        self.root = None
        self.alert_window = None
        self.alert_active = False
        self.ok_button = None
        self.camera_alert_window = None
        self.camera_alert_active = False
        self.recording_alert_window = None
        self.recording_alert_active = False
        self.password_entry_window = None
        self.password_entry = None
        self.retry_button = None
        self.tools_label = None
        self.attempts_label = None
        self.security_utils = SecurityUtils()
        self.ldap = LDAPAuthenticator(config)
        
        # Recording alert grace period tracking
        self.recording_grace_start_time = 0
        self.recording_grace_active = False
        
    def create_root(self):
        """Create the Tkinter root window."""
        if self.root is None:
            self.root = tk.Tk()
            self.root.withdraw()  # Hide the root window

    def show_alert(self, message: str, alert_type: str = "info") -> None:
        """Show an alert to the user."""
        if alert_type == "mobile":
            self.show_mobile_alert()
        elif alert_type == "camera":
            self.show_camera_alert()
        elif alert_type == "recording":
            self.show_recording_alert([message])
        else:
            self.create_root()
            messagebox.showinfo("Alert", message, parent=self.root)

    def hide_alert(self) -> None:
        """Hide the current alert."""
        self.hide_mobile_alert()
        self.hide_camera_alert()
        self.hide_recording_alert()

    def is_alert_active(self) -> bool:
        """Check if an alert is currently active."""
        return (self.alert_active or self.camera_alert_active or 
                self.recording_alert_active)

    def show_mobile_alert(self):
        """Display a big alert dialog to the user for mobile phone detection."""
        self.create_root()

        if self.alert_window is None:
            self.alert_window = tk.Toplevel(self.root)
            self.alert_window.title("SECURITY ALERT")
            self.alert_window.attributes("-fullscreen", True)
            self.alert_window.attributes("-topmost", True)
            self.alert_window.configure(bg='red')
            self.alert_window.resizable(False, False)
            self.alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            # Disable escape key
            self.alert_window.bind('<Escape>', lambda e: None)
            
            # Center frame
            center_frame = tk.Frame(self.alert_window, bg='red')
            center_frame.pack(expand=True)
            
            # Warning symbol
            warning_label = tk.Label(
                center_frame,
                text="⚠️",
                fg="white",
                bg="red",
                font=("Helvetica", 120, "bold")
            )
            warning_label.pack(pady=(50, 20))
            
            # Alert title
            title_label = tk.Label(
                center_frame,
                text="SECURITY VIOLATION",
                fg="white",
                bg="red",
                font=("Helvetica", 48, "bold")
            )
            title_label.pack(pady=(0, 20))
            
            # Alert message
            message_label = tk.Label(
                center_frame,
                text="MOBILE PHONE DETECTED\nREMOVE DEVICE IMMEDIATELY",
                fg="white",
                bg="red",
                font=("Helvetica", 28, "bold"),
                justify=tk.CENTER
            )
            message_label.pack(pady=(0, 40))
            
            # OK button (initially disabled)
            self.ok_button = tk.Button(
                center_frame,
                text="Device Removed (Disabled)",
                command=self.hide_mobile_alert,
                font=("Helvetica", 20, "bold"),
                bg="darkred",
                fg="gray",
                width=25,
                height=3,
                relief="sunken",
                bd=3,
                state=tk.DISABLED
            )
            self.ok_button.pack(pady=20)
            
            # System info
            sys_info = SecurityUtils.get_system_info()
            info_text = f"System: {sys_info['computer_name']} | User: {sys_info['username']} | IP: {sys_info['ip_address']}\nTime: {sys_info['timestamp']}"
            info_label = tk.Label(
                center_frame,
                text=info_text,
                fg="white",
                bg="red",
                font=("Courier", 14, "bold")
            )
            info_label.pack(pady=(40, 20))

        # Show the alert window
        self.alert_window.deiconify()
        self.alert_window.lift()
        self.alert_window.attributes("-topmost", True)
        self.alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.alert_active = True
        
        # Log alert creation
        SecurityUtils.log_security_event("SECURITY_ALERT_CREATED", "Full-screen security alert created and displayed")

    def hide_mobile_alert(self):
        """Hide the mobile alert window only if mobile is not detected for consecutive frames."""
        if self.alert_window is not None:
            self.alert_window.withdraw()
            self.alert_active = False
            SecurityUtils.log_security_event("SECURITY_ALERT_DISMISSED", "Security alert dismissed - mobile device removed")

    def show_mobile_alert_in_thread(self):
        """Show mobile alert in a thread-safe manner."""
        if self.alert_active:
            return
        if self.alert_window is not None and self.alert_window.winfo_exists():
            self.alert_window.deiconify()
        else:
            self.show_mobile_alert()

    def update_mobile_alert_button(self, consecutive_misses):
        """Update the mobile alert button based on consecutive misses."""
        if hasattr(self, 'ok_button') and self.ok_button is not None:
            if consecutive_misses >= 3:  # Enable button after 3 consecutive misses
                self.ok_button.config(
                    text="✓ Device Removed - Click to Continue",
                    bg="green",
                    fg="white",
                    state=tk.NORMAL,
                    relief="raised"
                )
            else:
                self.ok_button.config(
                    text=f"Device Removed (Wait {3-consecutive_misses} more checks)",
                    bg="darkred",
                    fg="gray",
                    state=tk.DISABLED,
                    relief="sunken"
                )

    def show_camera_alert(self):
        """Display camera unavailable alert."""
        self.create_root()

        if self.camera_alert_window is None:
            self.camera_alert_window = tk.Toplevel(self.root)
            self.camera_alert_window.title("CAMERA ERROR")
            self.camera_alert_window.attributes("-fullscreen", True)
            self.camera_alert_window.attributes("-topmost", True)
            self.camera_alert_window.configure(bg='orange')
            self.camera_alert_window.resizable(False, False)
            self.camera_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            # Center frame
            center_frame = tk.Frame(self.camera_alert_window, bg='orange')
            center_frame.pack(expand=True)
            
            # Camera icon
            camera_label = tk.Label(
                center_frame,
                text="📷",
                fg="white",
                bg="orange",
                font=("Helvetica", 100, "bold")
            )
            camera_label.pack(pady=(50, 20))
            
            # Alert title
            title_label = tk.Label(
                center_frame,
                text="CAMERA UNAVAILABLE",
                fg="white",
                bg="orange",
                font=("Helvetica", 36, "bold")
            )
            title_label.pack(pady=(0, 20))
            
            # Alert message
            message_label = tk.Label(
                center_frame,
                text="Please check camera connection\nand restart the application",
                fg="white",
                bg="orange",
                font=("Helvetica", 24),
                justify=tk.CENTER
            )
            message_label.pack(pady=(0, 40))
            
            # Retry button
            self.retry_button = tk.Button(
                center_frame,
                text="🔄 Retry Camera Connection",
                command=self.hide_camera_alert,
                font=("Helvetica", 18, "bold"),
                bg="darkorange",
                fg="white",
                width=25,
                height=3,
                relief="raised",
                bd=3
            )
            self.retry_button.pack(pady=20)

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
            self.camera_alert_active = False

    def show_recording_alert(self, detected_tools):
        """Display an alert for screen recording tool detection."""
        self.create_root()

        # Check if we're in grace period - don't show alert during grace period
        if self.is_recording_grace_period_active():
            return

        self.force_show_recording_alert(detected_tools)

    def force_show_recording_alert(self, detected_tools):
        """Force show recording alert bypassing grace period check."""
        if self.recording_alert_window is None:
            self.recording_alert_window = tk.Toplevel(self.root)
            self.recording_alert_window.title("RECORDING DETECTION")
            self.recording_alert_window.attributes("-fullscreen", True)
            self.recording_alert_window.attributes("-topmost", True)
            self.recording_alert_window.configure(bg='darkred')
            self.recording_alert_window.resizable(False, False)
            self.recording_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
            
            # Disable escape key
            self.recording_alert_window.bind('<Escape>', lambda e: None)
            
            # Center frame
            center_frame = tk.Frame(self.recording_alert_window, bg='darkred')
            center_frame.pack(expand=True)
            
            # Warning symbol
            warning_label = tk.Label(
                center_frame,
                text="🎥",
                fg="white",
                bg="darkred",
                font=("Helvetica", 100, "bold")
            )
            warning_label.pack(pady=(30, 15))
            
            # Alert title
            title_label = tk.Label(
                center_frame,
                text="SCREEN RECORDING DETECTED",
                fg="white",
                bg="darkred",
                font=("Helvetica", 32, "bold")
            )
            title_label.pack(pady=(0, 15))
            
            # Tools detected label
            self.tools_label = tk.Label(
                center_frame,
                text="",
                fg="yellow",
                bg="darkred",
                font=("Helvetica", 18, "bold"),
                justify=tk.CENTER
            )
            self.tools_label.pack(pady=(0, 20))
            
            # Instructions
            instructions_label = tk.Label(
                center_frame,
                text="CLOSE ALL RECORDING APPLICATIONS\nENTER SECURITY PASSWORD TO CONTINUE",
                fg="white",
                bg="darkred",
                font=("Helvetica", 20, "bold"),
                justify=tk.CENTER
            )
            instructions_label.pack(pady=(0, 20))
            
            # Enter Password button
            password_button = tk.Button(
                center_frame,
                text="🔓 Enter Security Password",
                command=self.show_password_entry_dialog,
                font=("Helvetica", 16, "bold"),
                bg="darkblue",
                fg="white",
                width=25,
                height=2,
                relief="raised",
                bd=3
            )
            password_button.pack(pady=10)

        # Update detected tools display
        self.update_recording_tools_display(detected_tools)
        
        # Show the window
        self.recording_alert_window.deiconify()
        self.recording_alert_window.lift()
        self.recording_alert_window.attributes("-topmost", True)
        self.recording_alert_active = True
        
        SecurityUtils.log_security_event("RECORDING_ALERT_SHOWN", f"Recording alert displayed for tools: {detected_tools}")

    def show_recording_alert_in_thread(self, detected_tools):
        """Show recording alert in a thread-safe manner."""
        if not self.recording_alert_active:
            threading.Thread(target=lambda: self.show_recording_alert(detected_tools), daemon=True).start()

    def hide_recording_alert(self):
        """Hide recording alert."""
        if self.recording_alert_window is not None:
            self.recording_alert_window.withdraw()
            self.recording_alert_active = False
            SecurityUtils.log_security_event("RECORDING_ALERT_DISMISSED", "Recording alert dismissed")

    def show_password_entry_dialog(self):
        """Show password entry dialog."""
        if self.password_entry_window is not None:
            return  # Already showing
            
        self.password_entry_window = tk.Toplevel(self.root)
        self.password_entry_window.title("Security Password")
        self.password_entry_window.geometry("500x300")
        self.password_entry_window.configure(bg='black')
        self.password_entry_window.attributes("-topmost", True)
        self.password_entry_window.resizable(False, False)
        self.password_entry_window.protocol("WM_DELETE_WINDOW", self.close_password_dialog)
        
        # Center the window
        self.password_entry_window.transient(self.recording_alert_window)
        self.password_entry_window.grab_set()
        
        # Center frame
        center_frame = tk.Frame(self.password_entry_window, bg='black')
        center_frame.pack(expand=True)
        
        # Title
        title_label = tk.Label(
            center_frame,
            text="🔐 SECURITY AUTHENTICATION",
            fg="white",
            bg="black",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=(20, 15))
        
        # Password label
        password_label = tk.Label(
            center_frame,
            text="Enter Security Password:",
            fg="white",
            bg="black",
            font=("Helvetica", 12)
        )
        password_label.pack(pady=(0, 10))
        
        # Password entry
        self.password_entry = tk.Entry(
            center_frame,
            show="*",
            font=("Helvetica", 14),
            width=20,
            justify=tk.CENTER
        )
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.verify_password_and_close())
        
        # Buttons frame
        buttons_frame = tk.Frame(center_frame, bg='black')
        buttons_frame.pack(pady=20)
        
        # Submit button
        submit_button = tk.Button(
            buttons_frame,
            text="✓ Submit",
            command=self.verify_password_and_close,
            font=("Helvetica", 12, "bold"),
            bg="green",
            fg="white",
            width=10
        )
        submit_button.pack(side=tk.LEFT, padx=10)
        
        # Hint button
        hint_button = tk.Button(
            buttons_frame,
            text="💡 Hint",
            command=self.show_password_hint,
            font=("Helvetica", 12, "bold"),
            bg="blue",
            fg="white",
            width=10
        )
        hint_button.pack(side=tk.LEFT, padx=10)
        
        # Cancel button
        cancel_button = tk.Button(
            buttons_frame,
            text="✗ Cancel",
            command=self.close_password_dialog,
            font=("Helvetica", 12, "bold"),
            bg="red",
            fg="white",
            width=10
        )
        cancel_button.pack(side=tk.LEFT, padx=10)
        
        # Attempts label
        self.attempts_label = tk.Label(
            center_frame,
            text="",
            fg="red",
            bg="black",
            font=("Helvetica", 10)
        )
        self.attempts_label.pack(pady=(10, 0))

    def verify_password_and_close(self):
        """Verify password and close dialog if correct."""
        if self.password_entry is None:
            return
            
        entered_password = self.password_entry.get()
        
        if self.security_utils.verify_password(entered_password):
            # Password correct - start grace period
            self.start_recording_grace_period()
            self.close_password_dialog()
            self.hide_recording_alert()
            SecurityUtils.log_security_event("RECORDING_PASSWORD_SUCCESS", "Recording alert password verification successful")
        else:
            # Password incorrect
            self.security_utils.password_attempts += 1
            remaining = Config.MAX_PASSWORD_ATTEMPTS - self.security_utils.password_attempts
            
            if remaining > 0:
                self.attempts_label.config(text=f"Incorrect password. {remaining} attempts remaining.")
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus_set()
            else:
                self.handle_max_password_attempts()

    def show_password_hint(self):
        """Show password hint."""
        hint = self.security_utils.get_security_password_hint()
        messagebox.showinfo("Password Hint", hint, parent=self.password_entry_window)

    def handle_max_password_attempts(self):
        """Handle maximum password attempts exceeded."""
        SecurityUtils.log_security_event("MAX_PASSWORD_ATTEMPTS", "Maximum password attempts exceeded")
        self.close_password_dialog()
        messagebox.showerror(
            "Security Violation", 
            "Maximum password attempts exceeded.\nContact system administrator.",
            parent=self.recording_alert_window
        )

    def close_password_dialog(self):
        """Close password entry dialog."""
        if self.password_entry_window is not None:
            self.password_entry_window.destroy()
            self.password_entry_window = None
            self.password_entry = None

    def is_recording_grace_period_active(self):
        """Check if recording grace period is active."""
        if not self.recording_grace_active:
            return False
        
        elapsed = time.time() - self.recording_grace_start_time
        if elapsed >= Config.RECORDING_GRACE_PERIOD:
            self.recording_grace_active = False
            return False
        
        return True

    def start_recording_grace_period(self):
        """Start the recording grace period."""
        self.recording_grace_start_time = time.time()
        self.recording_grace_active = True
        SecurityUtils.log_security_event("RECORDING_GRACE_PERIOD_START", 
                                       f"Recording grace period started for {Config.RECORDING_GRACE_PERIOD} seconds")

    def get_grace_period_status(self):
        """Get grace period status for debugging."""
        if not self.recording_grace_active:
            return "Grace period not active"
        
        elapsed = time.time() - self.recording_grace_start_time
        remaining = Config.RECORDING_GRACE_PERIOD - elapsed
        return f"Grace period active: {remaining:.1f}s remaining"

    def get_grace_period_debug_info(self):
        """Get detailed grace period information for debugging."""
        return {
            'active': self.recording_grace_active,
            'start_time': self.recording_grace_start_time,
            'current_time': time.time(),
            'elapsed': time.time() - self.recording_grace_start_time if self.recording_grace_active else 0,
            'remaining': Config.RECORDING_GRACE_PERIOD - (time.time() - self.recording_grace_start_time) if self.recording_grace_active else 0
        }

    def update_recording_tools_display(self, tools):
        """Update the display of detected recording tools."""
        if self.tools_label is not None:
            if tools:
                tools_text = "Detected Tools:\n" + "\n".join(f"• {tool}" for tool in tools)
            else:
                tools_text = "No active recording tools detected"
            self.tools_label.config(text=tools_text)

    def update_tkinter(self):
        """Update Tkinter GUI - call this regularly from main loop."""
        if self.root is not None:
            try:
                self.root.update_idletasks()
                self.root.update()
            except tk.TclError:
                pass  # Window might be destroyed

    def check_and_reshow_recording_alert_if_needed(self, detected_tools):
        """Check if recording alert should be reshown after grace period expires."""
        if (not self.recording_alert_active and 
            not self.is_recording_grace_period_active() and 
            detected_tools):
            self.show_recording_alert_in_thread(detected_tools)

    def verify_password(self, username, password):
        """Verify password using LDAP authentication."""
        try:
            success, result = self.ldap.authenticate({
                'username': username,
                'password': password
            })
            return success
        except Exception as e:
            print(f"Password verification error: {e}")
            return False
