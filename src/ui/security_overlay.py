"""
Security Overlay GUI - Main authentication overlay for device security

This module provides a comprehensive security overlay that:
- Blocks device access until authentication
- Manages user sessions
- Provides authentication UI
- Monitors for session expiry and re-authentication
"""

import mttkinter.mtTkinter as tk
import tkinter.messagebox as messagebox
import threading
import time
from typing import Optional

from ..auth.auth_manager import AuthenticationManager
from ..utils.security_utils import SecurityUtils
from ..core.config import Config


class SecurityOverlay:
    """Main security overlay that controls device access."""
    
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.overlay_window = None
        self.root = None
        self.is_device_locked = True
        self.monitoring_thread = None
        self.stop_monitoring = False
        
        # Modern color scheme - consistent with GUI manager
        self.colors = {
            'primary': '#1e3a8a',      # Deep blue
            'primary_light': '#3b82f6', # Light blue
            'secondary': '#0f172a',     # Dark blue/black
            'accent': '#06b6d4',        # Cyan
            'success': '#10b981',       # Green
            'warning': '#f59e0b',       # Orange
            'danger': '#ef4444',        # Red
            'light': '#f8fafc',         # Light gray
            'dark': '#1f2937',          # Dark gray
            'surface': '#ffffff',       # White
            'on_surface': '#374151',    # Text on white
            'background': '#f1f5f9',    # Light background
            'card': '#ffffff',          # Card background
            'border': '#e5e7eb'         # Border color
        }
        
    def create_root(self):
        """Create root window."""
        if self.root is None:
            self.root = tk.Tk()
            self.root.withdraw()  # Hide the main root window
    
    def show_locked_screen(self):
        """Show device locked screen."""
        self.create_root()
        
        if self.overlay_window is not None:
            self.overlay_window.destroy()
        
        self.overlay_window = tk.Toplevel(self.root)
        self.overlay_window.title("Device Locked")
        self.overlay_window.attributes("-fullscreen", True)
        self.overlay_window.attributes("-topmost", True)
        self.overlay_window.configure(bg=self.colors['background'])
        self.overlay_window.resizable(False, False)
        self.overlay_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing
        
        # Header with danger color
        header_frame = tk.Frame(self.overlay_window, bg=self.colors['danger'], height=120)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        header_title = tk.Label(
            header_frame,
            text="🔒 DEVICE LOCKED",
            fg='white',
            bg=self.colors['danger'],
            font=("Segoe UI", 24, "bold")
        )
        header_title.pack(expand=True)
        
        # Center frame
        center_frame = tk.Frame(self.overlay_window, bg=self.colors['background'])
        center_frame.pack(expand=True, fill='both', padx=150, pady=50)
        
        # Lock card
        lock_card = tk.Frame(center_frame, bg=self.colors['card'], relief='flat', bd=0)
        lock_card.pack(fill='both', expand=True)
        
        # Card header
        card_header = tk.Frame(lock_card, bg=self.colors['primary'], height=60)
        card_header.pack(fill='x')
        card_header.pack_propagate(False)
        
        card_title = tk.Label(
            card_header,
            text="Authentication Required",
            fg='white',
            bg=self.colors['primary'],
            font=("Segoe UI", 16, "bold")
        )
        card_title.pack(expand=True)
        
        # Card content
        card_content = tk.Frame(lock_card, bg=self.colors['card'])
        card_content.pack(expand=True, fill='both', padx=40, pady=30)
        
        # Lock icon
        lock_label = tk.Label(
            card_content,
            text="🔒",
            fg=self.colors['danger'],
            bg=self.colors['card'],
            font=("Segoe UI", 80, "bold")
        )
        lock_label.pack(pady=(20, 30))
        
        # Instructions
        instruction_label = tk.Label(
            card_content,
            text="This device is locked for security.\nPlease authenticate to continue.",
            fg=self.colors['on_surface'],
            bg=self.colors['card'],
            font=("Segoe UI", 16, "normal"),
            justify='center'
        )
        instruction_label.pack(pady=(0, 30))
        
        # Unlock button
        unlock_btn = tk.Button(
            card_content,
            text="🔓 Unlock Device",
            command=self.attempt_unlock,
            font=("Segoe UI", 16, "bold"),
            bg=self.colors['primary'],
            fg='white',
            relief='flat',
            bd=0,
            padx=40,
            pady=15,
            cursor='hand2'
        )
        unlock_btn.pack(pady=(0, 20))
        
        # Current user info (if session exists but expired)
        if self.auth_manager.session_manager.current_session:
            expired_user = self.auth_manager.session_manager.current_session.get('username', 'Unknown')
            expired_label = tk.Label(
                card_content,
                text=f"Session expired for: {expired_user}",
                fg=self.colors['warning'],
                bg=self.colors['card'],
                font=("Segoe UI", 12, "normal")
            )
            expired_label.pack(pady=(10, 0))
        
        # System info footer
        footer_frame = tk.Frame(self.overlay_window, bg=self.colors['dark'], height=60)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        sys_info = SecurityUtils.get_system_info()
        info_text = f"Device: {sys_info['computer_name']} | IP: {sys_info['ip_address']}"
        info_label = tk.Label(
            footer_frame,
            text=info_text,
            fg='white',
            bg=self.colors['dark'],
            font=("Segoe UI", 10, "normal")
        )
        info_label.pack(expand=True)

    def attempt_unlock(self):
        """Attempt to unlock the device through authentication."""
        # Hide the overlay temporarily for authentication
        if self.overlay_window:
            self.overlay_window.withdraw()
        
        try:
            # Attempt authentication
            if self.auth_manager.require_authentication():
                self.unlock_device()
            else:
                # Authentication failed, show locked screen again
                self.show_locked_screen()
                messagebox.showerror("Authentication Failed", 
                                   "Unable to authenticate. Device remains locked.")
        except Exception as e:
            self.show_locked_screen()
            messagebox.showerror("Authentication Error", 
                               f"Authentication error: {e}")
    
    def unlock_device(self):
        """Unlock the device after successful authentication."""
        self.is_device_locked = False
        
        if self.overlay_window:
            self.overlay_window.destroy()
            self.overlay_window = None
        
        # Get current user info
        current_user = self.auth_manager.get_current_user()
        current_role = self.auth_manager.get_current_role()
        
        self.show_unlock_success_message(current_user or "Unknown", current_role or "user")
        
        # Start continuous monitoring for session expiry
        self.start_continuous_monitoring()
        
        SecurityUtils.log_security_event("DEVICE_UNLOCKED", 
                                       f"Device unlocked for user: {current_user}")
    
    def show_unlock_success_message(self, user: str, role: str):
        """Show unlock success message."""
        self.create_root()
        
        success_window = tk.Toplevel(self.root)
        success_window.title("Device Unlocked")
        success_window.geometry("400x200")
        success_window.configure(bg='darkgreen')
        success_window.attributes("-topmost", True)
        success_window.resizable(False, False)
        
        # Center the window
        success_window.transient(self.root)
        success_window.grab_set()
        
        # Success content
        center_frame = tk.Frame(success_window, bg='darkgreen')
        center_frame.pack(expand=True)
        
        success_icon = tk.Label(
            center_frame,
            text="✅",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 40)
        )
        success_icon.pack(pady=10)
        
        success_label = tk.Label(
            center_frame,
            text="DEVICE UNLOCKED",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 16, "bold")
        )
        success_label.pack()
        
        user_label = tk.Label(
            center_frame,
            text=f"Welcome, {user} ({role})",
            fg="lightgreen",
            bg="darkgreen",
            font=("Helvetica", 12)
        )
        user_label.pack(pady=10)
        
        # Auto-close after 3 seconds
        success_window.after(3000, success_window.destroy)
    
    def lock_device(self, reason: str = "Session expired"):
        """Lock the device and show locked screen."""
        self.is_device_locked = True
        self.stop_continuous_monitoring()
        
        SecurityUtils.log_security_event("DEVICE_LOCKED", f"Device locked: {reason}")
        
        self.show_locked_screen()
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring for session validity."""
        if not self.stop_monitoring:
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring."""
        self.stop_monitoring = True
    
    def _monitoring_loop(self):
        """Continuous monitoring loop for session validity."""
        while not self.stop_monitoring and not self.is_device_locked:
            try:
                # Check if authentication is still valid
                if not self.auth_manager.is_authenticated():
                    self.lock_device("Session expired or invalidated")
                    break
                
                # Check session validity
                if not self.auth_manager.session_manager.is_session_valid():
                    self.lock_device("Session expired")
                    break
                
                # Update activity timestamp
                self.auth_manager.update_activity()
                
                # Sleep for check interval
                time.sleep(Config.SESSION_CHECK_INTERVAL)
                
            except Exception as e:
                SecurityUtils.log_security_event("MONITORING_ERROR", f"Session monitoring error: {e}")
                time.sleep(10)  # Wait before retrying
    
    def update_activity(self):
        """Update user activity (called from main application)."""
        if not self.is_device_locked:
            self.auth_manager.update_activity()
    
    def is_device_unlocked(self) -> bool:
        """Check if device is currently unlocked."""
        return not self.is_device_locked
    
    def get_current_user_info(self) -> Optional[dict]:
        """Get current user information."""
        if self.is_device_locked:
            return None
        
        return {
            'username': self.auth_manager.get_current_user(),
            'role': self.auth_manager.get_current_role(),
            'session_info': self.auth_manager.session_manager.get_session_info()
        }
    
    def manual_logout(self):
        """Manually logout and lock device."""
        self.auth_manager.logout()
        self.lock_device("Manual logout")
    
    def show_session_info_dialog(self):
        """Show session information dialog."""
        user_info = self.get_current_user_info()
        if not user_info:
            messagebox.showwarning("No Session", "No active session found.")
            return
        
        session_info = user_info['session_info']
        info_text = f"""
Current User: {user_info['username']}
Role: {user_info['role']}
Session Duration: {session_info.get('session_duration', 'Unknown')}
Last Activity: {session_info.get('time_since_activity', 'Unknown')}
        """.strip()
        
        messagebox.showinfo("Session Information", info_text)
    
    def show_system_menu(self):
        """Show system menu with options."""
        if self.is_device_locked:
            return
        
        menu_window = tk.Toplevel(self.root)
        menu_window.title("System Menu")
        menu_window.geometry("300x250")
        menu_window.configure(bg='darkblue')
        menu_window.attributes("-topmost", True)
        menu_window.resizable(False, False)
        
        # Menu title
        title_label = tk.Label(
            menu_window,
            text="System Menu",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Menu buttons
        tk.Button(
            menu_window,
            text="Session Information",
            command=lambda: [self.show_session_info_dialog(), menu_window.destroy()],
            font=("Helvetica", 12),
            width=20
        ).pack(pady=5)
        
        tk.Button(
            menu_window,
            text="Logout",
            command=lambda: [self.manual_logout(), menu_window.destroy()],
            font=("Helvetica", 12),
            bg="red",
            fg="white",
            width=20
        ).pack(pady=5)
        
        tk.Button(
            menu_window,
            text="Close Menu",
            command=menu_window.destroy,
            font=("Helvetica", 12),
            width=20
        ).pack(pady=10)
    
    def update_tkinter(self):
        """Update Tkinter GUI - call from main loop."""
        if self.root:
            try:
                self.root.update_idletasks()
                self.root.update()
            except tk.TclError:
                pass  # Window might be destroyed


# Testing and example usage
if __name__ == "__main__":
    # Create security overlay
    overlay = SecurityOverlay()
    
    # Start with locked device
    overlay.show_locked_screen()
    
    # Start the GUI event loop
    overlay.root.mainloop()
