"""
Security Overlay GUI - Main authentication overlay for device security

This module provides a comprehensive security overlay that:
- Blocks device access until authentication
- Manages user sessions
- Provides authentication UI
- Monitors for session expiry and re-authentication
"""

import time
import threading
from typing import Optional
import tkinter as tk
from tkinter import messagebox
from auth_manager import AuthenticationManager
from security_utils import SecurityUtils
from config import Config


class SecurityOverlay:
    """Main security overlay that controls device access."""
    
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.overlay_window = None
        self.root = None
        self.is_device_locked = True
        self.monitoring_thread = None
        self.stop_monitoring = False
        
    def create_root(self):
        """Create root window."""
        if self.root is None:
            self.root = tk.Tk()
            self.root.withdraw()
    
    def show_locked_screen(self):
        """Show device locked screen."""
        self.create_root()
        
        if self.overlay_window is not None:
            try:
                self.overlay_window.destroy()
            except:
                pass
        
        self.overlay_window = tk.Toplevel(self.root)
        self.overlay_window.title("Device Locked")
        self.overlay_window.attributes("-fullscreen", True)
        self.overlay_window.attributes("-topmost", True)
        self.overlay_window.configure(bg='black')
        self.overlay_window.resizable(False, False)
        self.overlay_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing
        
        # Center frame
        center_frame = tk.Frame(self.overlay_window, bg='black')
        center_frame.pack(expand=True)
        
        # Lock icon and title
        lock_label = tk.Label(
            center_frame,
            text="🔒",
            fg="red",
            bg="black",
            font=("Helvetica", 100, "bold")
        )
        lock_label.pack(pady=(50, 20))
        
        title_label = tk.Label(
            center_frame,
            text="DEVICE LOCKED",
            fg="red",
            bg="black",
            font=("Helvetica", 36, "bold")
        )
        title_label.pack(pady=(0, 10))
        
        subtitle_label = tk.Label(
            center_frame,
            text="Authentication Required",
            fg="white",
            bg="black",
            font=("Helvetica", 20)
        )
        subtitle_label.pack(pady=(0, 40))
        
        # Unlock button
        unlock_btn = tk.Button(
            center_frame,
            text="🔓 Unlock Device",
            command=self.attempt_unlock,
            font=("Helvetica", 18, "bold"),
            bg="darkblue",
            fg="white",
            width=20,
            height=3,
            relief="raised",
            bd=3
        )
        unlock_btn.pack(pady=20)
        
        # Current user info (if session exists but expired)
        if self.auth_manager.session_manager.current_session:
            current_user = self.auth_manager.session_manager.current_session['username']
            user_info_label = tk.Label(
                center_frame,
                text=f"Last User: {current_user}",
                fg="gray",
                bg="black",
                font=("Helvetica", 14)
            )
            user_info_label.pack(pady=10)
        
        # System info
        sys_info = SecurityUtils.get_system_info()
        info_text = f"Device: {sys_info['computer_name']} | IP: {sys_info['ip_address']}"
        info_label = tk.Label(
            center_frame,
            text=info_text,
            fg="gray",
            bg="black",
            font=("Courier", 12)
        )
        info_label.pack(pady=(40, 20))
        
        # Security notice
        notice_label = tk.Label(
            center_frame,
            text="This device is protected by advanced security monitoring.\nAll access attempts are logged and monitored.",
            fg="orange",
            bg="black",
            font=("Helvetica", 12),
            justify="center"
        )
        notice_label.pack(pady=20)
        
        SecurityUtils.log_security_event("DEVICE_LOCKED_SCREEN_SHOWN", "Device locked screen displayed")
    
    def attempt_unlock(self):
        """Attempt to unlock the device."""
        # Hide the locked screen temporarily
        if self.overlay_window:
            self.overlay_window.withdraw()
        
        # Attempt authentication
        if self.auth_manager.require_authentication():
            # Authentication successful
            self.unlock_device()
        else:
            # Authentication failed - show locked screen again
            SecurityUtils.log_security_event("UNLOCK_ATTEMPT_FAILED", "Device unlock attempt failed")
            self.show_locked_screen()
    
    def unlock_device(self):
        """Unlock the device after successful authentication."""
        self.is_device_locked = False
        
        if self.overlay_window:
            self.overlay_window.destroy()
            self.overlay_window = None
        
        # Start session monitoring
        self.start_continuous_monitoring()
        
        user = self.auth_manager.get_current_user()
        role = self.auth_manager.get_current_role()
        
        SecurityUtils.log_security_event("DEVICE_UNLOCKED", f"Device unlocked for user {user} with role {role}")
        
        # Show success message briefly
        self.show_unlock_success_message(user, role)
    
    def show_unlock_success_message(self, user: str, role: str):
        """Show brief success message after unlock."""
        # Ensure root window exists
        self.create_root()
        
        success_window = tk.Toplevel(self.root)
        success_window.title("Access Granted")
        success_window.configure(bg='darkgreen')
        success_window.geometry("500x300")
        success_window.resizable(False, False)
        success_window.attributes("-topmost", True)
        success_window.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Center the window
        success_window.transient(self.root)
        
        # Success content
        success_label = tk.Label(
            success_window,
            text="✅ ACCESS GRANTED",
            fg="white",
            bg="darkgreen",
            font=("Helvetica", 24, "bold")
        )
        success_label.pack(pady=(50, 20))
        
        user_label = tk.Label(
            success_window,
            text=f"Welcome, {user}",
            fg="lightgreen",
            bg="darkgreen",
            font=("Helvetica", 18)
        )
        user_label.pack(pady=10)
        
        role_label = tk.Label(
            success_window,
            text=f"Role: {role.title()}",
            fg="lightgreen",
            bg="darkgreen",
            font=("Helvetica", 14)
        )
        role_label.pack(pady=5)
        
        # Auto-close after 3 seconds - use success_window.after instead of root.after
        success_window.after(3000, success_window.destroy)
        
        SecurityUtils.log_security_event("UNLOCK_SUCCESS_MESSAGE_SHOWN", f"Success message shown for {user}")
    
    def lock_device(self, reason: str = "Session expired"):
        """Lock the device."""
        self.is_device_locked = True
        self.stop_continuous_monitoring()
        
        SecurityUtils.log_security_event("DEVICE_LOCKED", f"Device locked: {reason}")
        
        # Clear session if it exists
        if self.auth_manager.session_manager.current_session:
            user = self.auth_manager.session_manager.current_session['username']
            SecurityUtils.log_security_event("SESSION_ENDED", f"Session ended for {user}: {reason}")
        
        self.show_locked_screen()
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring of session and device state."""
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            self.stop_monitoring = False
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring."""
        self.stop_monitoring = True
    
    def _monitoring_loop(self):
        """Main monitoring loop for session and security."""
        while not self.stop_monitoring and not self.is_device_locked:
            try:
                # Check session validity
                if not self.auth_manager.is_authenticated():
                    self.lock_device("Session invalid")
                    break
                
                # Update activity (this would be called by the main app)
                # self.auth_manager.update_activity()
                
                time.sleep(Config.SESSION_CHECK_INTERVAL)
                
            except Exception as e:
                SecurityUtils.log_security_event("MONITORING_ERROR", f"Error in security monitoring: {e}")
                time.sleep(Config.SESSION_CHECK_INTERVAL)
    
    def update_activity(self):
        """Update user activity (called by main application)."""
        if not self.is_device_locked:
            self.auth_manager.update_activity()
    
    def is_device_unlocked(self) -> bool:
        """Check if device is currently unlocked."""
        return not self.is_device_locked and self.auth_manager.is_authenticated()
    
    def get_current_user_info(self) -> Optional[dict]:
        """Get current user information."""
        if self.is_device_unlocked():
            return {
                'username': self.auth_manager.get_current_user(),
                'role': self.auth_manager.get_current_role(),
                'session': self.auth_manager.session_manager.current_session
            }
        return None
    
    def manual_logout(self):
        """Manual logout by user."""
        if self.auth_manager.session_manager.current_session:
            user = self.auth_manager.session_manager.current_session['username']
            SecurityUtils.log_security_event("MANUAL_LOGOUT", f"Manual logout by {user}")
        
        self.auth_manager.logout()
        self.lock_device("Manual logout")
    
    def show_session_info_dialog(self):
        """Show session information dialog."""
        if not self.is_device_unlocked():
            messagebox.showerror("Error", "No active session")
            return
        
        user_info = self.get_current_user_info()
        session = user_info['session']
        
        info_text = f"""Current Session Information:

User: {user_info['username']}
Role: {user_info['role'].title()}
Login Time: {session['login_time']}
Auth Method: {session['auth_method'].replace('_', ' ').title()}
Session ID: {session['session_id']}

Last Activity: {session['last_activity']}"""
        
        messagebox.showinfo("Session Information", info_text)
    
    def show_system_menu(self):
        """Show system menu with logout and info options."""
        if not self.is_device_unlocked():
            return
        
        menu_window = tk.Toplevel(self.root)
        menu_window.title("System Menu")
        menu_window.configure(bg='darkblue')
        menu_window.geometry("300x250")
        menu_window.resizable(False, False)
        menu_window.attributes("-topmost", True)
        
        # User info
        user_info = self.get_current_user_info()
        user_label = tk.Label(
            menu_window,
            text=f"User: {user_info['username']}",
            fg="white",
            bg="darkblue",
            font=("Helvetica", 14, "bold")
        )
        user_label.pack(pady=20)
        
        role_label = tk.Label(
            menu_window,
            text=f"Role: {user_info['role'].title()}",
            fg="lightblue",
            bg="darkblue",
            font=("Helvetica", 12)
        )
        role_label.pack(pady=5)
        
        # Menu buttons
        info_btn = tk.Button(
            menu_window,
            text="Session Info",
            command=lambda: [self.show_session_info_dialog(), menu_window.destroy()],
            font=("Helvetica", 12),
            bg="blue",
            fg="white",
            width=20
        )
        info_btn.pack(pady=10)
        
        logout_btn = tk.Button(
            menu_window,
            text="Logout",
            command=lambda: [menu_window.destroy(), self.manual_logout()],
            font=("Helvetica", 12),
            bg="red",
            fg="white",
            width=20
        )
        logout_btn.pack(pady=10)
        
        close_btn = tk.Button(
            menu_window,
            text="Close",
            command=menu_window.destroy,
            font=("Helvetica", 12),
            bg="gray",
            fg="white",
            width=20
        )
        close_btn.pack(pady=10)
    
    def update_tkinter(self):
        """Update Tkinter events (called by main app)."""
        if self.root:
            try:
                self.root.update()
            except:
                pass


# Testing and example usage
if __name__ == "__main__":
    # Create security overlay
    overlay = SecurityOverlay()
    
    # Start with locked device
    overlay.show_locked_screen()
    
    # Start the GUI event loop
    overlay.root.mainloop()
