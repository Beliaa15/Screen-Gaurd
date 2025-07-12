"""
Process manager for handling application minimization and restoration.
"""

import psutil
import pygetwindow as gw
from security_utils import SecurityUtils

class ProcessManager:
    """Manages application processes for security enforcement."""
    
    def __init__(self):
        self.notepad_minimized = False
    
    def minimize_notepadpp(self):
        """Minimize Notepad++ window."""
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'notepad++.exe':
                # Get the Notepad++ window by title
                windows = gw.getWindowsWithTitle("Notepad++")
                if windows:
                    windows[0].minimize()
                    sys_info = SecurityUtils.get_system_info()
                    print(f"SECURITY ALERT: Minimized Notepad++ - {sys_info['computer_name']} ({sys_info['ip_address']}) - User: {sys_info['username']} - {sys_info['timestamp']}")
                    # Log security event
                    SecurityUtils.log_security_event("NOTEPAD_MINIMIZED", "Notepad++ minimized due to security violation")
                return  # Stop searching after finding Notepad++ process

    def restore_notepadpp(self):
        """Restore Notepad++ window."""
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'notepad++.exe':
                # Get the Notepad++ window by title
                windows = gw.getWindowsWithTitle("Notepad++")
                if windows and windows[0].isMinimized:
                    windows[0].restore()
                    print("Restored Notepad++")
                    # Log security event
                    SecurityUtils.log_security_event("NOTEPAD_RESTORED", "Notepad++ restored after security clearance")
                return  # Stop searching after finding Notepad++ process
    
    def set_notepad_minimized(self, status):
        """Set the notepad minimized status."""
        self.notepad_minimized = status
    
    def is_notepad_minimized(self):
        """Check if notepad is currently minimized."""
        return self.notepad_minimized
