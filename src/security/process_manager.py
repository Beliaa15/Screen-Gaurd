"""
Process manager for handling application minimization and restoration.
"""

import psutil
import pygetwindow as gw
from typing import Optional

from ..utils.security_utils import SecurityUtils


class ProcessManager:
    """Manages application processes for security enforcement."""
    
    def __init__(self):
        self.notepad_minimized = False
    
    def minimize_notepadpp(self) -> None:
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

    def restore_notepadpp(self) -> None:
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
    
    def set_notepad_minimized(self, status: bool) -> None:
        """Set the notepad minimized status."""
        self.notepad_minimized = status
    
    def is_notepad_minimized(self) -> bool:
        """Check if notepad is currently minimized."""
        return self.notepad_minimized
    
    def minimize_application(self, process_name: str) -> bool:
        """Minimize any application by process name."""
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    # Try to find windows for this process
                    windows = gw.getAllWindows()
                    for window in windows:
                        if process_name.lower().replace('.exe', '') in window.title.lower():
                            window.minimize()
                            SecurityUtils.log_security_event("APPLICATION_MINIMIZED", 
                                                           f"Application {process_name} minimized due to security policy")
                            return True
            return False
        except Exception as e:
            print(f"Error minimizing application {process_name}: {e}")
            return False
    
    def restore_application(self, process_name: str) -> bool:
        """Restore any application by process name."""
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    # Try to find windows for this process
                    windows = gw.getAllWindows()
                    for window in windows:
                        if process_name.lower().replace('.exe', '') in window.title.lower():
                            if window.isMinimized:
                                window.restore()
                                SecurityUtils.log_security_event("APPLICATION_RESTORED", 
                                                               f"Application {process_name} restored after security clearance")
                                return True
            return False
        except Exception as e:
            print(f"Error restoring application {process_name}: {e}")
            return False
    
    def kill_process(self, process_name: str) -> bool:
        """Terminate a process by name (use with caution)."""
        try:
            killed = False
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    proc.terminate()
                    SecurityUtils.log_security_event("PROCESS_TERMINATED", 
                                                   f"Process {process_name} terminated for security reasons")
                    killed = True
            return killed
        except Exception as e:
            print(f"Error terminating process {process_name}: {e}")
            return False
    
    def get_running_processes(self) -> list:
        """Get list of currently running processes."""
        try:
            processes = []
            for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent']):
                processes.append({
                    'name': proc.info['name'],
                    'pid': proc.info['pid'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent']
                })
            return processes
        except Exception as e:
            print(f"Error getting process list: {e}")
            return []
