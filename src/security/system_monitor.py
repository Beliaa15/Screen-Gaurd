"""
System monitoring utilities for detecting screen recording tools and managing processes.
"""

import psutil
import threading
import time
from typing import List, Optional

from ..core.config import Config
from ..core.base import BaseMonitor
from ..utils.security_utils import SecurityUtils

# Try to import keyboard for monitoring (optional)
try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False
    print("Keyboard monitoring not available - install 'keyboard' package for full functionality")


class SystemMonitor(BaseMonitor):
    """Monitor system processes and activities for security threats."""
    
    def __init__(self):
        self.screen_monitoring_active = False
        self.pending_recording_tools = []
        self.last_recording_detection_time = 0
        self.monitoring_thread = None
        
    def start_monitoring(self) -> None:
        """Start the monitoring process."""
        self.start_security_monitoring()
        
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        self.stop_security_monitoring()
        
    def get_status(self) -> dict:
        """Get current monitoring status."""
        return {
            'monitoring_active': self.screen_monitoring_active,
            'camera_available': self.check_camera_availability(),
            'pending_tools': len(self.pending_recording_tools),
            'last_detection': self.last_recording_detection_time
        }
        
    def check_camera_availability(self) -> bool:
        """Check if camera is available and working."""
        try:
            import cv2
            cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                return ret and frame is not None
            return False
        except Exception:
            return False

    def detect_screen_recording_tools(self) -> List[str]:
        """Detect if any screen recording tools are running."""
        running_tools = []
        active_recording_tools = []
        
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            try:
                proc_name = proc.info['name'].lower()
                cpu_percent = proc.info['cpu_percent'] or 0
                
                # Check if it's a known recording process
                if any(tool.lower() in proc_name for tool in Config.SCREEN_RECORDING_PROCESSES):
                    running_tools.append(proc.info['name'])
                    
                    # Check if it's actively recording (high CPU usage or known active processes)
                    if (any(active_tool.lower() in proc_name for active_tool in Config.ACTIVE_RECORDING_PROCESSES) or
                        cpu_percent > Config.RECORDING_CPU_THRESHOLD):
                        active_recording_tools.append(proc.info['name'])
                
                # Special handling for NVIDIA recording
                if self.detect_nvidia_recording():
                    if Config.NVIDIA_RECORDING_ACTIVE_MESSAGE not in active_recording_tools:
                        active_recording_tools.append(Config.NVIDIA_RECORDING_ACTIVE_MESSAGE)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Only return active recording tools for alerts, but log all detected tools
        if running_tools:
            SecurityUtils.log_security_event("RECORDING_TOOLS_DETECTED", 
                                           f"Recording tools detected: {running_tools}")
        
        return active_recording_tools  # Only return actively recording tools

    def detect_nvidia_recording(self) -> bool:
        """Detect if NVIDIA is actively recording (not just running GeForce Experience)."""
        try:
            for proc in psutil.process_iter(['name', 'cpu_percent']):
                proc_name = proc.info['name'].lower()
                cpu_percent = proc.info['cpu_percent'] or 0
                
                # Check for NVIDIA processes with high CPU usage indicating active recording
                if any(nvidia_proc.lower() in proc_name for nvidia_proc in Config.NVIDIA_RECORDING_PROCESSES):
                    if cpu_percent > Config.NVIDIA_CPU_THRESHOLD:
                        return True
            return False
        except Exception:
            return False

    def disable_nvidia_recording(self) -> None:
        """Attempt to disable NVIDIA recording features."""
        try:
            # This is a placeholder - actual implementation would require
            # administrative privileges and system-specific commands
            SecurityUtils.log_security_event("NVIDIA_DISABLE_ATTEMPT", 
                                           "Attempted to disable NVIDIA recording features")
                    
        except Exception as e:
            SecurityUtils.log_security_event("NVIDIA_DISABLE_ERROR", 
                                           f"Error disabling NVIDIA recording: {e}")

    def start_security_monitoring(self) -> None:
        """Start monitoring for security threats."""
        self.screen_monitoring_active = True
        SecurityUtils.log_security_event("SECURITY_MONITORING_STARTED", 
                                       "Screen recording and key monitoring activated")
        
        # Start monitoring in a separate thread
        self.monitoring_thread = threading.Thread(target=self.security_monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Try to start keyboard monitoring
        try:
            if KEYBOARD_AVAILABLE:
                self.monitor_print_screen_key()
        except Exception as e:
            print(f"Could not start keyboard monitoring: {e}")

    def stop_security_monitoring(self) -> None:
        """Stop security monitoring."""
        self.screen_monitoring_active = False
        SecurityUtils.log_security_event("SECURITY_MONITORING_STOPPED", 
                                       "Security monitoring deactivated")

    def security_monitoring_loop(self) -> None:
        """Continuous monitoring loop for security threats."""
        while self.screen_monitoring_active:
            try:
                # Check for recording tools
                detected_tools = self.detect_screen_recording_tools()
                if detected_tools:
                    self.pending_recording_tools = detected_tools
                else:
                    self.pending_recording_tools = []
                
                # Sleep for monitoring interval
                time.sleep(Config.MONITORING_LOOP_INTERVAL)
                
            except Exception as e:
                SecurityUtils.log_security_event("MONITORING_ERROR", f"Monitoring loop error: {e}")
                time.sleep(Config.MONITORING_ERROR_RETRY_INTERVAL)

    def check_recording_alert_needed(self, detected_tools: List[str]) -> bool:
        """Check if we should show recording alert based on cooldown and current state."""
        current_time = time.time()
        
        # Check cooldown period
        if current_time - self.last_recording_detection_time < Config.RECORDING_ALERT_COOLDOWN:
            return False
            
        if len(detected_tools) > 0:
            self.last_recording_detection_time = current_time
            return True
            
        return False

    def monitor_print_screen_key(self) -> None:
        """Monitor for Print Screen key press."""
        if KEYBOARD_AVAILABLE:
            try:
                keyboard.add_hotkey('print screen', self.on_print_screen_detected)
                keyboard.add_hotkey('alt+print screen', self.on_print_screen_detected)
                keyboard.add_hotkey('windows+shift+s', self.on_snipping_tool_detected)
            except Exception as e:
                print(f"Could not set up keyboard hotkeys: {e}")
        else:
            print("Keyboard monitoring not available")

    def on_print_screen_detected(self) -> None:
        """Handle Print Screen key detection."""
        SecurityUtils.log_security_event("PRINT_SCREEN_DETECTED", 
                                       "User attempted to capture screen using Print Screen")
        # Store for main thread to process
        if self.check_recording_alert_needed([Config.PRINT_SCREEN_DETECTION_MESSAGE]):
            self.pending_recording_tools.append(Config.PRINT_SCREEN_DETECTION_MESSAGE)

    def on_snipping_tool_detected(self) -> None:
        """Handle Snipping Tool hotkey detection."""
        SecurityUtils.log_security_event("SNIPPING_TOOL_HOTKEY", 
                                       "User attempted to use Snipping Tool hotkey")
        # Store for main thread to process
        if self.check_recording_alert_needed([Config.SNIPPING_TOOL_DETECTION_MESSAGE]):
            self.pending_recording_tools.append(Config.SNIPPING_TOOL_DETECTION_MESSAGE)

    def force_check_recording_tools(self) -> List[str]:
        """Force check for recording tools bypassing cooldown periods."""
        return self.detect_screen_recording_tools()

    def update_last_recording_detection_time(self) -> None:
        """Update last recording detection time to current time."""
        self.last_recording_detection_time = time.time()
