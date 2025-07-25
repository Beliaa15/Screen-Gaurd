"""
System monitoring utilities for detecting screen recording tools and managing processes.
"""
import cv2
import psutil
import time
import threading
import subprocess
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


class SystemMonitor:
    """Monitor system processes and activities for security threats."""
    
    def __init__(self):
        self.screen_monitoring_active = False
        self.pending_recording_tools = []
        self.last_recording_detection_time = 0
        
    def check_camera_availability(self) -> bool:
        """Check if camera is available and working."""
        try:
            # Try to open camera
            test_cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX)
            if test_cap.isOpened():
                ret, _ = test_cap.read()
                test_cap.release()
                return ret
            else:
                test_cap.release()
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
                
                # Check for actively recording tools (higher CPU usage or known active recorders)
                for tool in Config.ACTIVE_RECORDING_PROCESSES:
                    if tool.lower() in proc_name:
                        # Get CPU usage to determine if actively recording
                        try:
                            cpu_usage = proc.cpu_percent(interval=Config.CPU_MEASUREMENT_INTERVAL)
                            if cpu_usage > Config.RECORDING_CPU_THRESHOLD:  # If using more than threshold CPU, likely recording
                                active_recording_tools.append(proc.info['name'])
                            else:
                                # For some tools, even if CPU is low, we consider them active if running
                                # This ensures we catch tools that might be idle but ready to record
                                active_recording_tools.append(proc.info['name'])
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # If we can't get CPU usage, assume it's active if it's a known recorder
                            active_recording_tools.append(proc.info['name'])
                
                # Check for any recording-capable tools
                for tool in Config.SCREEN_RECORDING_PROCESSES:
                    if tool.lower() in proc_name:
                        running_tools.append(proc.info['name'])
                        # Also add to active tools if it's a recording process
                        if proc.info['name'] not in active_recording_tools:
                            active_recording_tools.append(proc.info['name'])
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Only return active recording tools for alerts, but log all detected tools
        if running_tools:
            SecurityUtils.log_security_event("RECORDING_TOOLS_DETECTED", f"Recording-capable tools running: {', '.join(running_tools)}")
        
        return active_recording_tools  # Only return actively recording tools

    def detect_nvidia_recording(self) -> bool:
        """Detect if NVIDIA is actively recording (not just running GeForce Experience)."""
        try:
            # Check for NVIDIA recording-specific processes
            for proc in psutil.process_iter(['name', 'cmdline', 'cpu_percent']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(nvidia_proc.lower() in proc_name for nvidia_proc in Config.NVIDIA_RECORDING_PROCESSES):
                        # Check CPU usage - if NVIDIA Share is using significant CPU, it might be recording
                        cpu_usage = proc.cpu_percent(interval=Config.CPU_MEASUREMENT_INTERVAL)
                        if cpu_usage > Config.NVIDIA_CPU_THRESHOLD:  # Higher threshold for NVIDIA processes
                            return True
                        
                        # Check command line for recording-related arguments
                        cmdline = proc.info.get('cmdline', [])
                        if cmdline and any(keyword in arg.lower() for arg in cmdline for keyword in Config.RECORDING_KEYWORDS):
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception:
            return False

    def disable_nvidia_recording(self) -> None:
        """Attempt to disable NVIDIA recording features."""
        try:
            # Try to stop NVIDIA recording services
            for service in Config.NVIDIA_SERVICES:
                try:
                    subprocess.run(['sc', 'stop', service], capture_output=True, check=False)
                    SecurityUtils.log_security_event("NVIDIA_SERVICE_STOPPED", f"Stopped NVIDIA service: {service}")
                except subprocess.SubprocessError:
                    pass
                    
            # Kill NVIDIA Share if it's using high CPU (likely recording)
            for proc in psutil.process_iter(['name', 'cpu_percent']):
                try:
                    if 'nvidia share' in proc.info['name'].lower():
                        cpu_usage = proc.cpu_percent(interval=Config.CPU_MEASUREMENT_INTERVAL)
                        if cpu_usage > Config.NVIDIA_CPU_THRESHOLD:
                            proc.terminate()
                            SecurityUtils.log_security_event("NVIDIA_SHARE_TERMINATED", "Terminated NVIDIA Share due to high CPU usage")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except Exception as e:
            SecurityUtils.log_security_event("NVIDIA_DISABLE_FAILED", f"Failed to disable NVIDIA recording: {e}")

    def start_security_monitoring(self) -> None:
        """Start monitoring for security threats."""
        self.screen_monitoring_active = True
        SecurityUtils.log_security_event("SECURITY_MONITORING_STARTED", "Screen recording and key monitoring activated")
        
        # Start monitoring in a separate thread
        monitoring_thread = threading.Thread(target=self.security_monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        # Try to start keyboard monitoring
        try:
            self.monitor_print_screen_key()
        except Exception as e:
            SecurityUtils.log_security_event("KEYBOARD_MONITORING_FAILED", f"Could not start keyboard monitoring: {e}")

    def stop_security_monitoring(self) -> None:
        """Stop security monitoring."""
        self.screen_monitoring_active = False
        SecurityUtils.log_security_event("SECURITY_MONITORING_STOPPED", "Security monitoring deactivated")

    def security_monitoring_loop(self) -> None:
        """Continuous monitoring loop for security threats."""
        while self.screen_monitoring_active:
            try:
                # Check for screen recording tools every configured interval
                recording_tools = self.detect_screen_recording_tools()
                
                # Also check for NVIDIA recording activity
                if self.detect_nvidia_recording():
                    recording_tools.append(Config.NVIDIA_RECORDING_ACTIVE_MESSAGE)
                
                if recording_tools:
                    SecurityUtils.log_security_event("SCREEN_RECORDING_DETECTED", f"Active recording detected: {', '.join(recording_tools)}")
                    # Use dedicated recording alert and ensure it runs in main thread
                    if self.check_recording_alert_needed(recording_tools):
                        # Store the tools for main thread access
                        self.pending_recording_tools = recording_tools
                
                time.sleep(Config.MONITORING_LOOP_INTERVAL)
            except Exception as e:
                SecurityUtils.log_security_event("MONITORING_ERROR", f"Error in security monitoring: {e}")
                time.sleep(Config.MONITORING_ERROR_RETRY_INTERVAL)

    def check_recording_alert_needed(self, detected_tools: List[str]) -> bool:
        """Check if we should show recording alert based on cooldown and current state."""
        current_time = time.time()
        
        # Check cooldown period
        if current_time - self.last_recording_detection_time < Config.RECORDING_ALERT_COOLDOWN:
            return False
            
        return len(detected_tools) > 0

    def monitor_print_screen_key(self) -> None:
        """Monitor for Print Screen key press."""
        if KEYBOARD_AVAILABLE:
            try:
                for hotkey in Config.PRINT_SCREEN_HOTKEYS:
                    keyboard.add_hotkey(hotkey, self.on_print_screen_detected)
                for hotkey in Config.SNIPPING_TOOL_HOTKEYS:
                    keyboard.add_hotkey(hotkey, self.on_snipping_tool_detected)
            except Exception as e:
                print(f"Keyboard monitoring setup failed: {e}")
        else:
            print("Keyboard monitoring not available - install 'keyboard' package")

    def on_print_screen_detected(self) -> None:
        """Handle Print Screen key detection."""
        SecurityUtils.log_security_event("PRINT_SCREEN_DETECTED", "User attempted to capture screen using Print Screen")
        # Show recording alert for print screen detection - store for main thread
        if self.check_recording_alert_needed([Config.PRINT_SCREEN_DETECTION_MESSAGE]):
            self.pending_recording_tools = [Config.PRINT_SCREEN_DETECTION_MESSAGE]

    def on_snipping_tool_detected(self) -> None:
        """Handle Snipping Tool hotkey detection."""
        SecurityUtils.log_security_event("SNIPPING_TOOL_HOTKEY", "User attempted to use Snipping Tool hotkey")
        # Show recording alert for snipping tool - store for main thread
        if self.check_recording_alert_needed([Config.SNIPPING_TOOL_DETECTION_MESSAGE]):
            self.pending_recording_tools = [Config.SNIPPING_TOOL_DETECTION_MESSAGE]

    def force_check_recording_tools(self) -> List[str]:
        """Force check for recording tools bypassing cooldown periods."""
        recording_tools = self.detect_screen_recording_tools()
        
        # Also check for NVIDIA recording activity
        if self.detect_nvidia_recording():
            recording_tools.append(Config.NVIDIA_RECORDING_ACTIVE_MESSAGE)
        
        return recording_tools

    def update_last_recording_detection_time(self) -> None:
        """Update the timestamp for last recording detection."""
        self.last_recording_detection_time = time.time()