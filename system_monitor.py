"""
System monitoring utilities for detecting screen recording tools and managing processes.
"""

import psutil
import subprocess
import time
import threading
from config import Config
from security_utils import SecurityUtils

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
        
    def check_camera_availability(self):
        """Check if camera is available and working."""
        try:
            import cv2
            # Try to open camera
            test_cap = cv2.VideoCapture(0)
            if test_cap.isOpened():
                ret, _ = test_cap.read()
                test_cap.release()
                return ret
            else:
                test_cap.release()
                return False
        except Exception:
            return False

    def detect_screen_recording_tools(self):
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
                            cpu_usage = proc.cpu_percent()
                            if cpu_usage > Config.RECORDING_CPU_THRESHOLD:  # If using more than threshold CPU, likely recording
                                active_recording_tools.append(proc.info['name'])
                            else:
                                # For some tools, even if CPU is low, we consider them active if running
                                # This ensures we catch tools that might be idle but ready to record
                                active_recording_tools.append(proc.info['name'])
                        except:
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

    def detect_nvidia_recording(self):
        """Detect if NVIDIA is actively recording (not just running GeForce Experience)."""
        try:
            # Check for NVIDIA recording-specific processes
            for proc in psutil.process_iter(['name', 'cmdline', 'cpu_percent']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(nvidia_proc.lower() in proc_name for nvidia_proc in Config.NVIDIA_RECORDING_PROCESSES):
                        # Check CPU usage - if NVIDIA Share is using significant CPU, it might be recording
                        cpu_usage = proc.cpu_percent()
                        if cpu_usage > Config.NVIDIA_CPU_THRESHOLD:  # Higher threshold for NVIDIA processes
                            return True
                        
                        # Check command line for recording-related arguments
                        cmdline = proc.info.get('cmdline', [])
                        if cmdline and any('record' in arg.lower() or 'capture' in arg.lower() for arg in cmdline):
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception:
            return False

    def disable_nvidia_recording(self):
        """Attempt to disable NVIDIA recording features."""
        try:
            # Try to stop NVIDIA recording services
            for service in Config.NVIDIA_SERVICES:
                try:
                    subprocess.run(['sc', 'stop', service], capture_output=True, check=False)
                    SecurityUtils.log_security_event("NVIDIA_SERVICE_STOPPED", f"Stopped NVIDIA service: {service}")
                except:
                    pass
                    
            # Kill NVIDIA Share if it's using high CPU (likely recording)
            for proc in psutil.process_iter(['name', 'cpu_percent']):
                try:
                    if 'nvidia share' in proc.info['name'].lower():
                        if proc.cpu_percent() > Config.NVIDIA_CPU_THRESHOLD:
                            proc.terminate()
                            SecurityUtils.log_security_event("NVIDIA_SHARE_TERMINATED", "Terminated NVIDIA Share due to high CPU usage")
                except:
                    pass
                    
        except Exception as e:
            SecurityUtils.log_security_event("NVIDIA_DISABLE_FAILED", f"Failed to disable NVIDIA recording: {e}")

    def start_security_monitoring(self):
        """Start monitoring for security threats."""
        self.screen_monitoring_active = True
        SecurityUtils.log_security_event("SECURITY_MONITORING_STARTED", "Screen recording and key monitoring activated")
        
        # Start monitoring in a separate thread
        monitoring_thread = threading.Thread(target=self.security_monitoring_loop)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        # Try to start keyboard monitoring
        try:
            self.monitor_print_screen_key()
        except Exception as e:
            SecurityUtils.log_security_event("KEYBOARD_MONITORING_FAILED", f"Could not start keyboard monitoring: {e}")

    def stop_security_monitoring(self):
        """Stop security monitoring."""
        self.screen_monitoring_active = False
        SecurityUtils.log_security_event("SECURITY_MONITORING_STOPPED", "Security monitoring deactivated")

    def security_monitoring_loop(self):
        """Continuous monitoring loop for security threats."""
        while self.screen_monitoring_active:
            try:
                # Check for screen recording tools every 2 seconds
                recording_tools = self.detect_screen_recording_tools()
                
                # Also check for NVIDIA recording activity
                if self.detect_nvidia_recording():
                    recording_tools.append("NVIDIA Recording Active")
                
                if recording_tools:
                    SecurityUtils.log_security_event("SCREEN_RECORDING_DETECTED", f"Active recording detected: {', '.join(recording_tools)}")
                    # Use dedicated recording alert and ensure it runs in main thread
                    if self.check_recording_alert_needed(recording_tools):
                        # Store the tools for main thread access
                        self.pending_recording_tools = recording_tools
                
                time.sleep(2)
            except Exception as e:
                SecurityUtils.log_security_event("MONITORING_ERROR", f"Error in security monitoring: {e}")
                time.sleep(5)

    def check_recording_alert_needed(self, detected_tools):
        """Check if we should show recording alert based on cooldown and current state."""
        current_time = time.time()
        
        # Check cooldown period
        if current_time - self.last_recording_detection_time < Config.RECORDING_ALERT_COOLDOWN:
            return False
            
        return len(detected_tools) > 0

    def monitor_print_screen_key(self):
        """Monitor for Print Screen key press."""
        if KEYBOARD_AVAILABLE:
            try:
                keyboard.add_hotkey('print screen', self.on_print_screen_detected)
                keyboard.add_hotkey('alt+print screen', self.on_print_screen_detected)
                keyboard.add_hotkey('windows+shift+s', self.on_snipping_tool_detected)
            except Exception as e:
                print(f"Keyboard monitoring setup failed: {e}")
        else:
            print("Keyboard monitoring not available - install 'keyboard' package")

    def on_print_screen_detected(self):
        """Handle Print Screen key detection."""
        SecurityUtils.log_security_event("PRINT_SCREEN_DETECTED", "User attempted to capture screen using Print Screen")
        # Show recording alert for print screen detection - store for main thread
        if self.check_recording_alert_needed(["Print Screen Capture"]):
            self.pending_recording_tools = ["Print Screen Capture"]

    def on_snipping_tool_detected(self):
        """Handle Snipping Tool hotkey detection."""
        SecurityUtils.log_security_event("SNIPPING_TOOL_HOTKEY", "User attempted to use Snipping Tool hotkey")
        # Show recording alert for snipping tool - store for main thread
        if self.check_recording_alert_needed(["Snipping Tool Hotkey"]):
            self.pending_recording_tools = ["Snipping Tool Hotkey"]

    def force_check_recording_tools(self):
        """Force check for recording tools bypassing cooldown periods."""
        recording_tools = self.detect_screen_recording_tools()
        
        # Also check for NVIDIA recording activity
        if self.detect_nvidia_recording():
            recording_tools.append("NVIDIA Recording Active")
        
        return recording_tools

    def update_last_recording_detection_time(self):
        """Update the timestamp for last recording detection."""
        self.last_recording_detection_time = time.time()
