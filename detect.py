# Ultralytics YOLO 🚀, AGPL-3.0 license
import psutil
import time
import pygetwindow as gw
import tkinter as tk
from tkinter import messagebox
import argparse
from pathlib import Path
import threading
import torch
import cv2
import socket
import os
import getpass
from datetime import datetime
import subprocess
from sahi import AutoDetectionModel
from sahi.predict import get_sliced_prediction

# Try to import keyboard for monitoring (optional)
try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False
    print("Keyboard monitoring not available - install 'keyboard' package for full functionality")

from ultralytics.utils.files import increment_path
from ultralytics.utils.plotting import Annotator, colors


class SAHIInference:
    """Runs YOLOv8 and SAHI for object detection on video with options to view, save, and track results."""

    def __init__(self):
         self.consecutive_max=3
         self.capture_index = 0
         self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
         self.detection_model = None
         self.consecutive_detections = 0
         self.consecutive_misses = 0  
         self.notepad_minimized = False
         self.alert_window = None
         self.alert_thread = None
         self.stop_thread = False
         self.root = None
         self.ok_button = None
         self.alert_active = False
         self.camera_alert_window = None
         self.camera_alert_active = False
         self.recording_alert_window = None
         self.recording_alert_active = False
         self.last_recording_detection_time = 0
         self.recording_alert_cooldown = 30  # 30 seconds cooldown
         self.screen_monitoring_active = False
         self.pending_recording_tools = []  # Store tools detected in background thread
         self.screen_recording_processes = [
             'snippingtool.exe', 'screensketcher.exe', 'obs64.exe', 'obs32.exe',
             'camtasia.exe', 'bandicam.exe', 'fraps.exe', 'xsplit.exe',
             'streamlabs obs.exe', 'nvidia share.exe'
         ]
         # More aggressive recording detection - processes that are likely actively recording
         self.active_recording_processes = [
             'obs64.exe', 'obs32.exe', 'camtasia.exe', 'bandicam.exe', 
             'fraps.exe', 'xsplit.exe', 'streamlabs obs.exe'
         ]

    def load_model(self, weights):
        """Loads a YOLOv8 model with specified weights for object detection using SAHI."""
        yolov8_model_path = f"models/{weights}"
        
        # Create models directory if it doesn't exist
        Path("models").mkdir(exist_ok=True)
        
        # Check if model file exists, if not use the one in root directory
        if not Path(yolov8_model_path).exists():
            if Path(weights).exists():
                yolov8_model_path = weights
            else:
                # Let ultralytics download the model automatically
                yolov8_model_path = weights
        
        self.detection_model = AutoDetectionModel.from_pretrained(
            model_type="yolov8", model_path=yolov8_model_path, confidence_threshold=0.5, device=self.device
        )
    
    def create_root(self):
            """Create the Tkinter root window."""
            if self.root is None:
                self.root = tk.Tk()
                self.root.withdraw()  # Hide the root window initially

    def show_alert(self):
        """Display a big alert dialog to the user."""
        self.create_root()

        if self.alert_window is None:
            # Get system information
            sys_info = self.get_system_info()
            
            # Create a centered window
            self.alert_window = tk.Toplevel(self.root)
            self.alert_window.title("Screen Guard")
            #self.alert_window.overrideredirect(True)
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
                command=self.hide_alert, 
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
        self.log_security_event("SECURITY_ALERT_CREATED", f"Full-screen security alert created and displayed")

    def hide_alert(self):
        """Hide the alert window only if mobile is not detected for 3 consecutive frames."""
        if self.consecutive_misses >= self.consecutive_max:
            if self.alert_window is not None:
                self.alert_window.withdraw()  # Hide the alert window
                self.alert_window.attributes("-topmost", False)  # Remove topmost attribute
                self.alert_active = False
                self.log_security_event("SECURITY_ALERT_CLOSED", f"Alert closed by user after {self.consecutive_max} consecutive clear frames")
                print("Alert closed - no mobile detected for 3 consecutive frames")
        else:
            self.log_security_event("ALERT_CLOSE_DENIED", f"User attempted to close alert but mobile still detected - {self.consecutive_max - self.consecutive_misses} more clear frames needed")
            print(f"Cannot close alert - mobile still detected. Need {self.consecutive_max - self.consecutive_misses} more misses")

    def show_alert_in_thread(self):
        """Show alert in a thread-safe manner."""
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
                    self.log_security_event("SECURITY_ALERT_REAPPEARED", "Alert window reappeared - mobile phone detected again")
            except tk.TclError:
                # Window doesn't exist anymore, create new one
                self.alert_window = None
                self.show_alert()
        else:
            # Create and show the alert window
            self.show_alert()
    
    def close_alert(self):
        """Close the alert window if it is open."""
        if self.alert_window is not None:
            try:
                if self.alert_window.winfo_exists():
                    self.hide_alert()
                    print("Alert window closed.")
            except tk.TclError:
                # Window doesn't exist anymore
                print("Alert window already closed.")

    def minimize_notepadpp(self):
        """Minimize Notepad++ window."""
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'notepad++.exe':
                # Get the Notepad++ window by title
                windows = gw.getWindowsWithTitle("Notepad++")
                if windows:
                    windows[0].minimize()
                    sys_info = self.get_system_info()
                    print(f"SECURITY ALERT: Minimized Notepad++ - {sys_info['computer_name']} ({sys_info['ip_address']}) - User: {sys_info['username']} - {sys_info['timestamp']}")
                    # Log security event
                    self.log_security_event("Minimized Notepad++")
                    # Show alert in main thread
                    self.show_alert_in_thread()
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
                    self.log_security_event("Restored Notepad++")
                    self.close_alert()
                return  # Stop searching after finding Notepad++ process
            
    def inference(
        self, weights="yolov8m.pt", source="test.mp4", view_img=False, save_img=False, exist_ok=False, track=True
    ):
        """
        Run object detection on a video using YOLOv8 and SAHI.

        Args:
            weights (str): Model weights path.
            source (str): Video file path.
            view_img (bool): Show results.
            save_img (bool): Save results.
            exist_ok (bool): Overwrite existing files.
            track (bool): Enable object tracking with SAHI
        """
        # Check camera availability first
        if source == 0 or source == "0":  # Webcam source
            if not self.check_camera_availability():
                self.log_security_event("CAMERA_UNAVAILABLE", "Camera not available at startup")
                self.show_camera_alert()
                # Keep checking for camera until available
                while not self.check_camera_availability():
                    if self.root:
                        try:
                            self.root.update()
                        except tk.TclError:
                            pass
                    time.sleep(1)
                self.hide_camera_alert()

        # Start monitoring for screen recording tools and key presses
        self.start_security_monitoring()

        # Video setup
        cap = cv2.VideoCapture(source)
        assert cap.isOpened(), "Error reading video file"
        frame_width, frame_height = int(cap.get(3)), int(cap.get(4))

        # Load model
        self.load_model(weights)
        
        while cap.isOpened():
            success, frame = cap.read()
            if not success:
                # For webcam, if read fails, check camera availability
                if source == 0 or source == "0":
                    if not self.check_camera_availability():
                        self.log_security_event("CAMERA_DISCONNECTED", "Camera disconnected during operation")
                        if not self.camera_alert_active:
                            self.show_camera_alert()
                        continue
                else:
                    break
                    
            # Check for screen recording tools
            recording_tools = self.detect_screen_recording_tools()
            if recording_tools:
                self.log_security_event("SCREEN_RECORDING_DETECTED", f"Screen recording tools detected: {', '.join(recording_tools)}")
                # Check if we should show recording alert
                if self.check_recording_alert_needed(recording_tools):
                    self.show_recording_alert(recording_tools)

            annotator = Annotator(frame)  # Initialize annotator for plotting detection and tracking results
            results = get_sliced_prediction(
                frame,
                self.detection_model,
                slice_height=512,
                slice_width=512,
                overlap_height_ratio=0.2,
                overlap_width_ratio=0.2,
            )
            detection_data = [
                (det.category.name, det.category.id, (det.bbox.minx, det.bbox.miny, det.bbox.maxx, det.bbox.maxy),det.score.value)
                for det in results.object_prediction_list
            ]
            isPerson = False
            isMobile = False
            for det in detection_data:
                annotator.box_label(det[2], label=f"Class: {det[0]}, Conf: {det[3]:.2f}", color=colors(int(det[1]), True))
                if det[0] == "person":
                    isPerson = True
                elif det[0] == "cell phone":
                    isMobile = True
            if isMobile:     
                self.consecutive_detections += 1
                self.consecutive_misses = 0
                print(f"person with Mobile detected! detections: {self.consecutive_detections}")
                # Disable OK button when mobile is detected
                if self.ok_button:
                    self.ok_button.config(state='disabled', text='OK (Mobile Detected)')
                    
                # Show alert again if mobile detected after alert was closed
                if not self.alert_active and self.consecutive_detections >= 1:
                    self.show_alert_in_thread()
                    self.log_security_event("MOBILE_PHONE_ALERT_SHOWN", f"Alert displayed - mobile phone detected with person")
            else:
                self.consecutive_misses += 1
                self.consecutive_detections = 0
                print(f"person with Mobile NOT detected! misses: {self.consecutive_misses}")
                
                # Enable OK button after 3 consecutive misses
                if self.consecutive_misses >= self.consecutive_max:
                    if self.ok_button and self.ok_button['state'] == 'disabled':
                        self.ok_button.config(state='normal', text='OK (No Mobile Detected - Safe to Close)')
                else:
                    # Still counting misses, keep button disabled
                    if self.ok_button:
                        self.ok_button.config(state='disabled', text=f'OK ({self.consecutive_max - self.consecutive_misses} more needed)')

            if self.consecutive_detections >= self.consecutive_max and not self.notepad_minimized:
                self.minimize_notepadpp()
                self.log_security_event("MOBILE_PHONE_DETECTED", f"System locked after {self.consecutive_max} consecutive detections")
                self.notepad_minimized = True
                self.consecutive_detections = 0
                 
            if self.consecutive_misses >= self.consecutive_max and self.notepad_minimized:   
                self.restore_notepadpp()
                self.log_security_event("MOBILE_PHONE_CLEARED", f"System restored after {self.consecutive_max} consecutive clear frames")
                self.notepad_minimized = False
                self.consecutive_misses = 0
                
            # Log every detection instance (not just when alert is first shown)
            if isPerson and isMobile:
                self.log_security_event("MOBILE_PHONE_DETECTION", f"Mobile phone detected with person - frame #{self.consecutive_detections}")   

            if view_img:
                cv2.imshow("detection", frame)
                
            # Process Tkinter events to keep GUI responsive
            if self.root is not None:
                try:
                    self.root.update()
                    # Check if recording tools were detected in background thread
                    if hasattr(self, 'pending_recording_tools') and self.pending_recording_tools:
                        tools = self.pending_recording_tools
                        self.pending_recording_tools = []  # Clear the pending list
                        self.show_recording_alert(tools)
                except tk.TclError:
                    pass  # Prevent crash if window closed

            #if save_img:
            #    video_writer.write(frame)

            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
            time.sleep(0.1) 

        #video_writer.release()
        cap.release()
        cv2.destroyAllWindows()
        self.stop_security_monitoring()

    def parse_opt(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--weights", type=str, default="yolov8m.pt", help="initial weights path")
        parser.add_argument("--source", type=str, default=0, help="video file path")
        parser.add_argument("--view-img", default="true", help="show results")
        parser.add_argument("--save-img", default="false", help="save results")
        parser.add_argument("--exist-ok", action="store_true", help="existing project/name ok, do not increment")
        return parser.parse_args()

    def get_system_info(self):
        """Get system information for the alert."""
        try:
            # Get IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "Unknown"
        
        # Get logged-in user
        try:
            username = getpass.getuser()
        except:
            username = "Unknown"
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get computer name
        try:
            computer_name = os.environ.get('COMPUTERNAME', 'Unknown')
        except:
            computer_name = "Unknown"
        
        return {
            'ip_address': ip_address,
            'username': username,
            'timestamp': timestamp,
            'computer_name': computer_name
        }
    
    def log_security_event(self, event_type, details=""):
        """Log security events to a file."""
        try:
            sys_info = self.get_system_info()
            log_entry = f"[{sys_info['timestamp']}] {event_type} - Computer: {sys_info['computer_name']} - IP: {sys_info['ip_address']} - User: {sys_info['username']} - {details}\n"
            
            # Create logs directory if it doesn't exist
            Path("logs").mkdir(exist_ok=True)
            
            # Write to log file
            log_file = f"logs/security_log_{datetime.now().strftime('%Y-%m-%d')}.txt"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
                
            print(f"Security event logged: {event_type}")
        except Exception as e:
            print(f"Failed to log security event: {e}")

    def check_camera_availability(self):
        """Check if camera is available and working."""
        try:
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
                for tool in self.active_recording_processes:
                    if tool.lower() in proc_name:
                        # Get CPU usage to determine if actively recording
                        try:
                            cpu_usage = proc.cpu_percent()
                            if cpu_usage > 5:  # If using more than 5% CPU, likely recording
                                active_recording_tools.append(proc.info['name'])
                        except:
                            # If we can't get CPU usage, assume it's active if it's a known recorder
                            active_recording_tools.append(proc.info['name'])
                
                # Check for any recording-capable tools
                for tool in self.screen_recording_processes:
                    if tool.lower() in proc_name:
                        running_tools.append(proc.info['name'])
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Only return active recording tools for alerts, but log all detected tools
        if running_tools:
            self.log_security_event("RECORDING_TOOLS_DETECTED", f"Recording-capable tools running: {', '.join(running_tools)}")
        
        return active_recording_tools  # Only return actively recording tools

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
        self.log_security_event("PRINT_SCREEN_DETECTED", "User attempted to capture screen using Print Screen")
        # Show recording alert for print screen detection - store for main thread
        if self.check_recording_alert_needed(["Print Screen Capture"]):
            self.pending_recording_tools = ["Print Screen Capture"]

    def on_snipping_tool_detected(self):
        """Handle Snipping Tool hotkey detection."""
        self.log_security_event("SNIPPING_TOOL_HOTKEY", "User attempted to use Snipping Tool hotkey")
        # Show recording alert for snipping tool - store for main thread
        if self.check_recording_alert_needed(["Snipping Tool Hotkey"]):
            self.pending_recording_tools = ["Snipping Tool Hotkey"]

    def show_camera_alert(self):
        """Display camera unavailable alert."""
        self.create_root()

        if self.camera_alert_window is None:
            sys_info = self.get_system_info()
            
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

            # Retry button
            retry_button = tk.Button(
                self.camera_alert_window,
                text="Retry Camera Connection",
                command=self.retry_camera_connection,
                font=("Helvetica", 16, "bold"),
                bg="green",
                fg="white",
                width=25
            )
            retry_button.pack(pady=30)

        self.camera_alert_window.deiconify()
        self.camera_alert_window.lift()
        self.camera_alert_window.attributes("-topmost", True)
        self.camera_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.camera_alert_active = True
        
        self.log_security_event("CAMERA_ALERT_SHOWN", "Camera unavailable alert displayed")

    def retry_camera_connection(self):
        """Attempt to reconnect to camera."""
        if self.check_camera_availability():
            self.hide_camera_alert()
            self.log_security_event("CAMERA_RECONNECTED", "Camera successfully reconnected")
        else:
            self.log_security_event("CAMERA_RETRY_FAILED", "Camera connection retry failed")
            # Flash the window to indicate retry failed
            self.camera_alert_window.configure(bg='red')
            self.root.after(500, lambda: self.camera_alert_window.configure(bg='orange'))

    def hide_camera_alert(self):
        """Hide camera alert."""
        if self.camera_alert_window is not None:
            self.camera_alert_window.withdraw()
            self.camera_alert_window.attributes("-topmost", False)
            self.camera_alert_active = False
            self.log_security_event("CAMERA_ALERT_CLOSED", "Camera alert closed - camera available")

    def start_security_monitoring(self):
        """Start monitoring for security threats."""
        self.screen_monitoring_active = True
        self.log_security_event("SECURITY_MONITORING_STARTED", "Screen recording and key monitoring activated")
        
        # Start monitoring in a separate thread
        monitoring_thread = threading.Thread(target=self.security_monitoring_loop)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        # Try to start keyboard monitoring
        try:
            self.monitor_print_screen_key()
        except Exception as e:
            self.log_security_event("KEYBOARD_MONITORING_FAILED", f"Could not start keyboard monitoring: {e}")

    def stop_security_monitoring(self):
        """Stop security monitoring."""
        self.screen_monitoring_active = False
        self.log_security_event("SECURITY_MONITORING_STOPPED", "Security monitoring deactivated")

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
                    self.log_security_event("SCREEN_RECORDING_DETECTED", f"Active recording detected: {', '.join(recording_tools)}")
                    # Use dedicated recording alert and ensure it runs in main thread
                    if self.check_recording_alert_needed(recording_tools):
                        # Store the tools for main thread access
                        self.pending_recording_tools = recording_tools
                
                time.sleep(2)
            except Exception as e:
                self.log_security_event("MONITORING_ERROR", f"Error in security monitoring: {e}")
                time.sleep(5)

    def show_recording_alert(self, detected_tools):
        """Display an alert for screen recording tool detection."""
        self.create_root()

        if self.recording_alert_window is None:
            sys_info = self.get_system_info()
            
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
            tools_label = tk.Label(
                self.recording_alert_window,
                text=tools_text,
                fg="orange",
                bg="darkred",
                font=("Courier", 18, "bold"),
                wraplength=screen_width - 100
            )
            tools_label.pack(pady=20)

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

            # Close button
            close_button = tk.Button(
                self.recording_alert_window,
                text="I Have Closed Recording Apps",
                command=self.hide_recording_alert,
                font=("Helvetica", 18, "bold"),
                bg="white",
                fg="darkred",
                width=30,
                height=2
            )
            close_button.pack(pady=30)

        # Show the recording alert window
        self.recording_alert_window.deiconify()
        self.recording_alert_window.lift()
        self.recording_alert_window.attributes("-topmost", True)
        self.recording_alert_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self.recording_alert_active = True
        
        # Update timestamp for last detection
        self.last_recording_detection_time = time.time()
        
        self.log_security_event("RECORDING_ALERT_SHOWN", f"Screen recording alert displayed for tools: {', '.join(detected_tools)}")

    def hide_recording_alert(self):
        """Hide the recording alert window."""
        if self.recording_alert_window is not None:
            # Check if recording tools are still running
            running_tools = self.detect_screen_recording_tools()
            if running_tools:
                # Flash red to indicate tools still running
                self.recording_alert_window.configure(bg='red')
                self.root.after(500, lambda: self.recording_alert_window.configure(bg='darkred'))
                self.log_security_event("RECORDING_ALERT_CLOSE_DENIED", f"Recording tools still running: {', '.join(running_tools)}")
                
                # Update the detected tools display
                for widget in self.recording_alert_window.winfo_children():
                    if isinstance(widget, tk.Label) and "Detected Tools:" in widget.cget("text"):
                        widget.config(text=f"Detected Tools: {', '.join(running_tools)}")
                        break
            else:
                # All clear, hide the alert
                self.recording_alert_window.withdraw()
                self.recording_alert_window.attributes("-topmost", False)
                self.recording_alert_active = False
                self.log_security_event("RECORDING_ALERT_CLOSED", "Recording alert closed - no recording tools detected")

    def check_recording_alert_needed(self, detected_tools):
        """Check if we should show recording alert based on cooldown and current state."""
        current_time = time.time()
        
        # Don't show if mobile alert is already active (priority to mobile detection)
        if self.alert_active:
            return False
            
        # Don't show if recording alert is already active
        if self.recording_alert_active:
            return False
            
        # Check cooldown period
        if current_time - self.last_recording_detection_time < self.recording_alert_cooldown:
            return False
            
        return len(detected_tools) > 0

    def detect_nvidia_recording(self):
        """Detect if NVIDIA is actively recording (not just running GeForce Experience)."""
        try:
            # Check for NVIDIA recording-specific processes
            nvidia_recording_processes = ['nvidia share.exe', 'nvcontainer.exe']
            for proc in psutil.process_iter(['name', 'cmdline', 'cpu_percent']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(nvidia_proc.lower() in proc_name for nvidia_proc in nvidia_recording_processes):
                        # Check CPU usage - if NVIDIA Share is using significant CPU, it might be recording
                        cpu_usage = proc.cpu_percent()
                        if cpu_usage > 10:  # Higher threshold for NVIDIA processes
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
            nvidia_services = ['NvContainerLocalSystem', 'NVDisplay.ContainerLocalSystem']
            for service in nvidia_services:
                try:
                    subprocess.run(['sc', 'stop', service], capture_output=True, check=False)
                    self.log_security_event("NVIDIA_SERVICE_STOPPED", f"Stopped NVIDIA service: {service}")
                except:
                    pass
                    
            # Kill NVIDIA Share if it's using high CPU (likely recording)
            for proc in psutil.process_iter(['name', 'cpu_percent']):
                try:
                    if 'nvidia share' in proc.info['name'].lower():
                        if proc.cpu_percent() > 10:
                            proc.terminate()
                            self.log_security_event("NVIDIA_SHARE_TERMINATED", "Terminated NVIDIA Share due to high CPU usage")
                except:
                    pass
                    
        except Exception as e:
            self.log_security_event("NVIDIA_DISABLE_FAILED", f"Failed to disable NVIDIA recording: {e}")


if __name__ == "__main__":
    inference = SAHIInference()
    inference.inference(**vars(inference.parse_opt()))