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
from sahi import AutoDetectionModel
from sahi.predict import get_sliced_prediction

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
            self.alert_window.title("تحذير!")
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
            info_text = f"""SECURITY ALERT DETAILS:
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
        # Video setup
        cap = cv2.VideoCapture(source)
        assert cap.isOpened(), "Error reading video file"
        frame_width, frame_height = int(cap.get(3)), int(cap.get(4))


        # Load model
        self.load_model(weights)
        while cap.isOpened():
            success, frame = cap.read()
            if not success:
                break
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
            if isPerson and isMobile:     
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
                        self.ok_button.config(state='normal', text='OK - Safe to Close')
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


if __name__ == "__main__":
    inference = SAHIInference()
    inference.inference(**vars(inference.parse_opt()))