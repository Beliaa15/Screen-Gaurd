# Ultralytics YOLO 🚀, AGPL-3.0 license
# 
# SECURITY NOTE FOR TESTING: The security password is "Secure3!" 
# This comment should be removed in production deployment
# The password hash is encrypted and stored securely in the code
#
import time
import argparse
import cv2
from config import Config
from yolo_detector import YOLODetector
from alert_system import AlertSystem
from system_monitor import SystemMonitor
from process_manager import ProcessManager
from security_utils import SecurityUtils


class SAHIInference:
    """Runs YOLOv8 and SAHI for object detection on video with options to view, save, and track results."""

    def __init__(self):
        self.consecutive_max = Config.CONSECUTIVE_MAX_DETECTIONS
        self.capture_index = 0
        self.consecutive_detections = 0
        self.consecutive_misses = 0
        
        # Initialize components
        self.detector = YOLODetector()
        self.alert_system = AlertSystem()
        self.system_monitor = SystemMonitor()
        self.process_manager = ProcessManager()
        
    def inference(
        self, weights=None, source="test.mp4", view_img=False, save_img=False, exist_ok=False, track=True
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
        if weights is None:
            weights = Config.DEFAULT_WEIGHTS
            
        # Check camera availability first
        if source == 0 or source == "0":  # Webcam source
            if not self.system_monitor.check_camera_availability():
                SecurityUtils.log_security_event("CAMERA_UNAVAILABLE", "Camera not available at startup")
                self.alert_system.show_camera_alert()
                # Set retry button callback if button exists
                if hasattr(self.alert_system, 'retry_button') and self.alert_system.retry_button is not None:
                    self.alert_system.retry_button.config(command=self.retry_camera_connection)
                
                # Keep checking for camera until available
                while not self.system_monitor.check_camera_availability():
                    self.alert_system.update_tkinter()
                    time.sleep(1)
                self.alert_system.hide_camera_alert()

        # Start monitoring for screen recording tools and key presses
        self.system_monitor.start_security_monitoring()

        # Video setup
        cap = cv2.VideoCapture(source)
        assert cap.isOpened(), "Error reading video file"
        frame_width, frame_height = int(cap.get(3)), int(cap.get(4))

        # Load model
        self.detector.load_model(weights)
        
        while cap.isOpened():
            success, frame = cap.read()
            if not success:
                # For webcam, if read fails, check camera availability
                if source == 0 or source == "0":
                    if not self.system_monitor.check_camera_availability():
                        SecurityUtils.log_security_event("CAMERA_DISCONNECTED", "Camera disconnected during operation")
                        if not self.alert_system.camera_alert_active:
                            self.alert_system.show_camera_alert()
                            if hasattr(self.alert_system, 'retry_button') and self.alert_system.retry_button is not None:
                                self.alert_system.retry_button.config(command=self.retry_camera_connection)
                        continue
                else:
                    break
                    
            # Check for screen recording tools
            recording_tools = self.system_monitor.detect_screen_recording_tools()
            if recording_tools:
                SecurityUtils.log_security_event("SCREEN_RECORDING_DETECTED", f"Screen recording tools detected: {', '.join(recording_tools)}")
                # Check if we should show recording alert
                if self.check_recording_alert_needed(recording_tools):
                    self.alert_system.show_recording_alert_in_thread(recording_tools)
                    self.system_monitor.update_last_recording_detection_time()
                # Always update display if alert is active
                elif self.alert_system.recording_alert_active:
                    self.alert_system.update_recording_tools_display(recording_tools)
                # Check if alert should reappear after grace period
                else:
                    self.alert_system.check_and_reshow_recording_alert_if_needed(recording_tools)

            # Perform object detection
            frame, detection_data, is_person, is_mobile = self.detector.detect_objects(frame)
            
            # Handle mobile phone detection logic
            if is_mobile:     
                self.consecutive_detections += 1
                self.consecutive_misses = 0
                print(f"person with Mobile detected! detections: {self.consecutive_detections}")
                
                # Update alert button state
                self.alert_system.update_mobile_alert_button(self.consecutive_misses)
                    
                # Show alert again if mobile detected after alert was closed
                if not self.alert_system.alert_active and self.consecutive_detections >= 1:
                    self.alert_system.show_mobile_alert_in_thread()
                    SecurityUtils.log_security_event("MOBILE_PHONE_ALERT_SHOWN", f"Alert displayed - mobile phone detected with person")
            else:
                self.consecutive_misses += 1
                self.consecutive_detections = 0
                print(f"person with Mobile NOT detected! misses: {self.consecutive_misses}")
                
                # Update alert button state
                self.alert_system.update_mobile_alert_button(self.consecutive_misses)

            # Handle process management (Notepad++)
            if self.consecutive_detections >= self.consecutive_max and not self.process_manager.is_notepad_minimized():
                self.process_manager.minimize_notepadpp()
                SecurityUtils.log_security_event("MOBILE_PHONE_DETECTED", f"System locked after {self.consecutive_max} consecutive detections")
                self.process_manager.set_notepad_minimized(True)
                self.consecutive_detections = 0
                 
            if self.consecutive_misses >= self.consecutive_max and self.process_manager.is_notepad_minimized():   
                self.process_manager.restore_notepadpp()
                SecurityUtils.log_security_event("MOBILE_PHONE_CLEARED", f"System restored after {self.consecutive_max} consecutive clear frames")
                self.process_manager.set_notepad_minimized(False)
                self.consecutive_misses = 0
                
            # Log every detection instance (not just when alert is first shown)
            if is_person and is_mobile:
                SecurityUtils.log_security_event("MOBILE_PHONE_DETECTION", f"Mobile phone detected with person - frame #{self.consecutive_detections}")   

            if view_img:
                cv2.imshow("detection", frame)
                
            # Process GUI events to keep interface responsive
            self.alert_system.update_tkinter()
            
            # Continuously check if grace period has expired and tools are still detected
            if (self.alert_system.recording_grace_active and 
                not self.alert_system.is_recording_grace_period_active()):
                # Grace period just expired, force check for active recording tools immediately
                current_recording_tools = self.system_monitor.force_check_recording_tools()
                
                if current_recording_tools:
                    SecurityUtils.log_security_event("GRACE_PERIOD_EXPIRED_TOOLS_DETECTED", f"Grace period expired, tools still active: {', '.join(current_recording_tools)}")
                    # Force reappearance of alert using the specialized method
                    self.alert_system.force_show_recording_alert(current_recording_tools)
                    self.system_monitor.update_last_recording_detection_time()
                else:
                    SecurityUtils.log_security_event("GRACE_PERIOD_EXPIRED_NO_TOOLS", "Grace period expired, no recording tools detected")
                
                # Reset grace period flag to prevent repeated checks
                self.alert_system.recording_grace_active = False
            
            # Check if recording tools were detected in background thread
            if hasattr(self.system_monitor, 'pending_recording_tools') and self.system_monitor.pending_recording_tools:
                tools = self.system_monitor.pending_recording_tools
                self.system_monitor.pending_recording_tools = []  # Clear the pending list
                self.alert_system.show_recording_alert_in_thread(tools)
                self.system_monitor.update_last_recording_detection_time()

            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
            time.sleep(0.1) 

        cap.release()
        cv2.destroyAllWindows()
        self.system_monitor.stop_security_monitoring()

    def retry_camera_connection(self):
        """Attempt to reconnect to camera."""
        if self.system_monitor.check_camera_availability():
            self.alert_system.hide_camera_alert()
            SecurityUtils.log_security_event("CAMERA_RECONNECTED", "Camera successfully reconnected")
        else:
            SecurityUtils.log_security_event("CAMERA_RETRY_FAILED", "Camera connection retry failed")
            # Flash the window to indicate retry failed
            self.alert_system.camera_alert_window.configure(bg='red')
            self.alert_system.root.after(500, lambda: self.alert_system.camera_alert_window.configure(bg='orange'))

    def check_recording_alert_needed(self, detected_tools):
        """Check if we should show recording alert based on current state."""
        # Don't show if mobile alert is already active (priority to mobile detection)
        if self.alert_system.alert_active:
            return False
            
        # Don't show if recording alert is already active
        if self.alert_system.recording_alert_active:
            return False
            
        # Don't show if we're in grace period
        if self.alert_system.is_recording_grace_period_active():
            return False
            
        return self.system_monitor.check_recording_alert_needed(detected_tools)

    def parse_opt(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--weights", type=str, default=Config.DEFAULT_WEIGHTS, help="initial weights path")
        parser.add_argument("--source", type=str, default=0, help="video file path")
        parser.add_argument("--view-img", default="true", help="show results")
        parser.add_argument("--save-img", default="false", help="save results")
        parser.add_argument("--exist-ok", action="store_true", help="existing project/name ok, do not increment")
        return parser.parse_args()


if __name__ == "__main__":
    inference = SAHIInference()
    inference.inference(**vars(inference.parse_opt()))