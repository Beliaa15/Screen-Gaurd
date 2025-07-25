# Ultralytics YOLO 🚀, AGPL-3.0 license
# 
# SECURITY NOTE: Password is securely encrypted and stored in security_utils.py
# This file does not contain any hardcoded credentials
#

import argparse
import cv2
import time
from typing import Dict, Any, Union

from ..core.config import Config
from ..core.base import SecurityEvent
from ..utils.security_utils import SecurityUtils
from .yolo_detector import YOLODetector
from ..security.alert_system import AlertSystem
from ..security.system_monitor import SystemMonitor
from ..security.process_manager import ProcessManager
from ..ui.security_overlay import SecurityOverlay


class DetectorService:
    """Main detection service that orchestrates YOLO detection with security monitoring."""

    def __init__(self):
        self.consecutive_max = Config.CONSECUTIVE_MAX_DETECTIONS
        self.capture_index = 0
        self.consecutive_detections = 0
        self.consecutive_misses = 0
        self.gui_authenticated = False  # Track if GUI authentication was completed
        
        # Initialize components
        self.detector = YOLODetector()
        self.alert_system = AlertSystem(Config())
        self.system_monitor = SystemMonitor()
        self.process_manager = ProcessManager()
        
        # Initialize security overlay for authentication
        self.security_overlay = SecurityOverlay()
        
    def set_gui_authenticated(self, authenticated=True):
        """Set GUI authentication status."""
        self.gui_authenticated = authenticated
        if authenticated:
            SecurityUtils.log_security_event("GUI_AUTH_COMPLETE", "GUI authentication completed successfully")
        
    def start_with_authentication(self):
        """Start the system with authentication requirement."""
        SecurityUtils.log_security_event("SYSTEM_STARTUP", "Physical security system starting with authentication")
        
        # Use the authentication manager directly instead of security overlay mainloop
        if self.security_overlay.auth_manager.require_authentication():
            self.run_detection()
        else:
            print("❌ Authentication failed. System access denied.")
            SecurityUtils.log_security_event("AUTH_FAILED", "System access denied due to authentication failure")
        
    def run_detection(
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
        # Check authentication first if required
        if Config.AUTHENTICATION_REQUIRED and not self.gui_authenticated:
            self.start_with_authentication()
            return
        
        if weights is None:
            weights = Config.DEFAULT_WEIGHTS
            
        # Check camera availability first
        if source == 0 or source == "0":
            print("🎥 Initializing camera...")
            # Try different camera backends to avoid MSMF issues
            cap = None
            
            # Try DirectShow backend first (often more stable on Windows)
            try:
                cap = cv2.VideoCapture(source, cv2.CAP_DSHOW)
                if cap.isOpened():
                    ret, test_frame = cap.read()
                    if ret and test_frame is not None:
                        print("✅ Camera initialized successfully with DirectShow backend")
                    else:
                        cap.release()
                        cap = None
            except Exception as e:
                print(f"DirectShow backend failed: {e}")
                if cap:
                    cap.release()
                cap = None
            
            # If DirectShow failed, try default backend
            if cap is None:
                try:
                    cap = cv2.VideoCapture(source)
                    if cap.isOpened():
                        ret, test_frame = cap.read()
                        if ret and test_frame is not None:
                            print("✅ Camera initialized successfully with default backend")
                        else:
                            cap.release()
                            cap = None
                except Exception as e:
                    print(f"Default backend failed: {e}")
                    if cap:
                        cap.release()
                    cap = None
            
            # If all backends failed, show alert
            if cap is None:
                print("❌ Failed to initialize camera with any backend")
                self.alert_system.show_camera_alert()
                self.retry_camera_connection()
                return
        else:
            # For video files, use standard initialization
            cap = cv2.VideoCapture(source)
            if not cap.isOpened():
                print(f"❌ Error reading video file: {source}")
                return

        # Start monitoring for screen recording tools and key presses
        self.system_monitor.start_security_monitoring()

        # Video setup (cap is already initialized above)
        if not cap.isOpened():
            print("❌ Error: Camera/video source is not opened")
            return
            
        # Configure camera properties to reduce MSMF errors
        if source == 0 or source == "0":
            # Set buffer size to 1 to reduce latency and potential errors
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            # Set reasonable frame rate
            cap.set(cv2.CAP_PROP_FPS, 30)
            # Set resolution (optional, comment out if causing issues)
            # cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            # cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            
        frame_width, frame_height = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        print(f"📹 Camera resolution: {frame_width}x{frame_height}")

        # Load model
        self.detector.load_model(weights)
        
        frame_count = 0
        error_count = 0
        max_errors = 10  # Maximum consecutive errors before giving up
        
        print("🚀 Starting detection loop...")
        while True:  # Use True instead of cap.isOpened() for more reliability
            # Check if camera is still accessible
            if not cap.isOpened():
                print("⚠️ Camera appears to be closed, attempting to reopen...")
                cap.release()
                time.sleep(1)  # Wait a moment
                
                # Try to reinitialize camera
                if source == 0 or source == "0":
                    cap = cv2.VideoCapture(source, cv2.CAP_DSHOW)
                    if not cap.isOpened():
                        cap = cv2.VideoCapture(source)
                else:
                    cap = cv2.VideoCapture(source)
                
                if not cap.isOpened():
                    print("❌ Failed to reopen camera. Stopping detection.")
                    break
                    
                # Reconfigure camera properties
                if source == 0 or source == "0":
                    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                    cap.set(cv2.CAP_PROP_FPS, 30)
                    
                print("✅ Camera reopened successfully")
            
            try:
                success, frame = cap.read()
                if not success:
                    error_count += 1
                    if error_count >= max_errors:
                        print(f"❌ Too many consecutive frame reading errors ({error_count}). Stopping detection.")
                        break
                    print(f"⚠️ Frame reading failed (attempt {error_count}/{max_errors})")
                    time.sleep(0.1)  # Brief pause before retry
                    continue
                
                # Reset error count on successful frame read
                error_count = 0
                frame_count += 1
                
                # Periodic status update (every 100 frames)
                if frame_count % 100 == 0:
                    print(f"📊 Processing frame {frame_count}, consecutive detections: {self.consecutive_detections}")
                
                if frame is None:
                    print("⚠️ Received empty frame, skipping...")
                    continue

                # Perform object detection
                annotated_frame, detection_data, has_person, has_mobile = self.detector.detect_objects(frame)

                # Handle mobile phone detection
                if has_mobile:
                    self.consecutive_detections += 1
                    self.consecutive_misses = 0
                    print(f"📱 Mobile detected! Count: {self.consecutive_detections}")
                    
                    if self.consecutive_detections >= self.consecutive_max:
                        self.process_manager.minimize_notepadpp()
                        self.alert_system.show_mobile_alert()
                else:
                    self.consecutive_misses += 1
                    if self.consecutive_misses >= 3:
                        self.consecutive_detections = 0
                        if self.alert_system.alert_active:
                            self.alert_system.hide_mobile_alert()
                            self.process_manager.restore_notepadpp()

                # Update mobile alert button state
                if self.alert_system.alert_active:
                    self.alert_system.update_mobile_alert_button(self.consecutive_misses)

                # Check for screen recording tools periodically
                detected_tools = self.system_monitor.detect_screen_recording_tools()
                if self.check_recording_alert_needed(detected_tools):
                    self.alert_system.show_recording_alert_in_thread(detected_tools)

                # Update GUI components
                self.alert_system.update_tkinter()

                # Display frame
                if view_img:
                    cv2.imshow("Security Monitor", annotated_frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        break

                # Save frame
                if save_img:
                    cv2.imwrite(f"output_frame_{self.capture_index}.jpg", annotated_frame)
                    
            except Exception as e:
                print(f"⚠️ Error processing frame: {e}")
                error_count += 1
                if error_count >= max_errors:
                    print(f"❌ Too many processing errors ({error_count}). Stopping detection.")
                    break
                time.sleep(0.1)  # Brief pause before retry
                continue
            
            # Increment frame counter for successful processing
            self.capture_index += 1

        print(f"🛑 Detection loop ended. Processed {frame_count} frames total.")
        print(f"📊 Final stats - Consecutive detections: {self.consecutive_detections}, Error count: {error_count}")
        cap.release()
        cv2.destroyAllWindows()
        self.system_monitor.stop_security_monitoring()

    def retry_camera_connection(self):
        """Attempt to reconnect to camera."""
        if self.system_monitor.check_camera_availability():
            self.alert_system.hide_camera_alert()
        else:
            print("❌ Camera still unavailable. Please check camera connection.")

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
        parser.add_argument("--source", type=str, default=0, help="file/dir/URL/glob, 0 for webcam")
        parser.add_argument("--view-img", action="store_true", help="show results")
        parser.add_argument("--save-img", action="store_true", help="save results")
        parser.add_argument("--exist-ok", action="store_true", help="existing project/name ok, do not increment")
        parser.add_argument("--track", action="store_true", default=True, help="enable object tracking")
        return parser.parse_args()


# For backward compatibility - alias to the old name
SAHIInference = DetectorService


if __name__ == "__main__":
    detector_service = DetectorService()
    detector_service.run_detection(**vars(detector_service.parse_opt()))
