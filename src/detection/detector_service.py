# Ultralytics YOLO 🚀, AGPL-3.0 license
# 
# SECURITY NOTE: Password is securely encrypted and stored in security_utils.py
# This file does not contain any hardcoded credentials
#
import numpy as np
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
        self.last_recording_detection_time = 0
        self.is_running = False  # Flag to control detection loop
        
        # Initialize components
        self.detector = YOLODetector()
        self.alert_system = AlertSystem(Config())
        self.system_monitor = SystemMonitor()
        self.process_manager = ProcessManager()
        
        # Initialize security overlay for authentication
        self.security_overlay = SecurityOverlay()
        
    def is_lighting_ok(self, frame, low_thresh=50, high_thresh=200):
        """Check if lighting conditions are acceptable for reliable detection"""
        avg_brightness = np.mean(frame)
        
        if avg_brightness < low_thresh:
            return False, "Too dark - please increase lighting"
        elif avg_brightness > high_thresh:
            return False, "Too bright - please reduce lighting"
        else:
            return True, "Lighting OK"

    def check_camera_and_lighting(self, source):
        """Initialize camera and check lighting conditions"""
        print("🎥 Initializing camera...")
        
        # Initialize camera
        cap = cv2.VideoCapture(source)
        if not cap.isOpened():
            print("❌ Error: Could not open camera")
            return None, False, "Camera initialization failed"
        
        # Test frame capture
        ret, test_frame = cap.read()
        if not ret or test_frame is None:
            print("❌ Error: Could not capture test frame")
            cap.release()
            return None, False, "Camera frame capture failed"
        
        # Convert frame to grayscale for better brightness calculation
        gray_frame = cv2.cvtColor(test_frame, cv2.COLOR_BGR2GRAY)
        avg_brightness = np.mean(gray_frame)
        print(f"🔍 DEBUG: Frame shape: {test_frame.shape}, Average brightness: {avg_brightness:.2f}")
        
        # Check lighting conditions with debug info
        lighting_ok, lighting_message = self.is_lighting_ok(gray_frame)
        print(f"💡 Lighting check result: {lighting_ok}, Message: {lighting_message}")
        print(f"📊 Brightness value: {avg_brightness:.2f} (Range: 0-255)")
        
        # Always show the lighting check window for debugging
        display_frame = test_frame.copy()
        cv2.putText(display_frame, f"Brightness: {avg_brightness:.1f}", (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
        cv2.putText(display_frame, lighting_message, (10, 70), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0) if lighting_ok else (0, 0, 255), 2)
        cv2.imshow("Lighting Check", display_frame)
        
        if not lighting_ok:
            print("⚠️ Poor lighting detected! Please adjust lighting conditions")
            print("Press 'c' to continue anyway, 'r' to recheck, or 'q' to quit")
            
            while True:
                key = cv2.waitKey(1) & 0xFF
                if key == ord('c'):
                    cv2.destroyWindow("Lighting Check")
                    print("✅ Continuing with current lighting conditions")
                    break
                elif key == ord('r'):
                    # Recheck lighting
                    ret, test_frame = cap.read()
                    if ret:
                        gray_frame = cv2.cvtColor(test_frame, cv2.COLOR_BGR2GRAY)
                        avg_brightness = np.mean(gray_frame)
                        lighting_ok, lighting_message = self.is_lighting_ok(gray_frame)
                        print(f"💡 Lighting recheck: {lighting_message} (Brightness: {avg_brightness:.2f})")
                        
                        display_frame = test_frame.copy()
                        cv2.putText(display_frame, f"Brightness: {avg_brightness:.1f}", (10, 30), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
                        cv2.putText(display_frame, lighting_message, (10, 70), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0) if lighting_ok else (0, 0, 255), 2)
                        cv2.imshow("Lighting Check", display_frame)
                        
                        if lighting_ok:
                            print("✅ Lighting is now acceptable!")
                            cv2.waitKey(2000)  # Show success message for 2 seconds
                            cv2.destroyWindow("Lighting Check")
                            break
                elif key == ord('q'):
                    cv2.destroyWindow("Lighting Check")
                    cap.release()
                    return None, False, "User cancelled due to lighting conditions"
        else:
            print("✅ Camera initialized successfully with good lighting")
            cv2.waitKey(2000)  # Show success message for 2 seconds
            cv2.destroyWindow("Lighting Check")
        
        return cap, lighting_ok, lighting_message
    
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
        
    #def run_detection(
     #   self, weights=None, source="test.mp4", view_img=False, save_img=False, exist_ok=False, track=True
    #):
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
        """ # Check authentication first if required
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
        self.system_monitor.stop_security_monitoring()"""

    def inference(self, weights=None, source="test.mp4", view_img=False, save_img=False, exist_ok=False, track=True):
        """
        Run object detection on a video using YOLOv8 and SAHI with lighting check.
        """
        if weights is None:
            weights = Config.DEFAULT_WEIGHTS
            
        # Start monitoring for screen recording tools and key presses
        self.system_monitor.start_security_monitoring()

        # Initialize camera with lighting check
        cap, lighting_ok, lighting_message = self.check_camera_and_lighting(source)
        if cap is None:
            print(f"❌ Failed to initialize camera: {lighting_message}")
            return
        
        # Log lighting status
        SecurityUtils.log_security_event("CAMERA_LIGHTING_CHECK", 
                                        f"Lighting status: {lighting_message}")

        frame_width, frame_height = int(cap.get(3)), int(cap.get(4))
        print(f"📹 Camera resolution: {frame_width}x{frame_height}")

        # Load model
        self.detector.load_model(weights)
        
        # Set running flag
        self.is_running = True
        print("🚀 Detection system started")
        
        # Counter for periodic lighting checks
        lighting_check_counter = 0
        lighting_check_interval = 300  # Check every 300 frames (about 10 seconds at 30fps)
        
        while cap.isOpened() and self.is_running:
            # Check if we should stop
            if not self.is_running:
                print("🛑 Detection system stop requested")
                break
                
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
            
            # Periodic lighting check during operation
            lighting_check_counter += 1
            if lighting_check_counter >= lighting_check_interval:
                current_lighting_ok, current_lighting_message = self.is_lighting_ok(frame)
                if not current_lighting_ok:
                    print(f"⚠️  Lighting warning during operation: {current_lighting_message}")
                    SecurityUtils.log_security_event("LIGHTING_WARNING", current_lighting_message)
                    
                    # Optionally show warning on frame
                    if view_img:
                        cv2.putText(frame, "LIGHTING WARNING", (10, frame.shape[0] - 20), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 165, 255), 2)
                
                lighting_check_counter = 0  # Reset counter
                    
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
            
            # Rest of the existing code for grace period checks...
            # [Previous code continues unchanged]
            
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
            time.sleep(0.1) 

        # Cleanup
        self.is_running = False
        cap.release()
        cv2.destroyAllWindows()
        self.system_monitor.stop_security_monitoring()
        print("🛑 Detection system stopped")

    def stop_detection(self):
        """Stop the detection system."""
        print("🛑 Stop detection requested")
        self.is_running = False

    def retry_camera_connection(self):
        """Attempt to reconnect to camera."""
        if self.system_monitor.check_camera_availability():
            self.alert_system.hide_camera_alert()
            SecurityUtils.log_security_event("CAMERA_RECONNECTED", "Camera successfully reconnected")
        else:
            SecurityUtils.log_security_event("CAMERA_RETRY_FAILED", "Camera connection retry failed")
            print("❌ Camera still unavailable. Please check camera connection.")
            # Flash the window to indicate retry failed
            if hasattr(self.alert_system, 'camera_alert_window') and self.alert_system.camera_alert_window:
                self.alert_system.camera_alert_window.configure(bg='red')
                self.alert_system.root.after(500, lambda: self.alert_system.camera_alert_window.configure(bg='orange'))

    def check_recording_alert_needed(self, detected_tools):
        """Check if we should show recording alert based on current state."""
        # Don't show if recording alert is already active
        if self.alert_system.recording_alert_active:
            return False
            
        # Don't show if we're in grace period
        if self.alert_system.is_recording_grace_period_active():
            return False
            
        # Check cooldown period
        current_time = time.time()
        if current_time - self.last_recording_detection_time < Config.RECORDING_ALERT_COOLDOWN:
            return False
        
        return len(detected_tools) > 0

    def parse_opt(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--weights", type=str, default=Config.DEFAULT_WEIGHTS, help="initial weights path")
        parser.add_argument("--source", type=str, default=0, help="video file path")
        parser.add_argument("--view-img", default="true", help="show results")
        parser.add_argument("--save-img", default="false", help="save results")
        parser.add_argument("--exist-ok", action="store_true", help="existing project/name ok, do not increment")
        return parser.parse_args()


# For backward compatibility - alias to the old name
SAHIInference = DetectorService


if __name__ == "__main__":
    detector_service = DetectorService()
    detector_service.run_detection(**vars(detector_service.parse_opt()))
