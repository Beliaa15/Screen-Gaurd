"""
Biometric Authentication - Face Recognition and Fingerprint Authentication
"""

import os
import cv2
import json
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple

# Import authentication libraries
try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False
    print("Face recognition not available. Install face-recognition library.")

try:
    import win32security
    import win32net
    WINDOWS_AUTH_AVAILABLE = True
except ImportError:
    WINDOWS_AUTH_AVAILABLE = False
    print("Windows authentication not available. Install pywin32 library.")

from ..core.config import Config
from ..core.base import BaseAuthenticator
from ..utils.security_utils import SecurityUtils


class BiometricAuthenticator(BaseAuthenticator):
    """Handles biometric authentication (face and fingerprint)."""
    
    def __init__(self):
        self.face_encodings_db = {}
        self.face_data_dir = Path(Config.FACE_IMAGES_DIR)
        self.face_data_dir.mkdir(exist_ok=True)
        self.load_face_encodings()

    def is_lighting_ok(self, frame, low_thresh=50, high_thresh=200):
        """Check if lighting conditions are acceptable for face recognition"""
        # Convert to grayscale for better brightness calculation
        if len(frame.shape) == 3:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        else:
            gray_frame = frame
        
        avg_brightness = np.mean(gray_frame)
        
        print(f"🔍 Face Auth - Lighting check: brightness = {avg_brightness:.2f}")
        
        if avg_brightness < low_thresh:
            return False, f"Too dark for face recognition - please increase lighting (current: {avg_brightness:.1f})"
        elif avg_brightness > high_thresh:
            return False, f"Too bright for face recognition - please reduce lighting (current: {avg_brightness:.1f})"
        else:
            return True, f"Lighting OK for face recognition (brightness: {avg_brightness:.1f})"
        
    def check_camera_lighting(self, cap, purpose="face recognition"):
        """Check lighting conditions and guide user to adjust if needed"""
        print(f"💡 Checking lighting conditions for {purpose}...")
        
        # Capture test frame
        ret, test_frame = cap.read()
        if not ret or test_frame is None:
            print("❌ Could not capture frame for lighting check")
            return False, "Frame capture failed"
        
        # Check lighting
        lighting_ok, lighting_message = self.is_lighting_ok(test_frame)
        print(f"💡 {lighting_message}")
        
        # Show lighting feedback window
        display_frame = test_frame.copy()
        
        # Add brightness info to frame
        gray_frame = cv2.cvtColor(test_frame, cv2.COLOR_BGR2GRAY)
        brightness = np.mean(gray_frame)
        
        # Add text overlay
        cv2.putText(display_frame, f"Brightness: {brightness:.1f}", (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
        cv2.putText(display_frame, lighting_message.split('(')[0], (10, 70), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0) if lighting_ok else (0, 0, 255), 2)
        
        if not lighting_ok:
            cv2.putText(display_frame, "Adjust lighting then press 'r' to recheck", (10, 110), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
            cv2.putText(display_frame, "Press 'c' to continue anyway, 'q' to quit", (10, 140), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 0), 2)
        else:
            cv2.putText(display_frame, "Good lighting! Continuing in 3 seconds...", (10, 110), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            cv2.putText(display_frame, "Press any key to continue immediately", (10, 140), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        
        cv2.imshow("Lighting Check - Face Recognition", display_frame)
        
        if lighting_ok:
            # Good lighting - wait 3 seconds or until key press
            start_time = cv2.getTickCount()
            while True:
                key = cv2.waitKey(100) & 0xFF
                elapsed = (cv2.getTickCount() - start_time) / cv2.getTickFrequency()
                
                if key != 255 or elapsed > 3.0:  # Any key pressed or 3 seconds elapsed
                    cv2.destroyWindow("Lighting Check - Face Recognition")
                    return True, lighting_message
        else:
            # Poor lighting - wait for user input
            while True:
                key = cv2.waitKey(1) & 0xFF
                
                if key == ord('c'):  # Continue anyway
                    cv2.destroyWindow("Lighting Check - Face Recognition")
                    print("⚠️ Continuing with poor lighting conditions")
                    SecurityUtils.log_security_event("FACE_AUTH_POOR_LIGHTING", f"Continuing with poor lighting: {lighting_message}")
                    return True, f"Continuing with poor lighting: {lighting_message}"
                    
                elif key == ord('r'):  # Recheck lighting
                    ret, test_frame = cap.read()
                    if ret:
                        lighting_ok, lighting_message = self.is_lighting_ok(test_frame)
                        print(f"💡 Lighting recheck: {lighting_message}")
                        
                        # Update display
                        display_frame = test_frame.copy()
                        gray_frame = cv2.cvtColor(test_frame, cv2.COLOR_BGR2GRAY)
                        brightness = np.mean(gray_frame)
                        
                        cv2.putText(display_frame, f"Brightness: {brightness:.1f}", (10, 30), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
                        cv2.putText(display_frame, lighting_message.split('(')[0], (10, 70), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0) if lighting_ok else (0, 0, 255), 2)
                        
                        if lighting_ok:
                            cv2.putText(display_frame, "Excellent! Good lighting detected!", (10, 110), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
                            cv2.imshow("Lighting Check - Face Recognition", display_frame)
                            cv2.waitKey(2000)  # Show success for 2 seconds
                            cv2.destroyWindow("Lighting Check - Face Recognition")
                            return True, lighting_message
                        else:
                            cv2.putText(display_frame, "Still poor lighting. Keep adjusting...", (10, 110), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
                            cv2.putText(display_frame, "Press 'r' to recheck, 'c' to continue, 'q' to quit", (10, 140), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 0), 2)
                            cv2.imshow("Lighting Check - Face Recognition", display_frame)
                    
                elif key == ord('q'):  # Quit
                    cv2.destroyWindow("Lighting Check - Face Recognition")
                    return False, "User cancelled due to lighting conditions"
        
        return True, lighting_message   
    



    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return FACE_RECOGNITION_AVAILABLE or WINDOWS_AUTH_AVAILABLE
        
    def load_face_encodings(self):
        """Load face encodings from file."""
        encoding_file = self.face_data_dir / "face_encodings.pkl"
        if encoding_file.exists():
            try:
                with open(encoding_file, 'rb') as f:
                    self.face_encodings_db = pickle.load(f)
                print(f"Loaded {len(self.face_encodings_db)} face encodings")
            except Exception as e:
                print(f"Error loading face encodings: {e}")
                self.face_encodings_db = {}
    
    def save_face_encodings(self):
        """Save face encodings to file."""
        encoding_file = self.face_data_dir / "face_encodings.pkl"
        try:
            with open(encoding_file, 'wb') as f:
                pickle.dump(self.face_encodings_db, f)
            print("Face encodings saved successfully")
        except Exception as e:
            print(f"Error saving face encodings: {e}")
    
    def register_face(self, username: str, image_path: str = None) -> bool:
        """Register a face for the given username."""
        if not FACE_RECOGNITION_AVAILABLE:
            print("Face recognition not available")
            return False
            
        try:
            if image_path and os.path.exists(image_path):
                # Load from image file
                image = face_recognition.load_image_file(image_path)
            else:
                # Capture from camera
                image = self.capture_face_from_camera()
                if image is None:
                    return False
            
            # Find face encodings
            face_encodings = face_recognition.face_encodings(image)
            
            if not face_encodings:
                print("No face found in the image")
                return False
            
            if len(face_encodings) > 1:
                print("Multiple faces found. Please use an image with only one face.")
                return False
            
            # Store the encoding
            self.face_encodings_db[username] = face_encodings[0]
            self.save_face_encodings()
            
            SecurityUtils.log_security_event("FACE_REGISTERED", f"Face registered for user: {username}")
            print(f"Face registered successfully for {username}")
            return True
            
        except Exception as e:
            print(f"Error registering face: {e}")
            SecurityUtils.log_security_event("FACE_REGISTRATION_ERROR", f"Face registration failed for {username}: {e}")
            return False
    
    def capture_face_from_camera(self) -> Optional[np.ndarray]:
        """Capture face from camera for registration with lighting check."""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Cannot access camera")
            return None
        
        # Check lighting conditions first
        lighting_ok, lighting_message = self.check_camera_lighting(cap, "face registration")
        if not lighting_ok:
            cap.release()
            return None
        
        print("Position your face in front of the camera and press SPACE to capture, ESC to cancel")
        SecurityUtils.log_security_event("FACE_REGISTRATION_START", f"Face registration started with lighting: {lighting_message}")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Add real-time lighting feedback
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            brightness = np.mean(gray_frame)
            lighting_status = "Good" if 50 <= brightness <= 200 else "Poor"
            color = (0, 255, 0) if lighting_status == "Good" else (0, 0, 255)
            
            # Add overlay info
            cv2.putText(frame, f"Lighting: {lighting_status} ({brightness:.1f})", (10, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
            cv2.putText(frame, "SPACE: Capture | ESC: Cancel", (10, frame.shape[0] - 20), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            
            # Show preview
            cv2.imshow("Face Registration - Check lighting and press SPACE", frame)
            
            key = cv2.waitKey(1) & 0xFF
            if key == ord(' '):  # Space to capture
                # Final lighting check before capture
                final_lighting_ok, final_message = self.is_lighting_ok(frame)
                if not final_lighting_ok:
                    print(f"⚠️ Warning: {final_message}")
                    print("Captured anyway, but face recognition accuracy may be reduced.")
                    SecurityUtils.log_security_event("FACE_REGISTRATION_POOR_LIGHTING", f"Face captured with poor lighting: {final_message}")
                
                # Convert BGR to RGB for face_recognition
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                cap.release()
                cv2.destroyAllWindows()
                return rgb_frame
            elif key == 27:  # ESC to cancel
                break
        
        cap.release()
        cv2.destroyAllWindows()
        return None
    
    def authenticate_face(self, timeout: int = 30) -> Optional[str]:
        """Authenticate using face recognition with lighting check."""
        if not FACE_RECOGNITION_AVAILABLE or not self.face_encodings_db:
            return None
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        
        # Check lighting conditions first
        lighting_ok, lighting_message = self.check_camera_lighting(cap, "face authentication")
        if not lighting_ok:
            cap.release()
            return None
        
        print(f"Face authentication started. Timeout: {timeout} seconds")
        print(f"Lighting status: {lighting_message}")
        SecurityUtils.log_security_event("FACE_AUTH_START", f"Face authentication started with lighting: {lighting_message}")
        
        start_time = cv2.getTickCount()
        last_lighting_check = start_time
        lighting_check_interval = 5.0  # Check lighting every 5 seconds during authentication
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Check timeout
            current_time = cv2.getTickCount()
            elapsed = (current_time - start_time) / cv2.getTickFrequency()
            if elapsed > timeout:
                print("Face authentication timed out")
                break
            
            # Periodic lighting check during authentication
            if (current_time - last_lighting_check) / cv2.getTickFrequency() > lighting_check_interval:
                current_lighting_ok, current_message = self.is_lighting_ok(frame)
                if not current_lighting_ok:
                    print(f"⚠️ Lighting warning during authentication: {current_message}")
                    SecurityUtils.log_security_event("FACE_AUTH_LIGHTING_WARNING", current_message)
                last_lighting_check = current_time
            
            # Convert BGR to RGB
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Find faces in frame
            face_locations = face_recognition.face_locations(rgb_frame)
            
            # Add real-time feedback to frame
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            brightness = np.mean(gray_frame)
            lighting_status = "Good" if 50 <= brightness <= 200 else "Poor"
            color = (0, 255, 0) if lighting_status == "Good" else (0, 0, 255)
            
            cv2.putText(frame, f"Lighting: {lighting_status} ({brightness:.1f})", (10, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
            cv2.putText(frame, f"Timeout: {int(timeout - elapsed)}s", (10, 60), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            cv2.putText(frame, f"Faces detected: {len(face_locations)}", (10, 90), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            
            if not face_locations:
                cv2.putText(frame, "No face detected - please position yourself", (10, 120), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)
                cv2.imshow("Face Authentication", frame)
                if cv2.waitKey(1) & 0xFF == 27:  # ESC to cancel
                    break
                continue
            
            # Get face encodings
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
            
            # Check against known faces
            for face_encoding in face_encodings:
                for username, known_encoding in self.face_encodings_db.items():
                    matches = face_recognition.compare_faces([known_encoding], face_encoding, 
                                                           tolerance=Config.FACE_RECOGNITION_TOLERANCE)
                    if matches[0]:
                        cap.release()
                        cv2.destroyAllWindows()
                        SecurityUtils.log_security_event("FACE_AUTH_SUCCESS", f"Face authentication successful for: {username}")
                        return username
            
            cv2.putText(frame, "Face not recognized - keep trying", (10, 120), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 165, 255), 1)
            
            # Show frame
            cv2.imshow("Face Authentication", frame)
            if cv2.waitKey(1) & 0xFF == 27:  # ESC to cancel
                break
        
        cap.release()
        cv2.destroyAllWindows()
        SecurityUtils.log_security_event("FACE_AUTH_FAILED", "Face authentication failed or cancelled")
        return None
    
    def authenticate_fingerprint(self) -> Optional[str]:
        """Authenticate using Windows Hello fingerprint."""
        if not WINDOWS_AUTH_AVAILABLE:
            return None
        
        try:
            # This is a simplified mock implementation
            # In a real scenario, you would integrate with Windows Hello API
            print("Please use your fingerprint on the Windows Hello sensor...")
            
            # Mock implementation - in reality, this would call Windows Hello APIs
            import time
            import random
            time.sleep(2)  # Simulate scanning time
            
            # For demo purposes, randomly succeed with registered users
            registered_users = ["admin", "user", "operator"]
            if random.random() > 0.3:  # 70% success rate for demo
                username = random.choice(registered_users)
                SecurityUtils.log_security_event("FINGERPRINT_AUTH_SUCCESS", f"Fingerprint authentication successful for: {username}")
                return username
            else:
                SecurityUtils.log_security_event("FINGERPRINT_AUTH_FAILED", "Fingerprint authentication failed")
                return None
                
        except Exception as e:
            print(f"Fingerprint authentication error: {e}")
            SecurityUtils.log_security_event("FINGERPRINT_AUTH_ERROR", f"Fingerprint authentication error: {e}")
            return None
    
    def authenticate(self, credentials: Dict[str, any]) -> Tuple[bool, Optional[str]]:
        """
        Authenticate using biometric methods.
        
        Args:
            credentials: Dictionary with 'method' key ('face' or 'fingerprint')
            
        Returns:
            Tuple of (success, username/error_message)
        """
        method = credentials.get('method', 'face')
        
        if method == 'face':
            username = self.authenticate_face(credentials.get('timeout', 30))
            if username:
                return True, username
            else:
                return False, "Face authentication failed"
        
        elif method == 'fingerprint':
            username = self.authenticate_fingerprint()
            if username:
                return True, username
            else:
                return False, "Fingerprint authentication failed"
        
        else:
            return False, f"Unknown biometric method: {method}"
