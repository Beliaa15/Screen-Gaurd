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
        """Capture face from camera for registration."""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Cannot access camera")
            return None
        
        print("Position your face in front of the camera and press SPACE to capture, ESC to cancel")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Show preview
            cv2.imshow("Face Registration - Press SPACE to capture, ESC to cancel", frame)
            
            key = cv2.waitKey(1) & 0xFF
            if key == ord(' '):  # Space to capture
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
        """Authenticate using face recognition."""
        if not FACE_RECOGNITION_AVAILABLE or not self.face_encodings_db:
            return None
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        
        print(f"Face authentication started. Timeout: {timeout} seconds")
        start_time = cv2.getTickCount()
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Check timeout
            elapsed = (cv2.getTickCount() - start_time) / cv2.getTickFrequency()
            if elapsed > timeout:
                print("Face authentication timed out")
                break
            
            # Convert BGR to RGB
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Find faces in frame
            face_locations = face_recognition.face_locations(rgb_frame)
            if not face_locations:
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
