"""
DeepFace-based Authentication
Advanced face recognition using DeepFace library with database storage
"""

import os
import cv2
import json
import base64
import sqlite3
import numpy as np
import hashlib
import secrets
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from io import BytesIO
from PIL import Image
import threading
import time

try:
    from deepface import DeepFace
    DEEPFACE_AVAILABLE = True
except ImportError:
    DEEPFACE_AVAILABLE = False
    print("DeepFace not available. Install deepface library: pip install deepface")

from ..core.config import Config
from ..core.base import BaseAuthenticator
from ..utils.security_utils import SecurityUtils
from .ldap_auth import LDAPAuthenticator


class DeepFaceAuthenticator(BaseAuthenticator):
    """Advanced face authentication using DeepFace library."""
    
    def __init__(self):
        self.db_path = Path(Config.FACE_IMAGES_DIR) / "deepface_auth.db"
        self.face_data_dir = Path(Config.FACE_IMAGES_DIR)
        self.face_data_dir.mkdir(exist_ok=True)
        
        # DeepFace configuration
        self.detector_backend = "opencv"  # Can be: opencv, ssd, dlib, mtcnn, retinaface
        self.model_name = "Facenet"  # Can be: VGG-Face, Facenet, Facenet512, OpenFace, DeepFace, DeepID, ArcFace, Dlib
        self.normalization = "base"  # Can be: base, raw, Facenet, Facenet2018, VGGFace, VGGFace2, ArcFace
        
        # Recognition thresholds
        self.confidence_threshold = 0.85
        self.euclidean_threshold = 10.0
        self.cosine_threshold = 0.40
        
        self.init_database()

    def is_available(self) -> bool:
        """Check if DeepFace authentication is available."""
        return DEEPFACE_AVAILABLE

    def init_database(self):
        """Initialize SQLite database for face storage."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS faces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT,
                    role TEXT DEFAULT 'user',
                    password_hash TEXT,
                    salt TEXT,
                    embedding TEXT NOT NULL,
                    face_image BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster searches
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON faces(username)')
            
            # Check if we need to add password columns to existing table
            cursor.execute("PRAGMA table_info(faces)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'password_hash' not in columns:
                cursor.execute('ALTER TABLE faces ADD COLUMN password_hash TEXT')
                print("Added password_hash column to faces table")
            
            if 'salt' not in columns:
                cursor.execute('ALTER TABLE faces ADD COLUMN salt TEXT')
                print("Added salt column to faces table")
            
            conn.commit()
            conn.close()
            print(f"DeepFace database initialized at: {self.db_path}")
            
        except Exception as e:
            print(f"Error initializing database: {e}")

    def _encrypt_password(self, password: str) -> Tuple[str, str]:
        """Encrypt password using PBKDF2 with salt."""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                           bytes.fromhex(salt), 100000)
        return base64.b64encode(password_hash).decode('utf-8'), salt

    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against stored hash."""
        try:
            computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                               bytes.fromhex(salt), 100000)
            stored_hash = base64.b64decode(password_hash.encode('utf-8'))
            print(f"Computed hash: {computed_hash}, Stored hash: {stored_hash}")
            return secrets.compare_digest(computed_hash, stored_hash)
        except Exception as e:
            print(f"Error verifying password: {e}")
            return False

    def _authenticate_with_ldap(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """Authenticate user with LDAP using stored credentials."""
        try:
            ldap_auth = LDAPAuthenticator(Config())
            
            # Try direct authentication first
            success, result = ldap_auth.authenticate({
                'username': username,
                'password': password,
                'domain': Config.LDAP_DOMAIN if hasattr(Config, 'LDAP_DOMAIN') else ''
            })
            
            if success:
                return True, result
            
            # If direct authentication fails, try with domain prefix
            domain_username = f"{Config.LDAP_DOMAIN}\\{username}" if hasattr(Config, 'LDAP_DOMAIN') else username
            success, result = ldap_auth.authenticate({
                'username': domain_username,
                'password': password,
                'domain': Config.LDAP_DOMAIN if hasattr(Config, 'LDAP_DOMAIN') else ''
            })
            
            return success, result
            
        except Exception as e:
            print(f"LDAP authentication error: {e}")
            return False, f"LDAP authentication failed: {str(e)}"

    def preprocess_image(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for better face recognition."""
        try:
            # Convert to grayscale for histogram equalization
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply histogram equalization
            equalized = cv2.equalizeHist(gray)
            
            # Convert back to BGR
            processed = cv2.cvtColor(equalized, cv2.COLOR_GRAY2BGR)
            
            # Check if image is blurry and apply sharpening if needed
            laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
            if laplacian_var < 100.0:  # Image is blurry
                kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
                processed = cv2.filter2D(processed, -1, kernel)
            
            # Denoise
            processed = cv2.fastNlMeansDenoisingColored(processed, None, 10, 10, 7, 21)
            
            return processed
            
        except Exception as e:
            print(f"Error preprocessing image: {e}")
            return image

    def extract_face_embedding(self, image: np.ndarray) -> Tuple[Optional[List[float]], float]:
        """Extract face embedding using DeepFace."""
        if not DEEPFACE_AVAILABLE:
            return None, 0.0
        
        try:
            # Preprocess the image
            processed_image = self.preprocess_image(image)
            
            # Extract face representation
            face_data = DeepFace.represent(
                img_path=processed_image,
                model_name=self.model_name,
                enforce_detection=True,
                detector_backend=self.detector_backend,
                anti_spoofing=False,
                normalization=self.normalization,
                max_faces=1
            )
            
            if face_data and len(face_data) > 0:
                embedding = face_data[0]["embedding"]
                confidence = face_data[0].get("face_confidence", 0.0)
                
                # Convert numpy array to list if needed
                if isinstance(embedding, np.ndarray):
                    embedding = embedding.tolist()
                
                return embedding, confidence
            
            return None, 0.0
            
        except Exception as e:
            print(f"Error extracting face embedding: {e}")
            return None, 0.0

    def check_camera_availability(self) -> tuple[bool, str]:
        """Check if camera is available for use."""
        try:
            # Try different backends to test camera availability
            backends = [cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_ANY]
            
            for backend in backends:
                try:
                    cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX, backend)
                    if cap.isOpened():
                        ret, frame = cap.read()
                        cap.release()
                        if ret and frame is not None:
                            return True, f"Camera available (Backend: {backend})"
                    if cap:
                        cap.release()
                except Exception as e:
                    continue
            
            return False, "Camera not available - may be in use by another process"
        except Exception as e:
            return False, f"Camera check failed: {str(e)}"

    def check_face_duplicate_from_image(self, image_path: str = None, exclude_username: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """
        Check if an image contains a face that's already registered.
        
        Args:
            image_path: Path to image file, or None to capture from camera
            exclude_username: Username to exclude from duplicate check
            
        Returns:
            Tuple of (is_duplicate, message, duplicate_info)
        """
        if not DEEPFACE_AVAILABLE:
            return False, "DeepFace not available", None
        
        try:
            if image_path and os.path.exists(image_path):
                # Load from image file
                image = cv2.imread(image_path)
                if image is None:
                    return False, f"Could not load image from {image_path}", None
            else:
                # Capture from camera
                image = self.capture_face_from_camera()
                if image is None:
                    return False, "Face capture cancelled or failed", None
            
            # Extract face embedding
            embedding, confidence = self.extract_face_embedding(image)
            
            if embedding is None:
                return False, "No face found in the image", None
            
            if confidence < self.confidence_threshold:
                return False, f"Face confidence ({confidence:.2f}) too low for reliable duplicate checking", None
            
            # Check for duplicates
            duplicate_check = self.check_face_duplicate(embedding, exclude_username, query_image=image)
            
            if duplicate_check:
                duplicate_user = duplicate_check['duplicate_username']
                duplicate_name = f"{duplicate_check['duplicate_first_name']} {duplicate_check['duplicate_last_name']}".strip()
                similarity = duplicate_check['similarity_percentage']
                
                message = f"Face matches existing user '{duplicate_user}'"
                if duplicate_name:
                    message += f" ({duplicate_name})"
                message += f" with {similarity:.1f}% similarity"
                
                return True, message, duplicate_check
            else:
                return False, "No duplicate face found", None
                
        except Exception as e:
            return False, f"Error checking for duplicates: {str(e)}", None

    def register_face_with_duplicate_check(self, username: str, first_name: str = "", last_name: str = "", 
                                          email: str = "", role: str = "user", password: str = "", 
                                          image_path: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """
        Register a face with comprehensive duplicate checking and detailed error reporting.
        
        Args:
            username: Username for the new user
            first_name: First name of the user
            last_name: Last name of the user
            email: Email address of the user
            role: Role/group for the user
            password: Password for the user
            image_path: Path to face image, or None to capture from camera
            
        Returns:
            Tuple of (success, message, duplicate_info)
            - success: Boolean indicating if registration was successful
            - message: Success message or error description
            - duplicate_info: Dictionary with duplicate user details if found, None otherwise
        """
        if not DEEPFACE_AVAILABLE:
            return False, "DeepFace not available", None
        
        if not password:
            return False, "Password is required for face registration", None
        
        try:
            if image_path and os.path.exists(image_path):
                # Load from image file
                image = cv2.imread(image_path)
                if image is None:
                    return False, f"Could not load image from {image_path}", None
            else:
                # Capture from camera
                image = self.capture_face_from_camera()
                if image is None:
                    return False, "Face capture cancelled or failed", None
            
            # Extract face embedding
            embedding, confidence = self.extract_face_embedding(image)
            
            if embedding is None:
                return False, "No face found in the image", None
            
            if confidence < self.confidence_threshold:
                return False, f"Face confidence ({confidence:.2f}) below threshold ({self.confidence_threshold}). Please ensure good lighting and clear face visibility.", None
            
            # Check for face duplicates before registration
            duplicate_check = self.check_face_duplicate(embedding, exclude_username=username, query_image=image)
            if duplicate_check:
                duplicate_user = duplicate_check['duplicate_username']
                duplicate_name = f"{duplicate_check['duplicate_first_name']} {duplicate_check['duplicate_last_name']}".strip()
                similarity = duplicate_check['similarity_percentage']
                
                error_msg = f"Face already registered to user '{duplicate_user}'"
                if duplicate_name:
                    error_msg += f" ({duplicate_name})"
                error_msg += f" with {similarity:.1f}% similarity."
                
                SecurityUtils.log_security_event("DEEPFACE_DUPLICATE_DETECTED", 
                                               f"Duplicate face detected for {username}: already registered to {duplicate_user}")
                
                return False, error_msg, duplicate_check
            
            # Proceed with registration using the original method
            success = self.register_face(username, first_name, last_name, email, role, password, image_path)
            
            if success:
                return True, f"Face registered successfully for {username}", None
            else:
                return False, "Face registration failed due to technical error", None
                
        except Exception as e:
            error_msg = f"Error during face registration: {str(e)}"
            SecurityUtils.log_security_event("DEEPFACE_REGISTRATION_ERROR", 
                                           f"Face registration failed for {username}: {e}")
            return False, error_msg, None

    def register_face(self, username: str, first_name: str = "", last_name: str = "", 
                     email: str = "", role: str = "user", password: str = "", image_path: str = None) -> bool:
        """Register a face for the given user with encrypted password."""
        if not DEEPFACE_AVAILABLE:
            print("DeepFace not available")
            return False
        
        if not password:
            print("Password is required for face registration")
            return False
        
        try:
            if image_path and os.path.exists(image_path):
                # Load from image file
                image = cv2.imread(image_path)
                if image is None:
                    print(f"Could not load image from {image_path}")
                    return False
            else:
                # Capture from camera
                image = self.capture_face_from_camera()
                if image is None:
                    return False
            
            # Extract face embedding
            embedding, confidence = self.extract_face_embedding(image)
            
            if embedding is None:
                print("No face found in the image")
                return False
            
            if confidence < self.confidence_threshold:
                print(f"Face confidence ({confidence:.2f}) below threshold ({self.confidence_threshold})")
                return False
            
            # Check for face duplicates before registration
            duplicate_check = self.check_face_duplicate(embedding, exclude_username=username, query_image=image)
            if duplicate_check:
                duplicate_user = duplicate_check['duplicate_username']
                duplicate_name = f"{duplicate_check['duplicate_first_name']} {duplicate_check['duplicate_last_name']}".strip()
                similarity = duplicate_check['similarity_percentage']
                
                error_msg = f"Face already registered to user '{duplicate_user}'"
                if duplicate_name:
                    error_msg += f" ({duplicate_name})"
                error_msg += f" with {similarity:.1f}% similarity. Cannot register duplicate face."
                
                print(error_msg)
                SecurityUtils.log_security_event("DEEPFACE_DUPLICATE_DETECTED", 
                                               f"Duplicate face detected for {username}: already registered to {duplicate_user}")
                return False
            
            # Convert image to binary for storage
            face_image_binary = None
            if image is not None:
                # Convert to PIL Image and then to binary
                pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
                buffered = BytesIO()
                pil_image.save(buffered, format="PNG")
                face_image_binary = buffered.getvalue()
            
            # Encrypt password
            password_hash, salt = self._encrypt_password(password)
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT id FROM faces WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                # Update existing user
                cursor.execute('''
                    UPDATE faces 
                    SET first_name = ?, last_name = ?, email = ?, role = ?, 
                        password_hash = ?, salt = ?, embedding = ?, face_image = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (first_name, last_name, email, role, password_hash, salt, 
                      json.dumps(embedding), face_image_binary, username))
                print(f"Updated face registration for {username}")
            else:
                # Insert new user
                cursor.execute('''
                    INSERT INTO faces (username, first_name, last_name, email, role, password_hash, salt, embedding, face_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (username, first_name, last_name, email, role, password_hash, salt, 
                      json.dumps(embedding), face_image_binary))
                print(f"New face registered for {username}")
            
            conn.commit()
            conn.close()
            
            SecurityUtils.log_security_event("DEEPFACE_REGISTERED", 
                                           f"Face registered for user: {username} with confidence: {confidence:.2f}")
            return True
            
        except Exception as e:
            print(f"Error registering face: {e}")
            SecurityUtils.log_security_event("DEEPFACE_REGISTRATION_ERROR", 
                                           f"Face registration failed for {username}: {e}")
            return False

    def capture_face_from_camera(self) -> Optional[np.ndarray]:
        """Capture face from camera for registration."""
        cap = None
        max_retries = 3
        retry_delay = 1.0
        
        # Try multiple camera backends to handle conflicts
        backends = [cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_ANY]
        
        for backend in backends:
            for attempt in range(max_retries):
                try:
                    print(f"Attempting to access camera (Backend: {backend}, Attempt: {attempt + 1}/{max_retries})")
                    cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX, backend)
                    
                    # Set camera properties for better stability
                    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    cap.set(cv2.CAP_PROP_FPS, 15)
                    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                    
                    if cap.isOpened():
                        # Test if we can actually read a frame
                        ret, test_frame = cap.read()
                        if ret and test_frame is not None:
                            print("Camera access successful!")
                            break
                        else:
                            print("Camera opened but cannot read frames")
                            cap.release()
                            cap = None
                    else:
                        print("Cannot open camera")
                        if cap:
                            cap.release()
                        cap = None
                        
                except Exception as e:
                    print(f"Camera access error: {e}")
                    if cap:
                        cap.release()
                    cap = None
                
                if cap is None and attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
            
            if cap is not None:
                break
        
        if cap is None:
            print("ERROR: Cannot access camera after all attempts.")
            print("Possible causes:")
            print("- Camera is being used by another application (detection system)")
            print("- Camera driver issues")
            print("- Insufficient permissions")
            return None
        
        print("Position your face in front of the camera and press SPACE to capture, ESC to cancel")
        frame_count = 0
        last_face_detected = False
        
        while True:
            try:
                ret, frame = cap.read()
                if not ret or frame is None:
                    print("Warning: Frame read failed, retrying...")
                    continue
                
                frame_count += 1
                
                # Show preview with face detection rectangle
                try:
                    if frame_count % 5 == 0:  # Only check face every 5 frames for performance
                        # Try to detect face for preview
                        faces = DeepFace.extract_faces(frame, detector_backend=self.detector_backend, 
                                                     enforce_detection=False)
                        last_face_detected = faces and len(faces) > 0
                    
                    if last_face_detected:
                        # Draw rectangle around detected face area
                        h, w = frame.shape[:2]
                        cv2.rectangle(frame, (w//4, h//4), (3*w//4, 3*h//4), (0, 255, 0), 2)
                        cv2.putText(frame, "Face Detected - Press SPACE to capture", 
                                  (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                    else:
                        cv2.putText(frame, "Position your face in the frame", 
                                  (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
                except Exception as e:
                    # If face detection fails, just show the frame
                    cv2.putText(frame, "Camera active - Press SPACE to capture", 
                              (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
                
                cv2.putText(frame, "SPACE: Capture, ESC: Cancel", 
                           (10, frame.shape[0] - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
                
                cv2.imshow("Face Registration", frame)
                
                key = cv2.waitKey(1) & 0xFF
                if key == ord(' '):  # Space to capture
                    print("Face captured!")
                    captured_frame = frame.copy()
                    cap.release()
                    cv2.destroyAllWindows()
                    return captured_frame
                elif key == 27:  # ESC to cancel
                    print("Face capture cancelled")
                    break
                    
            except Exception as e:
                print(f"Error during camera capture: {e}")
                break
        
        cap.release()
        cv2.destroyAllWindows()
        return None

    def authenticate_face(self, timeout: int = 30) -> Optional[Dict[str, any]]:
        """Authenticate using face recognition."""
        if not DEEPFACE_AVAILABLE:
            return None
        
        cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX)
        if not cap.isOpened():
            return None
        
        print(f"Face authentication started. Timeout: {timeout} seconds")
        start_time = time.time()
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                print("Face authentication timed out")
                break
            
            try:
                # Extract face embedding from current frame
                embedding, confidence = self.extract_face_embedding(frame)
                
                if embedding is None or confidence < self.confidence_threshold:
                    # Show frame with status
                    status_text = "No face detected" if embedding is None else f"Low confidence: {confidence:.2f}"
                    cv2.putText(frame, status_text, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
                    cv2.putText(frame, f"Time left: {timeout - int(elapsed)}s", 
                              (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
                    cv2.imshow("Face Authentication", frame)
                    
                    if cv2.waitKey(1) & 0xFF == 27:  # ESC to cancel
                        break
                    continue
                
                # Search for matching face in database
                match_result = self.find_face_match(embedding, query_image=frame)
                
                if match_result:
                    cap.release()
                    cv2.destroyAllWindows()
                    
                    # Try LDAP authentication with stored credentials
                    username = match_result['username']
                    password_hash = match_result.get('password_hash')
                    salt = match_result.get('salt')
                    
                    if password_hash and salt:
                        # We need the original password to authenticate with LDAP
                        # Since we can't decrypt the hash, we'll use a different approach
                        # For now, let's try to authenticate with the username only
                        # In a real scenario, you might want to implement a separate password prompt
                        print(f"Face recognized as {username}, attempting LDAP authentication...")
                        
                        # Note: Since we store encrypted passwords, we can't retrieve the original
                        # In a production system, you might want to:
                        # 1. Prompt for password after face recognition
                        # 2. Use cached credentials if previously entered
                        # 3. Use certificate-based authentication
                        
                        # For now, we'll return the match and let the caller handle LDAP auth
                        SecurityUtils.log_security_event("DEEPFACE_AUTH_SUCCESS", 
                                                       f"Face authentication successful for: {username}")
                        return match_result
                    else:
                        print(f"No stored credentials for {username}")
                        SecurityUtils.log_security_event("DEEPFACE_AUTH_SUCCESS", 
                                                       f"Face authentication successful for: {username} (no stored credentials)")
                        return match_result
                
                # Show frame with authentication status
                cv2.putText(frame, f"Face detected (conf: {confidence:.2f})", 
                          (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                cv2.putText(frame, "Searching for match...", 
                          (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 0), 1)
                cv2.putText(frame, f"Time left: {timeout - int(elapsed)}s", 
                          (10, 90), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
                
            except Exception as e:
                print(f"Error during face authentication: {e}")
                cv2.putText(frame, f"Error: {str(e)[:50]}", 
                          (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 1)
            
            cv2.imshow("Face Authentication", frame)
            if cv2.waitKey(1) & 0xFF == 27:  # ESC to cancel
                break
        
        cap.release()
        cv2.destroyAllWindows()
        SecurityUtils.log_security_event("DEEPFACE_AUTH_FAILED", "Face authentication failed or cancelled")
        return None

    def authenticate_face_with_ldap(self, timeout: int = 30) -> Optional[Dict[str, any]]:
        """Authenticate using face recognition and then LDAP authentication."""
        # First, authenticate the face
        face_result = self.authenticate_face(timeout)
        
        if not face_result:
            return None
        
        username = face_result['username']
        password_hash = face_result.get('password_hash')
        salt = face_result.get('salt')
        
        if not password_hash or not salt:
            print(f"No stored credentials for {username}. Face authentication successful but cannot proceed with LDAP.")
            return face_result
        
        # Since we can't decrypt the password hash, we need to prompt for password
        # In a GUI environment, you would show a password dialog here
        print(f"Face recognized as {username}. Please enter password for LDAP authentication:")
        
        # For now, we'll return the face result and let the GUI handle password prompt
        # The GUI can then call authenticate_with_ldap directly
        face_result['requires_password'] = True
        return face_result

    def authenticate_face_with_external_camera(self, camera_cap, timeout: int = 30) -> Optional[Dict[str, any]]:
        """Authenticate using face recognition with an external camera handle."""
        if not DEEPFACE_AVAILABLE or not camera_cap:
            return None
        
        print(f"Face authentication started with external camera. Timeout: {timeout} seconds")
        start_time = time.time()
        
        frame_count = 0
        while True:
            ret, frame = camera_cap.read()
            if not ret:
                break
            
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                print("Face authentication timed out")
                break
            
            frame_count += 1
            
            # Only process every 5th frame for performance
            if frame_count % 5 != 0:
                time.sleep(0.1)
                continue
            
            try:
                # Extract face embedding from current frame
                embedding, confidence = self.extract_face_embedding(frame)
                
                if embedding is None or confidence < self.confidence_threshold:
                    continue
                
                # Search for matching face in database
                match_result = self.find_face_match(embedding, query_image=frame)
                
                if match_result:
                    # Face authentication successful
                    username = match_result['username']
                    password_hash = match_result.get('password_hash')
                    salt = match_result.get('salt')
                    
                    if password_hash and salt:
                        SecurityUtils.log_security_event("DEEPFACE_AUTH_SUCCESS", 
                                                       f"Face authentication successful for: {username}")
                        return match_result
                    else:
                        print(f"No stored credentials for {username}")
                        SecurityUtils.log_security_event("DEEPFACE_AUTH_SUCCESS", 
                                                       f"Face authentication successful for: {username} (no stored credentials)")
                        return match_result
                
                time.sleep(0.2)  # Brief pause between checks
                
            except Exception as e:
                print(f"Error during face authentication: {e}")
                continue
        
        SecurityUtils.log_security_event("DEEPFACE_AUTH_FAILED", "Face authentication failed or timed out")
        return None

    def authenticate_user_with_stored_password(self, username: str, entered_password: str) -> Optional[Dict[str, any]]:
        """Authenticate user by verifying stored password and then LDAP."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT password_hash, salt, first_name, last_name, email, role FROM faces WHERE username = ?", 
                         (username,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return None
            
            password_hash, salt, first_name, last_name, email, role = result
            
            # TODO: fix password save in database
            # Verify the entered password matches stored hash
            if not self._verify_password(entered_password, password_hash, salt):
                SecurityUtils.log_security_event("AUTH_FAILED", f"Password verification failed for {username}")
                return None

            # Now try LDAP authentication
            ldap_success, ldap_result = self._authenticate_with_ldap(username, entered_password)
            if ldap_success:
                user_data = {
                    'username': username,
                    'first_name': first_name or '',
                    'last_name': last_name or '',
                    'email': email or '',
                    'role': role or '',
                    'auth_method': 'face_and_ldap'
                }
                SecurityUtils.log_security_event("AUTH_SUCCESS", f"Face + LDAP authentication successful for {username}")
                return user_data
            else:
                error_msg = ldap_result if isinstance(ldap_result, str) else "LDAP authentication failed"
                SecurityUtils.log_security_event("LDAP_AUTH_FAILED", f"LDAP authentication failed for {username}: {error_msg}")
                return None
                
        except Exception as e:
            print(f"Error in authenticate_user_with_stored_password: {e}")
            SecurityUtils.log_security_event("AUTH_ERROR", f"Authentication error for {username}: {str(e)}")
            return None

    def check_face_duplicate(self, query_embedding: List[float], exclude_username: str = None, query_image: np.ndarray = None) -> Optional[Dict[str, any]]:
        """
        Check if a face embedding matches any existing registered face using DeepFace verify().
        
        Args:
            query_embedding: Face embedding to check for duplicates
            exclude_username: Username to exclude from duplicate check (for updates)
            query_image: Original face image for more accurate verification
            
        Returns:
            Dictionary with duplicate user info if found, None if no duplicate
        """
        if not DEEPFACE_AVAILABLE:
            return None
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all face data from database, excluding the specified user if updating
            if exclude_username:
                cursor.execute("SELECT username, first_name, last_name, embedding, face_image FROM faces WHERE username != ?", (exclude_username,))
            else:
                cursor.execute("SELECT username, first_name, last_name, embedding, face_image FROM faces")
            faces = cursor.fetchall()
            conn.close()
            
            if not faces:
                return None
            
            query_embedding = np.array(query_embedding)
            
            for username, first_name, last_name, embedding_str, face_image_binary in faces:
                try:
                    # Use DeepFace verify() for more accurate comparison
                    if query_image is not None and face_image_binary is not None:
                        # Convert stored image binary back to image for verification
                        stored_image = np.frombuffer(face_image_binary, np.uint8)
                        stored_image = cv2.imdecode(stored_image, cv2.IMREAD_COLOR)
                        
                        if stored_image is not None:
                            try:
                                # Use DeepFace verify method for accurate comparison
                                verification_result = DeepFace.verify(
                                    img1_path=query_image,
                                    img2_path=stored_image,
                                    model_name=self.model_name,
                                    detector_backend=self.detector_backend,
                                    distance_metric='cosine',  # Use cosine distance as it's most reliable
                                    enforce_detection=False,
                                    normalization=self.normalization
                                )
                                
                                # Check if faces are verified as the same person
                                if verification_result.get('verified', False):
                                    distance = verification_result.get('distance', 1.0)
                                    threshold = verification_result.get('threshold', 0.40)
                                    confidence = max(0, (1 - distance / threshold) * 100)
                                    
                                    return {
                                        'duplicate_username': username,
                                        'duplicate_first_name': first_name or '',
                                        'duplicate_last_name': last_name or '',
                                        'distance': distance,
                                        'threshold': threshold,
                                        'similarity_percentage': confidence,
                                        'verification_method': 'deepface_verify'
                                    }
                            except Exception as verify_error:
                                print(f"DeepFace verify failed for {username}, falling back to embedding comparison: {verify_error}")
                                # Fall back to embedding comparison if verify fails
                    
                    # Fallback: Use embedding comparison with stricter thresholds
                    stored_embedding = np.array(json.loads(embedding_str))
                    
                    # Calculate euclidean distance
                    euclidean_distance = np.linalg.norm(query_embedding - stored_embedding)
                    
                    # Calculate cosine similarity
                    cosine_similarity = np.dot(query_embedding, stored_embedding) / (
                        np.linalg.norm(query_embedding) * np.linalg.norm(stored_embedding)
                    )
                    cosine_distance = 1 - cosine_similarity
                    
                    # Use stricter thresholds for duplicate detection (more sensitive than authentication)
                    duplicate_euclidean_threshold = 0.6  # Stricter than authentication threshold
                    duplicate_cosine_threshold = 0.03     # Stricter than authentication threshold
                    
                    # Check if this is a duplicate using stricter thresholds
                    if (euclidean_distance <= duplicate_euclidean_threshold and 
                        cosine_distance <= duplicate_cosine_threshold):
                        
                        return {
                            'duplicate_username': username,
                            'duplicate_first_name': first_name or '',
                            'duplicate_last_name': last_name or '',
                            'euclidean_distance': euclidean_distance,
                            'cosine_similarity': cosine_similarity,
                            'similarity_percentage': (1 - cosine_distance) * 100,
                            'verification_method': 'embedding_fallback'
                        }
                        
                except Exception as e:
                    print(f"Error processing face for {username} during duplicate check: {e}")
                    continue
            
            return None
            
        except Exception as e:
            print(f"Error checking face duplicates: {e}")
            return None

    def find_face_match(self, query_embedding: List[float], query_image: np.ndarray = None) -> Optional[Dict[str, any]]:
        """Find matching face in database using DeepFace verify() method for accurate authentication."""
        if not DEEPFACE_AVAILABLE:
            return None
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all face data from database including password data and face images
            cursor.execute("SELECT username, first_name, last_name, email, role, embedding, password_hash, salt, face_image FROM faces")
            faces = cursor.fetchall()
            conn.close()
            
            if not faces:
                return None
            
            best_match = None
            best_score = float('inf')
            
            query_embedding = np.array(query_embedding)
            
            for username, first_name, last_name, email, role, embedding_str, password_hash, salt, face_image_binary in faces:
                try:
                    # Primary method: Use DeepFace verify() for more accurate comparison
                    if query_image is not None and face_image_binary is not None:
                        # Convert stored image binary back to image for verification
                        stored_image = np.frombuffer(face_image_binary, np.uint8)
                        stored_image = cv2.imdecode(stored_image, cv2.IMREAD_COLOR)
                        
                        if stored_image is not None:
                            try:
                                # Use DeepFace verify method for accurate comparison
                                verification_result = DeepFace.verify(
                                    img1_path=query_image,
                                    img2_path=stored_image,
                                    model_name=self.model_name,
                                    detector_backend=self.detector_backend,
                                    distance_metric='cosine',  # Use cosine distance as it's most reliable
                                    enforce_detection=False,
                                    normalization=self.normalization
                                )
                                
                                # Check if faces are verified as the same person
                                if verification_result.get('verified', False):
                                    distance = verification_result.get('distance', 1.0)
                                    threshold = verification_result.get('threshold', 0.40)
                                    confidence_score = max(0, (1 - distance / threshold) * 100)
                                    
                                    # Use distance as score (lower is better)
                                    if distance < best_score:
                                        best_match = {
                                            'username': username,
                                            'first_name': first_name or '',
                                            'last_name': last_name or '',
                                            'email': email or '',
                                            'role': role or 'user',
                                            'password_hash': password_hash,
                                            'salt': salt,
                                            'distance': distance,
                                            'threshold': threshold,
                                            'confidence_score': confidence_score,
                                            'verification_method': 'deepface_verify'
                                        }
                                        best_score = distance
                                    continue  # Skip embedding comparison if verify succeeded
                            except Exception as verify_error:
                                print(f"DeepFace verify failed for {username}, falling back to embedding comparison: {verify_error}")
                                # Fall back to embedding comparison if verify fails
                    
                    # Fallback method: Use embedding comparison for compatibility
                    stored_embedding = np.array(json.loads(embedding_str))
                    
                    # Calculate euclidean distance
                    euclidean_distance = np.linalg.norm(query_embedding - stored_embedding)
                    
                    # Calculate cosine similarity
                    cosine_similarity = np.dot(query_embedding, stored_embedding) / (
                        np.linalg.norm(query_embedding) * np.linalg.norm(stored_embedding)
                    )
                    cosine_distance = 1 - cosine_similarity
                    
                    # Combined weighted score (you can adjust weights)
                    weighted_score = (0.7 * euclidean_distance) + (0.3 * cosine_distance)
                    
                    # Check if this is the best match so far using authentication thresholds
                    if (euclidean_distance <= self.euclidean_threshold and 
                        cosine_distance <= self.cosine_threshold and 
                        weighted_score < best_score):
                        
                        best_match = {
                            'username': username,
                            'first_name': first_name or '',
                            'last_name': last_name or '',
                            'email': email or '',
                            'role': role or 'user',
                            'password_hash': password_hash,
                            'salt': salt,
                            'euclidean_distance': euclidean_distance,
                            'cosine_similarity': cosine_similarity,
                            'weighted_score': weighted_score,
                            'verification_method': 'embedding_fallback'
                        }
                        best_score = weighted_score
                        
                except Exception as e:
                    print(f"Error processing face for {username}: {e}")
                    continue
            
            return best_match
            
        except Exception as e:
            print(f"Error finding face match: {e}")
            return None

    def find_all_face_duplicates(self) -> List[Dict[str, any]]:
        """
        Find all potential face duplicates in the database.
        
        Returns:
            List of dictionaries containing duplicate pairs information
        """
        if not DEEPFACE_AVAILABLE:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, first_name, last_name, embedding, face_image FROM faces ORDER BY username")
            faces = cursor.fetchall()
            conn.close()
            
            if len(faces) < 2:
                return []
            
            duplicates = []
            
            # Compare each face with every other face
            for i, (username1, first_name1, last_name1, embedding_str1, face_image1) in enumerate(faces):
                for j, (username2, first_name2, last_name2, embedding_str2, face_image2) in enumerate(faces[i+1:], i+1):
                    try:
                        # Try DeepFace verify first if both face images are available
                        is_duplicate = False
                        similarity_percentage = 0
                        verification_method = 'embedding_fallback'
                        
                        if face_image1 is not None and face_image2 is not None:
                            try:
                                # Convert stored image binaries back to images
                                image1 = np.frombuffer(face_image1, np.uint8)
                                image1 = cv2.imdecode(image1, cv2.IMREAD_COLOR)
                                
                                image2 = np.frombuffer(face_image2, np.uint8)
                                image2 = cv2.imdecode(image2, cv2.IMREAD_COLOR)
                                
                                if image1 is not None and image2 is not None:
                                    # Use DeepFace verify method
                                    verification_result = DeepFace.verify(
                                        img1_path=image1,
                                        img2_path=image2,
                                        model_name=self.model_name,
                                        detector_backend=self.detector_backend,
                                        distance_metric='cosine',
                                        enforce_detection=False,
                                        normalization=self.normalization
                                    )
                                    
                                    # Use stricter threshold for duplicate detection
                                    distance = verification_result.get('distance', 1.0)
                                    threshold = verification_result.get('threshold', 0.40)
                                    duplicate_threshold = threshold * 0.7  # More strict for duplicate detection
                                    
                                    if distance <= duplicate_threshold:
                                        is_duplicate = True
                                        similarity_percentage = max(0, (1 - distance / threshold) * 100)
                                        verification_method = 'deepface_verify'
                                    
                            except Exception as verify_error:
                                print(f"DeepFace verify failed for {username1} vs {username2}, falling back to embedding: {verify_error}")
                        
                        # Fallback to embedding comparison if DeepFace verify failed or unavailable
                        if not is_duplicate:
                            embedding1 = np.array(json.loads(embedding_str1))
                            embedding2 = np.array(json.loads(embedding_str2))
                            
                            # Calculate similarity metrics
                            euclidean_distance = np.linalg.norm(embedding1 - embedding2)
                            cosine_similarity = np.dot(embedding1, embedding2) / (
                                np.linalg.norm(embedding1) * np.linalg.norm(embedding2)
                            )
                            cosine_distance = 1 - cosine_similarity
                            
                            # Use stricter thresholds for duplicate detection
                            duplicate_euclidean_threshold = 0.6  # Stricter than authentication
                            duplicate_cosine_threshold = 0.03    # Stricter than authentication
                            
                            # Check if these faces are duplicates
                            if (euclidean_distance <= duplicate_euclidean_threshold and 
                                cosine_distance <= duplicate_cosine_threshold):
                                is_duplicate = True
                                similarity_percentage = (1 - cosine_distance) * 100
                        
                        # Add to duplicates list if found
                        if is_duplicate:
                            duplicates.append({
                                'user1': {
                                    'username': username1,
                                    'name': f"{first_name1 or ''} {last_name1 or ''}".strip()
                                },
                                'user2': {
                                    'username': username2,
                                    'name': f"{first_name2 or ''} {last_name2 or ''}".strip()
                                },
                                'similarity_percentage': similarity_percentage,
                                'verification_method': verification_method
                            })
                            
                    except Exception as e:
                        print(f"Error comparing faces {username1} and {username2}: {e}")
                        continue
            
            return duplicates
            
        except Exception as e:
            print(f"Error finding all face duplicates: {e}")
            return []

    def list_registered_faces(self) -> List[Dict[str, any]]:
        """List all registered faces."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, first_name, last_name, email, role, created_at, updated_at 
                FROM faces ORDER BY username
            ''')
            faces = cursor.fetchall()
            conn.close()
            
            result = []
            for face in faces:
                # Format created_at to match LDAP format (date only)
                created_date = ''
                if face[5]:
                    try:
                        created_date = face[5][:10]  # Get date part only
                    except:
                        created_date = face[5]
                
                # Build display name
                first_name = face[1] or ''
                last_name = face[2] or ''
                display_name = f"{first_name} {last_name}".strip()
                
                result.append({
                    'username': face[0],
                    'first_name': first_name,
                    'last_name': last_name,
                    'display_name': display_name or face[0],  # Fallback to username
                    'email': face[3] or '',
                    'role': face[4] or 'user',
                    'created_date': created_date,
                    'source': 'DeepFace'
                })
            
            return result
            
        except Exception as e:
            print(f"Error listing faces: {e}")
            return []

    def delete_face(self, username: str) -> bool:
        """Delete a user's face registration."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM faces WHERE username = ?", (username,))
            deleted_rows = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if deleted_rows > 0:
                SecurityUtils.log_security_event("DEEPFACE_DELETED", f"Face deleted for user: {username}")
                print(f"Face registration deleted for {username}")
                return True
            else:
                print(f"No face registration found for {username}")
                return False
                
        except Exception as e:
            print(f"Error deleting face: {e}")
            return False

    def authenticate(self, credentials: Dict[str, any]) -> Tuple[bool, Optional[str]]:
        """
        Authenticate using DeepFace.
        
        Args:
            credentials: Dictionary with authentication parameters
            
        Returns:
            Tuple of (success, username/error_message)
        """
        timeout = credentials.get('timeout', 30)
        
        result = self.authenticate_face(timeout)
        if result:
            return True, result['username']
        else:
            return False, "Face authentication failed"

    def get_user_info(self, username: str) -> Optional[Dict[str, any]]:
        """Get user information by username."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, first_name, last_name, email, role, created_at, updated_at 
                FROM faces WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return {
                    'username': user[0],
                    'first_name': user[1] or '',
                    'last_name': user[2] or '',
                    'email': user[3] or '',
                    'role': user[4] or 'user',
                    'created_at': user[5],
                    'updated_at': user[6]
                }
            
            return None
            
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None

    def create_ldap_user_with_face(self, username: str, first_name: str = "", last_name: str = "", 
                                  email: str = "", role: str = "user", image_path: str = None,
                                  temp_password: str = None) -> Tuple[bool, str]:
        """
        Create a new LDAP user and register their face simultaneously.
        
        Args:
            username: Username for the new user
            first_name: First name of the user
            last_name: Last name of the user
            email: Email address of the user
            role: Role/group for the user (admin, operator, user)
            image_path: Path to face image, or None to capture from camera
            temp_password: Temporary password, or None to generate one
            
        Returns:
            Tuple of (success, message/temporary_password)
        """
        try:
            # Initialize LDAP authenticator
            ldap_auth = LDAPAuthenticator(Config())
            
            # Check if LDAP is available
            if not ldap_auth.is_available():
                return False, "LDAP server is not available"
            
            # Generate temporary password if not provided
            if not temp_password:
                temp_password = ldap_auth.generate_temporary_password()
            
            # Create LDAP user first
            ldap_success, ldap_message = ldap_auth.create_user(
                username=username,
                password=temp_password,
                first_name=first_name,
                last_name=last_name,
                email=email,
                role=role
            )
            
            if not ldap_success:
                return False, f"Failed to create LDAP user: {ldap_message}"
            
            # Register face with the same password using duplicate checking
            face_success, face_message, duplicate_info = self.register_face_with_duplicate_check(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                role=role,
                password=temp_password,
                image_path=image_path
            )
            
            if not face_success:
                # If face registration fails, try to clean up LDAP user
                ldap_auth.delete_user(username)
                
                if duplicate_info:
                    # Provide detailed duplicate information
                    duplicate_user = duplicate_info['duplicate_username']
                    duplicate_name = f"{duplicate_info['duplicate_first_name']} {duplicate_info['duplicate_last_name']}".strip()
                    similarity = duplicate_info['similarity_percentage']
                    
                    detailed_error = f"Face registration failed: {face_message}\n"
                    detailed_error += f"This face is already registered to user '{duplicate_user}'"
                    if duplicate_name:
                        detailed_error += f" ({duplicate_name})"
                    detailed_error += f" with {similarity:.1f}% similarity.\n"
                    detailed_error += "LDAP user creation rolled back."
                    
                    return False, detailed_error
                else:
                    return False, f"Failed to register face: {face_message}. LDAP user creation rolled back."
            
            SecurityUtils.log_security_event("USER_CREATED_WITH_FACE", 
                                           f"Created LDAP user with face registration: {username}, role: {role}")
            
            return True, f"User '{username}' created successfully. Temporary password: {temp_password}"
            
        except Exception as e:
            SecurityUtils.log_security_event("USER_CREATION_ERROR", 
                                           f"Error creating user with face: {username}, error: {str(e)}")
            return False, f"Error creating user: {str(e)}"

    def update_ldap_user_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """
        Update both LDAP password and face registration password.
        
        Args:
            username: Username to update
            new_password: New password
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get current user info
            user_info = self.get_user_info(username)
            if not user_info:
                return False, "User not found in face registration database"
            
            # Update face registration with new password
            face_success = self.register_face(
                username=username,
                first_name=user_info.get('first_name', ''),
                last_name=user_info.get('last_name', ''),
                email=user_info.get('email', ''),
                role=user_info.get('role', 'user'),
                password=new_password
            )
            
            if not face_success:
                return False, "Failed to update face registration password"
            
            SecurityUtils.log_security_event("PASSWORD_UPDATED", 
                                           f"Updated password for user: {username}")
            
            return True, f"Password updated successfully for user '{username}'"
            
        except Exception as e:
            return False, f"Error updating password: {str(e)}"

    def delete_user(self, username: str) -> Tuple[bool, str]:
        """
        Delete a user from both DeepFace database and optionally LDAP.
        
        Args:
            username: Username to delete
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Check if user exists in face database
            user_info = self.get_user_info(username)
            if not user_info:
                return False, f"User '{username}' not found in face registration database"
            
            # Delete from face database
            face_deleted = self.delete_face(username)
            
            if not face_deleted:
                return False, f"Failed to delete face registration for user '{username}'"
            
            # Try to delete from LDAP as well (optional)
            try:
                ldap_auth = LDAPAuthenticator(Config())
                if ldap_auth.is_available():
                    ldap_success, ldap_message = ldap_auth.delete_user(username)
                    if ldap_success:
                        SecurityUtils.log_security_event("USER_DELETED_COMPLETE", 
                                                       f"Deleted user from both face database and LDAP: {username}")
                        return True, f"User '{username}' deleted successfully from both face database and LDAP"
                    else:
                        SecurityUtils.log_security_event("USER_DELETED_PARTIAL", 
                                                       f"Deleted user from face database only: {username}. LDAP deletion failed: {ldap_message}")
                        return True, f"User '{username}' deleted from face database. LDAP deletion failed: {ldap_message}"
                else:
                    SecurityUtils.log_security_event("USER_DELETED_FACE_ONLY", 
                                                   f"Deleted user from face database only (LDAP not available): {username}")
                    return True, f"User '{username}' deleted from face database (LDAP not available)"
            except Exception as ldap_error:
                SecurityUtils.log_security_event("USER_DELETED_FACE_ONLY", 
                                               f"Deleted user from face database only (LDAP error): {username}")
                return True, f"User '{username}' deleted from face database. LDAP deletion failed: {str(ldap_error)}"
            
        except Exception as e:
            SecurityUtils.log_security_event("USER_DELETION_ERROR", 
                                           f"Error deleting user: {username}, error: {str(e)}")
            return False, f"Error deleting user: {str(e)}"