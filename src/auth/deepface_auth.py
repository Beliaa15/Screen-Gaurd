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
                    embedding TEXT NOT NULL,
                    face_image BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster searches
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON faces(username)')
            
            conn.commit()
            conn.close()
            print(f"DeepFace database initialized at: {self.db_path}")
            
        except Exception as e:
            print(f"Error initializing database: {e}")

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

    def register_face(self, username: str, first_name: str = "", last_name: str = "", 
                     email: str = "", role: str = "user", image_path: str = None) -> bool:
        """Register a face for the given user."""
        if not DEEPFACE_AVAILABLE:
            print("DeepFace not available")
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
            
            # Convert image to binary for storage
            face_image_binary = None
            if image is not None:
                # Convert to PIL Image and then to binary
                pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
                buffered = BytesIO()
                pil_image.save(buffered, format="PNG")
                face_image_binary = buffered.getvalue()
            
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
                        embedding = ?, face_image = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (first_name, last_name, email, role, json.dumps(embedding), 
                      face_image_binary, username))
                print(f"Updated face registration for {username}")
            else:
                # Insert new user
                cursor.execute('''
                    INSERT INTO faces (username, first_name, last_name, email, role, embedding, face_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username, first_name, last_name, email, role, json.dumps(embedding), face_image_binary))
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
        cap = cv2.VideoCapture(Config.DEFAULT_CAMERA_INDEX)
        if not cap.isOpened():
            print("Cannot access camera")
            return None
        
        print("Position your face in front of the camera and press SPACE to capture, ESC to cancel")
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Show preview with face detection rectangle
            try:
                # Try to detect face for preview
                faces = DeepFace.extract_faces(frame, detector_backend=self.detector_backend, 
                                             enforce_detection=False)
                if faces and len(faces) > 0:
                    # Draw rectangle around detected face area
                    h, w = frame.shape[:2]
                    cv2.rectangle(frame, (w//4, h//4), (3*w//4, 3*h//4), (0, 255, 0), 2)
                    cv2.putText(frame, "Face Detected - Press SPACE to capture", 
                              (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                else:
                    cv2.putText(frame, "No face detected", 
                              (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            except:
                # If face detection fails, just show the frame
                pass
            
            cv2.putText(frame, "SPACE: Capture, ESC: Cancel", 
                       (10, frame.shape[0] - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            
            cv2.imshow("Face Registration", frame)
            
            key = cv2.waitKey(1) & 0xFF
            if key == ord(' '):  # Space to capture
                cap.release()
                cv2.destroyAllWindows()
                return frame
            elif key == 27:  # ESC to cancel
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
                match_result = self.find_face_match(embedding)
                
                if match_result:
                    cap.release()
                    cv2.destroyAllWindows()
                    
                    SecurityUtils.log_security_event("DEEPFACE_AUTH_SUCCESS", 
                                                   f"Face authentication successful for: {match_result['username']}")
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

    def find_face_match(self, query_embedding: List[float]) -> Optional[Dict[str, any]]:
        """Find matching face in database using similarity search."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all face embeddings from database
            cursor.execute("SELECT username, first_name, last_name, email, role, embedding FROM faces")
            faces = cursor.fetchall()
            conn.close()
            
            if not faces:
                return None
            
            best_match = None
            best_score = float('inf')
            
            query_embedding = np.array(query_embedding)
            
            for username, first_name, last_name, email, role, embedding_str in faces:
                try:
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
                    
                    # Check if this is the best match so far
                    if (euclidean_distance <= self.euclidean_threshold and 
                        cosine_distance <= self.cosine_threshold and 
                        weighted_score < best_score):
                        
                        best_match = {
                            'username': username,
                            'first_name': first_name or '',
                            'last_name': last_name or '',
                            'email': email or '',
                            'role': role or 'user',
                            'euclidean_distance': euclidean_distance,
                            'cosine_similarity': cosine_similarity,
                            'weighted_score': weighted_score
                        }
                        best_score = weighted_score
                        
                except Exception as e:
                    print(f"Error processing face for {username}: {e}")
                    continue
            
            return best_match
            
        except Exception as e:
            print(f"Error finding face match: {e}")
            return None

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
                result.append({
                    'username': face[0],
                    'first_name': face[1] or '',
                    'last_name': face[2] or '',
                    'email': face[3] or '',
                    'role': face[4] or 'user',
                    'created_at': face[5],
                    'updated_at': face[6]
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
