"""
Face Recognition REST API Service
Handles face verification requests from Windows Credential Provider
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import cv2
import numpy as np
import base64
import logging
import os
import json
from datetime import datetime
import uvicorn
from pathlib import Path
import sqlite3
import hashlib

# DeepFace for face recognition
from deepface import DeepFace
import tensorflow as tf

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Face Recognition Service", version="1.0.0")

# Configuration
FACE_DB_PATH = "face_database"
USER_DB_PATH = "users.db"
MIN_CONFIDENCE_THRESHOLD = 0.4  # Adjust based on your needs
FACE_RECOGNITION_MODEL = "ArcFace"  # or "Facenet", "VGG-Face", etc.

class FaceVerificationRequest(BaseModel):
    images: List[str]  # Base64 encoded images
    timestamp: Optional[int] = None

class FaceVerificationResponse(BaseModel):
    success: bool
    username: Optional[str] = None
    confidence: Optional[float] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

class UserRegistrationRequest(BaseModel):
    username: str
    images: List[str]  # Base64 encoded face images for enrollment

class UserRegistrationResponse(BaseModel):
    success: bool
    message: str
    user_id: Optional[str] = None

class FaceRecognitionService:
    def __init__(self):
        self.setup_database()
        self.setup_face_database()
        
    def setup_database(self):
        """Initialize SQLite database for user management."""
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                face_encoding_path TEXT NOT NULL,
                enrolled_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                success BOOLEAN NOT NULL,
                confidence FLOAT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                details TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("Database initialized successfully")
    
    def setup_face_database(self):
        """Setup face database directory structure."""
        os.makedirs(FACE_DB_PATH, exist_ok=True)
        logger.info(f"Face database directory: {FACE_DB_PATH}")
    
    def decode_base64_image(self, base64_string: str) -> np.ndarray:
        """Decode base64 image to numpy array."""
        try:
            # Remove data URL prefix if present
            if ',' in base64_string:
                base64_string = base64_string.split(',')[1]
            
            # Decode base64
            image_data = base64.b64decode(base64_string)
            
            # Convert to numpy array
            nparr = np.frombuffer(image_data, np.uint8)
            
            # Decode image
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if image is None:
                raise ValueError("Failed to decode image")
            
            return image
        except Exception as e:
            logger.error(f"Error decoding base64 image: {e}")
            raise
    
    def preprocess_image(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for face recognition."""
        try:
            # Convert BGR to RGB (OpenCV uses BGR, most models expect RGB)
            if len(image.shape) == 3 and image.shape[2] == 3:
                image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Resize if too large (for performance)
            height, width = image.shape[:2]
            if height > 1024 or width > 1024:
                scale = min(1024/height, 1024/width)
                new_height = int(height * scale)
                new_width = int(width * scale)
                image = cv2.resize(image, (new_width, new_height))
            
            return image
        except Exception as e:
            logger.error(f"Error preprocessing image: {e}")
            raise
    
    def get_user_face_path(self, username: str) -> str:
        """Get the path for user's face encoding."""
        return os.path.join(FACE_DB_PATH, f"{username}_face.jpg")
    
    def register_user(self, username: str, face_images: List[str]) -> UserRegistrationResponse:
        """Register a new user with face images."""
        try:
            logger.info(f"Registering user: {username}")
            
            # Check if user already exists
            conn = sqlite3.connect(USER_DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                return UserRegistrationResponse(
                    success=False,
                    message=f"User {username} already exists"
                )
            
            # Process face images
            processed_images = []
            for i, img_base64 in enumerate(face_images):
                try:
                    image = self.decode_base64_image(img_base64)
                    image = self.preprocess_image(image)
                    processed_images.append(image)
                except Exception as e:
                    logger.warning(f"Failed to process image {i} for user {username}: {e}")
            
            if not processed_images:
                conn.close()
                return UserRegistrationResponse(
                    success=False,
                    message="No valid face images provided"
                )
            
            # Use the first valid image as the reference
            reference_image = processed_images[0]
            
            # Save reference image
            face_path = self.get_user_face_path(username)
            cv2.imwrite(face_path, cv2.cvtColor(reference_image, cv2.COLOR_RGB2BGR))
            
            # Store in database
            cursor.execute("""
                INSERT INTO users (username, face_encoding_path)
                VALUES (?, ?)
            """, (username, face_path))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"User {username} registered successfully with ID: {user_id}")
            
            return UserRegistrationResponse(
                success=True,
                message=f"User {username} registered successfully",
                user_id=str(user_id)
            )
            
        except Exception as e:
            logger.error(f"Error registering user {username}: {e}")
            if 'conn' in locals():
                conn.close()
            return UserRegistrationResponse(
                success=False,
                message=f"Registration failed: {str(e)}"
            )
    
    def verify_face(self, face_images: List[str]) -> FaceVerificationResponse:
        """Verify face against registered users."""
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting face verification with {len(face_images)} images")
            
            # Process input images
            processed_images = []
            for i, img_base64 in enumerate(face_images):
                try:
                    image = self.decode_base64_image(img_base64)
                    image = self.preprocess_image(image)
                    processed_images.append(image)
                except Exception as e:
                    logger.warning(f"Failed to process image {i}: {e}")
            
            if not processed_images:
                return FaceVerificationResponse(
                    success=False,
                    error="No valid images provided for verification"
                )
            
            # Get all registered users
            conn = sqlite3.connect(USER_DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT username, face_encoding_path FROM users WHERE active = 1")
            users = cursor.fetchall()
            conn.close()
            
            if not users:
                return FaceVerificationResponse(
                    success=False,
                    error="No registered users found"
                )
            
            best_match = None
            best_confidence = 0.0
            
            # Try each input image against each registered user
            for username, face_path in users:
                if not os.path.exists(face_path):
                    logger.warning(f"Face image not found for user {username}: {face_path}")
                    continue
                
                try:
                    for input_image in processed_images:
                        # Save temporary image for DeepFace
                        temp_path = f"temp_verify_{username}.jpg"
                        cv2.imwrite(temp_path, cv2.cvtColor(input_image, cv2.COLOR_RGB2BGR))
                        
                        try:
                            # Use DeepFace for verification
                            result = DeepFace.verify(
                                img1_path=temp_path,
                                img2_path=face_path,
                                model_name=FACE_RECOGNITION_MODEL,
                                enforce_detection=False  # Allow verification even if face detection fails
                            )
                            
                            confidence = 1.0 - result['distance']  # Convert distance to confidence
                            verified = result['verified']
                            
                            logger.info(f"Verification result for {username}: verified={verified}, confidence={confidence:.3f}")
                            
                            if verified and confidence > best_confidence and confidence >= MIN_CONFIDENCE_THRESHOLD:
                                best_match = username
                                best_confidence = confidence
                                
                        except Exception as e:
                            logger.warning(f"DeepFace verification failed for {username}: {e}")
                        finally:
                            # Clean up temporary file
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                
                except Exception as e:
                    logger.error(f"Error verifying against user {username}: {e}")
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Log attempt
            self.log_login_attempt(best_match, best_match is not None, best_confidence)
            
            if best_match:
                # Update user's last login
                self.update_user_login(best_match)
                
                logger.info(f"Face verification successful: {best_match} (confidence: {best_confidence:.3f})")
                
                return FaceVerificationResponse(
                    success=True,
                    username=best_match,
                    confidence=best_confidence,
                    processing_time=processing_time
                )
            else:
                logger.info("Face verification failed: no matching user found")
                
                return FaceVerificationResponse(
                    success=False,
                    error="Face not recognized",
                    processing_time=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Error during face verification: {e}")
            
            return FaceVerificationResponse(
                success=False,
                error=f"Verification error: {str(e)}",
                processing_time=processing_time
            )
    
    def log_login_attempt(self, username: Optional[str], success: bool, confidence: float):
        """Log login attempt to database."""
        try:
            conn = sqlite3.connect(USER_DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO login_attempts (username, success, confidence, details)
                VALUES (?, ?, ?, ?)
            """, (username, success, confidence, f"Face recognition attempt"))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging login attempt: {e}")
    
    def update_user_login(self, username: str):
        """Update user's last login timestamp and count."""
        try:
            conn = sqlite3.connect(USER_DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1
                WHERE username = ?
            """, (username,))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error updating user login for {username}: {e}")

# Initialize service
face_service = FaceRecognitionService()

@app.post("/api/face/verify", response_model=FaceVerificationResponse)
async def verify_face(request: FaceVerificationRequest):
    """
    Verify face images against registered users.
    This is the main endpoint called by the Windows Credential Provider.
    """
    logger.info(f"Received face verification request with {len(request.images)} images")
    
    if not request.images:
        raise HTTPException(status_code=400, detail="No images provided")
    
    if len(request.images) > 5:  # Limit number of images
        raise HTTPException(status_code=400, detail="Too many images provided (max 5)")
    
    try:
        result = face_service.verify_face(request.images)
        return result
    except Exception as e:
        logger.error(f"Error in face verification endpoint: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/face/register", response_model=UserRegistrationResponse)
async def register_user(request: UserRegistrationRequest):
    """
    Register a new user with face images.
    This endpoint is used for enrollment.
    """
    logger.info(f"Received user registration request for: {request.username}")
    
    if not request.username or not request.username.strip():
        raise HTTPException(status_code=400, detail="Username is required")
    
    if not request.images:
        raise HTTPException(status_code=400, detail="No face images provided")
    
    if len(request.images) > 10:  # Limit number of images
        raise HTTPException(status_code=400, detail="Too many images provided (max 10)")
    
    try:
        result = face_service.register_user(request.username.strip(), request.images)
        return result
    except Exception as e:
        logger.error(f"Error in user registration endpoint: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Face Recognition API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "model": FACE_RECOGNITION_MODEL,
        "confidence_threshold": MIN_CONFIDENCE_THRESHOLD
    }

@app.get("/api/users")
async def list_users():
    """List all registered users (for admin purposes)."""
    try:
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, enrolled_date, last_login, login_count, active
            FROM users
            ORDER BY enrolled_date DESC
        """)
        
        users = []
        for row in cursor.fetchall():
            users.append({
                "username": row[0],
                "enrolled_date": row[1],
                "last_login": row[2],
                "login_count": row[3],
                "active": bool(row[4])
            })
        
        conn.close()
        return {"users": users, "count": len(users)}
        
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/login-attempts")
async def get_login_attempts(limit: int = 50):
    """Get recent login attempts (for admin purposes)."""
    try:
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, success, confidence, timestamp, details
            FROM login_attempts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        attempts = []
        for row in cursor.fetchall():
            attempts.append({
                "username": row[0],
                "success": bool(row[1]),
                "confidence": row[2],
                "timestamp": row[3],
                "details": row[4]
            })
        
        conn.close()
        return {"attempts": attempts, "count": len(attempts)}
        
    except Exception as e:
        logger.error(f"Error getting login attempts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    print("Starting Face Recognition Service...")
    print(f"Database path: {USER_DB_PATH}")
    print(f"Face database path: {FACE_DB_PATH}")
    print(f"Model: {FACE_RECOGNITION_MODEL}")
    print(f"Confidence threshold: {MIN_CONFIDENCE_THRESHOLD}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info",
        access_log=True
    )
