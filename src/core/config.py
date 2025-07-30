# Configuration settings for the security system
import os
from pathlib import Path

class Config:
    """Configuration class for the security monitoring system."""
    
    # Detection settings
    CONSECUTIVE_MAX_DETECTIONS = 3
    CONFIDENCE_THRESHOLD = 0.5
    DEFAULT_CAMERA_INDEX = 0
    
    # Timing and performance settings
    CPU_MEASUREMENT_INTERVAL = 1.0  # seconds - interval for accurate CPU measurement
    MONITORING_LOOP_INTERVAL = 2  # seconds - how often to check for recording tools
    MONITORING_ERROR_RETRY_INTERVAL = 5  # seconds - retry interval on monitoring errors
    
    # Alert settings
    RECORDING_ALERT_COOLDOWN = 30  # seconds
    RECORDING_GRACE_PERIOD = 30  # seconds - grace period after password entry to close recording apps
    MAX_PASSWORD_ATTEMPTS = 3
    
    # SAHI (Slicing Aided Hyper Inference) settings
    SLICE_HEIGHT = 512
    SLICE_WIDTH = 512
    OVERLAP_HEIGHT_RATIO = 0.2
    OVERLAP_WIDTH_RATIO = 0.2
    
    # Model settings
    DEFAULT_WEIGHTS = "yolov8m.pt"
    MODELS_DIR = "models"
    
    # Logging settings
    LOGS_DIR = "logs"
    LOG_DATE_FORMAT = "%Y-%m-%d"
    LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
    
    # Screen recording processes to monitor
    SCREEN_RECORDING_PROCESSES = [
        'snippingtool.exe', 'screensketcher.exe', 'obs64.exe', 'obs32.exe',
        'camtasia.exe', 'bandicam.exe', 'fraps.exe', 'xsplit.exe',
        'streamlabs obs.exe', 'nvidia share.exe'
    ]
    
    # Active recording processes (high priority)
    ACTIVE_RECORDING_PROCESSES = [
        'obs64.exe', 'obs32.exe', 'camtasia.exe', 'bandicam.exe', 
        'fraps.exe', 'xsplit.exe', 'streamlabs obs.exe'
    ]
    
    # NVIDIA recording processes
    NVIDIA_RECORDING_PROCESSES = ['nvidia share.exe', 'nvcontainer.exe']
    NVIDIA_SERVICES = ['NvContainerLocalSystem', 'NVDisplay.ContainerLocalSystem']
    
    # CPU usage thresholds
    RECORDING_CPU_THRESHOLD = 5  # percent
    NVIDIA_CPU_THRESHOLD = 10  # percent
    
    # Keyboard monitoring hotkeys
    PRINT_SCREEN_HOTKEYS = ['print screen', 'alt+print screen']
    SNIPPING_TOOL_HOTKEYS = ['windows+shift+s']
    
    # Detection keywords for command line analysis
    RECORDING_KEYWORDS = ['record', 'capture', 'stream', 'broadcast']
    
    # Alert messages
    NVIDIA_RECORDING_ACTIVE_MESSAGE = "NVIDIA Recording Active"
    PRINT_SCREEN_DETECTION_MESSAGE = "Print Screen Capture"
    SNIPPING_TOOL_DETECTION_MESSAGE = "Snipping Tool Hotkey"
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist."""
        Path(cls.MODELS_DIR).mkdir(exist_ok=True)
        Path(cls.LOGS_DIR).mkdir(exist_ok=True)

    # LDAP Configuration
    LDAP_SERVER = "ldap://192.168.1.5"  
    LDAP_BASE_DN = "security-local.com"    
    LDAP_DOMAIN = "security-local"  # Domain for NTLM authentication
    LDAP_ADMIN_GROUP = "SecurityAdmins"
    LDAP_OPERATOR_GROUP = "SecurityOperators"
    LDAP_USER_GROUP = "SecurityUsers"
    
    # NTLM Authentication Settings
    NTLM_DOMAIN = "security-local"  # Default domain for NTLM
    REQUIRE_DOMAIN_IN_USERNAME = False  # Require domain\username format

    # Authentication Configuration
    AUTHENTICATION_REQUIRED = True  # Set to False for development/testing without authentication
    AUTHENTICATION_METHODS = ["email_password", "fingerprint", "deepface"]
    SESSION_TIMEOUT = 8 * 60 * 60  # 8 hours in seconds
    MAX_LOGIN_ATTEMPTS = 3
    LOGIN_LOCKOUT_DURATION = 300  # 5 minutes in seconds
    
    # Face Recognition Settings
    FACE_RECOGNITION_TOLERANCE = 0.6
    FACE_ENCODING_MODEL = "large"  # or "small" for faster processing
    FACE_IMAGES_DIR = "face_data"
    
    # DeepFace Settings (Advanced Face Recognition)
    DEEPFACE_DETECTOR_BACKEND = "opencv"  # opencv, ssd, dlib, mtcnn, retinaface
    DEEPFACE_MODEL_NAME = "Facenet"  # VGG-Face, Facenet, Facenet512, OpenFace, DeepFace, DeepID, ArcFace, Dlib
    DEEPFACE_NORMALIZATION = "base"  # base, raw, Facenet, Facenet2018, VGGFace, VGGFace2, ArcFace
    DEEPFACE_CONFIDENCE_THRESHOLD = 0.85
    DEEPFACE_EUCLIDEAN_THRESHOLD = 10.0
    DEEPFACE_COSINE_THRESHOLD = 0.40
    
    # Fingerprint Settings
    FINGERPRINT_ENABLED = True
    FINGERPRINT_QUALITY_THRESHOLD = 50
    
    # Session Management
    SESSION_CHECK_INTERVAL = 60  # seconds
    IDLE_TIMEOUT = 30 * 60  # 30 minutes in seconds
