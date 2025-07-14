# Configuration settings for the security system
import os
from pathlib import Path

class Config:
    """Configuration class for the security monitoring system."""
    
    # Detection settings
    CONSECUTIVE_MAX_DETECTIONS = 3
    CONFIDENCE_THRESHOLD = 0.5
    
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
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist."""
        Path(cls.MODELS_DIR).mkdir(exist_ok=True)
        Path(cls.LOGS_DIR).mkdir(exist_ok=True)
