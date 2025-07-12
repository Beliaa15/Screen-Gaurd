"""
Physical Security System Package

A comprehensive security monitoring system using YOLOv8 and SAHI for real-time
object detection, with features for monitoring mobile phones, screen recording
tools, and system security enforcement.

Components:
- config: Configuration settings and constants
- yolo_detector: YOLO object detection with SAHI integration
- alert_system: GUI alert windows and notifications
- system_monitor: Process and security monitoring
- process_manager: Application process management
- security_utils: Security utilities and logging
- detect: Main detection class orchestrating all components
"""

__version__ = "1.0.0"
__author__ = "Security Team"

# Import main components for easy access
from .config import Config
from .yolo_detector import YOLODetector
from .alert_system import AlertSystem
from .system_monitor import SystemMonitor
from .process_manager import ProcessManager
from .security_utils import SecurityUtils
from .detect import SAHIInference

__all__ = [
    'Config',
    'YOLODetector', 
    'AlertSystem',
    'SystemMonitor',
    'ProcessManager',
    'SecurityUtils',
    'SAHIInference'
]
