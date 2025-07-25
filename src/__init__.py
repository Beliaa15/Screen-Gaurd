"""
Physical Security System Package

A comprehensive security monitoring system using YOLOv8 and SAHI for real-time
object detection, with features for monitoring mobile phones, screen recording
tools, and system security enforcement.

Components:
- core: Configuration settings, constants, and base classes
- auth: Authentication and authorization modules
- detection: YOLO object detection and related components
- security: Security monitoring, alerts, and enforcement
- ui: User interface components and management
- utils: Utility functions and helpers
"""

__version__ = "1.0.0"
__author__ = "Security Team"

# Import main components for easy access
from .core.config import Config
from .detection.yolo_detector import YOLODetector
from .security.alert_system import AlertSystem
from .security.system_monitor import SystemMonitor
from .security.process_manager import ProcessManager
from .utils.security_utils import SecurityUtils
from .detection.detector_service import DetectorService

__all__ = [
    'Config',
    'YOLODetector', 
    'AlertSystem',
    'SystemMonitor',
    'ProcessManager',
    'SecurityUtils',
    'DetectorService'
]
