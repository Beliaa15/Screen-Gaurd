"""
Detection module initialization.
"""

from .yolo_detector import YOLODetector
from .detector_service import DetectorService, SAHIInference

__all__ = [
    'YOLODetector',
    'DetectorService',
    'SAHIInference'  # For backward compatibility
]
