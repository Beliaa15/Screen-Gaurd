"""
YOLO object detection with SAHI integration for enhanced small object detection.
"""

import cv2
import torch
from pathlib import Path
from typing import Tuple, List, Any
from sahi import AutoDetectionModel
from sahi.predict import get_sliced_prediction
from ultralytics.utils.plotting import Annotator, colors
from config import Config

class YOLODetector:
    """YOLO object detector with SAHI (Slicing Aided Hyper Inference) integration."""
    
    def __init__(self):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.detection_model = None
        
    def load_model(self, weights: str = None) -> None:
        """Load a YOLOv8 model with specified weights for object detection using SAHI."""
        if weights is None:
            weights = Config.DEFAULT_WEIGHTS
            
        yolov8_model_path = f"{Config.MODELS_DIR}/{weights}"
        
        # Create models directory if it doesn't exist
        Config.ensure_directories()
        
        # Check if model file exists, if not use the one in root directory
        if not Path(yolov8_model_path).exists():
            if Path(weights).exists():
                yolov8_model_path = weights
            else:
                # Let ultralytics download the model automatically
                yolov8_model_path = weights
        
        self.detection_model = AutoDetectionModel.from_pretrained(
            model_type="yolov8", 
            model_path=yolov8_model_path, 
            confidence_threshold=Config.CONFIDENCE_THRESHOLD, 
            device=self.device
        )
        
        print(f"Model loaded: {yolov8_model_path} on device: {self.device}")
    
    def detect_objects(self, frame) -> Tuple[Any, List[Tuple], bool, bool]:
        """
        Detect objects in a frame using SAHI.
        
        Args:
            frame: Input frame for detection
            
        Returns:
            tuple: (annotated_frame, detection_data, has_person, has_mobile)
        """
        if self.detection_model is None:
            raise ValueError("Model not loaded. Call load_model() first.")
            
        annotator = Annotator(frame)  # Initialize annotator for plotting detection results
        
        # Perform sliced prediction for better small object detection
        results = get_sliced_prediction(
            frame,
            self.detection_model,
            slice_height=Config.SLICE_HEIGHT,
            slice_width=Config.SLICE_WIDTH,
            overlap_height_ratio=Config.OVERLAP_HEIGHT_RATIO,
            overlap_width_ratio=Config.OVERLAP_WIDTH_RATIO,
        )
        
        # Extract detection data
        detection_data = [
            (det.category.name, det.category.id, 
             (det.bbox.minx, det.bbox.miny, det.bbox.maxx, det.bbox.maxy), 
             det.score.value)
            for det in results.object_prediction_list
        ]
        
        # Check for specific objects
        has_person = False
        has_mobile = False
        
        # Annotate frame and check for target objects
        for det in detection_data:
            class_name, class_id, bbox, confidence = det
            annotator.box_label(bbox, label=f"Class: {class_name}, Conf: {confidence:.2f}", 
                               color=colors(int(class_id), True))
            
            if class_name == "person":
                has_person = True
            elif class_name == "cell phone":
                has_mobile = True
        
        return frame, detection_data, has_person, has_mobile
    
    def is_model_loaded(self) -> bool:
        """Check if model is loaded."""
        return self.detection_model is not None
