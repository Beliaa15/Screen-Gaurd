"""
Test suite for the Physical Security System detection module.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from src.detection.yolo_detector import YOLODetector
from src.detection.detector_service import DetectorService
from src.core.config import Config


class TestYOLODetector:
    """Test cases for YOLODetector."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = YOLODetector()
    
    def test_initialization(self):
        """Test proper initialization of YOLODetector."""
        assert self.detector.device in ['cuda', 'cpu']
        assert self.detector.detection_model is None
        assert self.detector.initialized is False
    
    def test_is_model_loaded_false(self):
        """Test model loaded check when no model is loaded."""
        result = self.detector.is_model_loaded()
        assert result is False
    
    @patch('src.detection.yolo_detector.AutoDetectionModel')
    def test_load_model_success(self, mock_auto_model):
        """Test successful model loading."""
        mock_model = Mock()
        mock_auto_model.from_pretrained.return_value = mock_model
        
        self.detector.load_model('yolov8n.pt')
        
        assert self.detector.detection_model == mock_model
        mock_auto_model.from_pretrained.assert_called_once()
        assert self.detector.is_model_loaded() is True
    
    def test_initialize_success(self):
        """Test successful detector initialization."""
        with patch.object(self.detector, 'load_model') as mock_load:
            result = self.detector.initialize()
            
            assert result is True
            assert self.detector.initialized is True
            mock_load.assert_called_once()
    
    def test_initialize_failure(self):
        """Test detector initialization failure."""
        with patch.object(self.detector, 'load_model', side_effect=Exception("Model load failed")):
            result = self.detector.initialize()
            
            assert result is False
            assert self.detector.initialized is False
    
    @patch('src.detection.yolo_detector.get_sliced_prediction')
    @patch('src.detection.yolo_detector.Annotator')
    def test_detect_objects(self, mock_annotator, mock_get_prediction):
        """Test object detection."""
        # Setup mocks
        mock_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        
        # Mock detection results
        mock_detection = Mock()
        mock_detection.category.name = 'person'
        mock_detection.category.id = 0
        mock_detection.bbox.minx = 100
        mock_detection.bbox.miny = 100
        mock_detection.bbox.maxx = 200
        mock_detection.bbox.maxy = 200
        mock_detection.score.value = 0.8
        
        mock_result = Mock()
        mock_result.object_prediction_list = [mock_detection]
        mock_get_prediction.return_value = mock_result
        
        mock_annotator_instance = Mock()
        mock_annotator.return_value = mock_annotator_instance
        
        # Setup detector with mock model
        self.detector.detection_model = Mock()
        
        # Run detection
        annotated_frame, detection_data, has_person, has_mobile = self.detector.detect_objects(mock_frame)
        
        # Verify results
        assert len(detection_data) == 1
        assert has_person is True
        assert has_mobile is False
        assert detection_data[0][0] == 'person'  # class name
        mock_annotator_instance.box_label.assert_called_once()
    
    def test_detect_objects_no_model(self):
        """Test detection without loaded model."""
        mock_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        
        with pytest.raises(ValueError, match="Model not loaded"):
            self.detector.detect_objects(mock_frame)
    
    def test_cleanup(self):
        """Test detector cleanup."""
        # Set up detector with mock model
        self.detector.detection_model = Mock()
        self.detector.initialized = True
        
        self.detector.cleanup()
        
        assert self.detector.detection_model is None
        assert self.detector.initialized is False


class TestDetectorService:
    """Test cases for DetectorService."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.detector_service = DetectorService()
    
    def test_initialization(self):
        """Test proper initialization of DetectorService."""
        assert self.detector_service.consecutive_max == Config.CONSECUTIVE_MAX_DETECTIONS
        assert self.detector_service.consecutive_detections == 0
        assert self.detector_service.consecutive_misses == 0
        assert self.detector_service.gui_authenticated is False
        assert self.detector_service.detector is not None
        assert self.detector_service.alert_system is not None
        assert self.detector_service.system_monitor is not None
        assert self.detector_service.process_manager is not None
    
    def test_set_gui_authenticated(self):
        """Test setting GUI authentication status."""
        self.detector_service.set_gui_authenticated(True)
        assert self.detector_service.gui_authenticated is True
    
    @patch('src.detection.detector_service.SecurityUtils')
    def test_set_gui_authenticated_with_logging(self, mock_security_utils):
        """Test GUI authentication with logging."""
        self.detector_service.set_gui_authenticated(True)
        
        mock_security_utils.log_security_event.assert_called_once_with(
            "GUI_AUTH_COMPLETE", "GUI authentication completed successfully"
        )
    
    def test_parse_opt(self):
        """Test command line argument parsing."""
        args = self.detector_service.parse_opt()
        
        # Should have default values
        assert args.weights == Config.DEFAULT_WEIGHTS
        assert args.source == 0
        assert hasattr(args, 'view_img')
        assert hasattr(args, 'save_img')
    
    @patch('src.detection.detector_service.cv2.VideoCapture')
    def test_check_recording_alert_needed(self, mock_cv2):
        """Test recording alert necessity check."""
        detected_tools = ['obs64.exe']
        
        # Mock alert system states
        self.detector_service.alert_system.alert_active = False
        self.detector_service.alert_system.recording_alert_active = False
        
        with patch.object(self.detector_service.alert_system, 'is_recording_grace_period_active', return_value=False):
            with patch.object(self.detector_service.system_monitor, 'check_recording_alert_needed', return_value=True):
                result = self.detector_service.check_recording_alert_needed(detected_tools)
                assert result is True
    
    def test_check_recording_alert_needed_mobile_active(self):
        """Test recording alert when mobile alert is active."""
        detected_tools = ['obs64.exe']
        
        # Mobile alert is active
        self.detector_service.alert_system.alert_active = True
        
        result = self.detector_service.check_recording_alert_needed(detected_tools)
        assert result is False
    
    def test_check_recording_alert_needed_recording_active(self):
        """Test recording alert when recording alert is already active."""
        detected_tools = ['obs64.exe']
        
        # Recording alert is active
        self.detector_service.alert_system.alert_active = False
        self.detector_service.alert_system.recording_alert_active = True
        
        result = self.detector_service.check_recording_alert_needed(detected_tools)
        assert result is False
    
    def test_check_recording_alert_needed_grace_period(self):
        """Test recording alert during grace period."""
        detected_tools = ['obs64.exe']
        
        self.detector_service.alert_system.alert_active = False
        self.detector_service.alert_system.recording_alert_active = False
        
        with patch.object(self.detector_service.alert_system, 'is_recording_grace_period_active', return_value=True):
            result = self.detector_service.check_recording_alert_needed(detected_tools)
            assert result is False


@pytest.fixture
def mock_frame():
    """Fixture to provide a mock video frame."""
    return np.zeros((480, 640, 3), dtype=np.uint8)


@pytest.fixture
def mock_detection_results():
    """Fixture to provide mock detection results."""
    mock_person = Mock()
    mock_person.category.name = 'person'
    mock_person.category.id = 0
    mock_person.bbox.minx = 100
    mock_person.bbox.miny = 100
    mock_person.bbox.maxx = 200
    mock_person.bbox.maxy = 200
    mock_person.score.value = 0.9
    
    mock_mobile = Mock()
    mock_mobile.category.name = 'cell phone'
    mock_mobile.category.id = 67
    mock_mobile.bbox.minx = 300
    mock_mobile.bbox.miny = 150
    mock_mobile.bbox.maxx = 350
    mock_mobile.bbox.maxy = 200
    mock_mobile.score.value = 0.7
    
    mock_result = Mock()
    mock_result.object_prediction_list = [mock_person, mock_mobile]
    
    return mock_result


class TestDetectionIntegration:
    """Integration tests for detection system."""
    
    @patch('src.detection.yolo_detector.get_sliced_prediction')
    @patch('src.detection.yolo_detector.Annotator')
    def test_mobile_detection_flow(self, mock_annotator, mock_get_prediction, mock_frame, mock_detection_results):
        """Test complete mobile detection flow."""
        detector_service = DetectorService()
        
        # Setup mocks
        mock_get_prediction.return_value = mock_detection_results
        mock_annotator_instance = Mock()
        mock_annotator.return_value = mock_annotator_instance
        
        # Mock detector model
        detector_service.detector.detection_model = Mock()
        
        # Run detection
        annotated_frame, detection_data, has_person, has_mobile = detector_service.detector.detect_objects(mock_frame)
        
        # Verify detection results
        assert has_person is True
        assert has_mobile is True
        assert len(detection_data) == 2
        
        # Check detection data
        person_detection = next(d for d in detection_data if d[0] == 'person')
        mobile_detection = next(d for d in detection_data if d[0] == 'cell phone')
        
        assert person_detection[3] == 0.9  # confidence
        assert mobile_detection[3] == 0.7  # confidence
    
    def test_alert_system_integration(self):
        """Test integration between detector service and alert system."""
        detector_service = DetectorService()
        
        # Test that alert system is properly initialized
        assert detector_service.alert_system is not None
        
        # Test consecutive detections logic
        initial_count = detector_service.consecutive_detections
        
        # Simulate mobile detection
        # This would normally be called within the detection loop
        detector_service.consecutive_detections += 1
        detector_service.consecutive_misses = 0
        
        assert detector_service.consecutive_detections == initial_count + 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
