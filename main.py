"""
Main entry point for the security monitoring system with comprehensive GUI.
"""

import threading
import time
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.detection.detector_service import DetectorService
from src.core.config import Config
from src.utils.security_utils import SecurityUtils
from src.ui.gui_manager import SecurityGUI


def start_detection_system(gui):
    """Start the main detection system after GUI authentication."""
    # Wait for authentication to complete
    while not gui.is_ready_for_detection():
        time.sleep(0.5)
    
    try:
        print("✅ Authentication successful. Starting security monitoring...")
        SecurityUtils.log_security_event("DETECTION_SYSTEM_START", "Main detection system starting after GUI authentication")
        
        # Initialize and start the detector service
        detector_service = DetectorService()
        
        # Mark that GUI authentication was completed
        detector_service.set_gui_authenticated(True)
        
        # Start the main detection loop with camera source (0) instead of default video
        detector_service.run_detection(source=0, view_img=True)
        
    except Exception as e:
        print(f"❌ Detection system error: {e}")
        SecurityUtils.log_security_event("DETECTION_SYSTEM_ERROR", f"Detection system error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    SecurityUtils.log_security_event("SYSTEM_START", "Physical Security System starting with GUI")
    
    try:
        # Check if authentication is required
        if Config.AUTHENTICATION_REQUIRED:
            print("🔐 Starting Physical Security System with GUI Authentication...")
            
            # Create and start the GUI
            gui = SecurityGUI()
            
            # Start detection system in background thread (will wait for auth)
            detection_thread = threading.Thread(
                target=start_detection_system, 
                args=(gui,), 
                daemon=True
            )
            detection_thread.start()
            
            # Run the GUI (blocking call)
            gui.run()
            
        else:
            print("⚠️  Warning: Authentication disabled. Starting without GUI...")
            # Run without authentication (development mode)
            detector_service = DetectorService()
            detector_service.run_detection(source=0, view_img=True)
            
    except KeyboardInterrupt:
        print("\n🛑 System shutdown requested by user")
        SecurityUtils.log_security_event("SYSTEM_SHUTDOWN", "System shutdown by user interrupt")
    except Exception as e:
        print(f"❌ System error: {e}")
        SecurityUtils.log_security_event("SYSTEM_ERROR", f"System error: {e}")
        import traceback
        traceback.print_exc()
