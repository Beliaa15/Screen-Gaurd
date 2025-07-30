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


if __name__ == "__main__":
    SecurityUtils.log_security_event("SYSTEM_START", "Physical Security System starting with GUI")
    
    try:
        # Check if authentication is required
        if Config.AUTHENTICATION_REQUIRED:
            print("🔐 Starting Physical Security System with GUI Authentication...")
            
            # Create detector service instance
            detector_service = DetectorService()
            detector_service.set_gui_authenticated(True)
            
            # Create GUI with detector service reference
            gui = SecurityGUI(detector_service=detector_service)

            # Run the GUI (blocking call)
            gui.run()
            
        else:
            print("⚠️  Warning: Authentication disabled. Starting without GUI...")
            # Run without authentication (development mode)
            detector_service = DetectorService()
            detector_service.inference(**vars(detector_service.parse_opt()))
            
    except KeyboardInterrupt:
        print("\n🛑 System shutdown requested by user")
        SecurityUtils.log_security_event("SYSTEM_SHUTDOWN", "System shutdown by user interrupt")
    except Exception as e:
        print(f"❌ System error: {e}")
        SecurityUtils.log_security_event("SYSTEM_ERROR", f"System error: {e}")
        import traceback
        traceback.print_exc()
