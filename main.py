"""
Main entry point for the security monitoring system with comprehensive GUI.
"""

import threading
import time
from detect import SAHIInference
from config import Config
from security_utils import SecurityUtils
from gui_manager import SecurityGUI

def start_detection_system(gui):
    """Start the main detection system after GUI authentication."""
    # Wait for authentication to complete
    while not gui.is_ready_for_detection():
        time.sleep(0.5)
    
    try:
        print("✅ Authentication successful. Starting security monitoring...")
        SecurityUtils.log_security_event("DETECTION_SYSTEM_START", "Main detection system starting after GUI authentication")
        
        # Initialize and start the inference system
        inference = SAHIInference()
        
        # Mark that GUI authentication was completed
        inference.set_gui_authenticated(True)
        
        # Pass session manager if available
        if gui.auth_manager and hasattr(inference.security_overlay, 'auth_manager'):
            inference.security_overlay.auth_manager.session_manager = gui.auth_manager.session_manager
        
        # Start the main inference loop
        inference.inference(**vars(inference.parse_opt()))
        
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
            inference = SAHIInference()
            inference.inference(**vars(inference.parse_opt()))
            
    except KeyboardInterrupt:
        print("\n🛑 System shutdown requested by user")
        SecurityUtils.log_security_event("SYSTEM_SHUTDOWN", "System shutdown by user interrupt")
    except Exception as e:
        print(f"❌ System error: {e}")
        SecurityUtils.log_security_event("SYSTEM_ERROR", f"System error: {e}")
        import traceback
        traceback.print_exc()
