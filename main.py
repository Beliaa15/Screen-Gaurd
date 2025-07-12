"""
Main entry point for the security monitoring system.
"""

from detect import SAHIInference

if __name__ == "__main__":
    """Main entry point for the security system."""
    inference = SAHIInference()
    inference.inference(**vars(inference.parse_opt()))
