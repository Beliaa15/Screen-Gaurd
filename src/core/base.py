"""
Base classes and interfaces for the physical security system.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class BaseDetector(ABC):
    """Abstract base class for all detection components."""
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the detector."""
        pass
    
    @abstractmethod
    def detect(self, frame: Any) -> Dict[str, Any]:
        """Perform detection on the given frame."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources."""
        pass


class BaseAuthenticator(ABC):
    """Abstract base class for authentication methods."""
    
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Authenticate using provided credentials.
        
        Returns:
            Tuple of (success, user_id/error_message)
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this authentication method is available."""
        pass


class BaseAlert(ABC):
    """Abstract base class for alert systems."""
    
    @abstractmethod
    def show_alert(self, message: str, alert_type: str = "info") -> None:
        """Show an alert to the user."""
        pass
    
    @abstractmethod
    def hide_alert(self) -> None:
        """Hide the current alert."""
        pass
    
    @abstractmethod
    def is_alert_active(self) -> bool:
        """Check if an alert is currently active."""
        pass


class BaseMonitor(ABC):
    """Abstract base class for system monitors."""
    
    @abstractmethod
    def start_monitoring(self) -> None:
        """Start the monitoring process."""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop the monitoring process."""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        pass


class SecurityEvent:
    """Represents a security event in the system."""
    
    def __init__(self, event_type: str, message: str, timestamp: datetime = None, 
                 severity: str = "INFO", source: str = None):
        self.event_type = event_type
        self.message = message
        self.timestamp = timestamp or datetime.now()
        self.severity = severity
        self.source = source
        self.metadata = {}
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the event."""
        self.metadata[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_type': self.event_type,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'source': self.source,
            'metadata': self.metadata
        }
    
    def __str__(self) -> str:
        return f"[{self.timestamp}] {self.severity}: {self.event_type} - {self.message}"


class SystemState:
    """Manages the overall system state."""
    
    def __init__(self):
        self.is_authenticated = False
        self.current_user = None
        self.session_start_time = None
        self.alerts_active = []
        self.monitoring_active = False
        self.detection_active = False
        
    def authenticate_user(self, user_id: str) -> None:
        """Mark user as authenticated."""
        self.is_authenticated = True
        self.current_user = user_id
        self.session_start_time = datetime.now()
    
    def logout_user(self) -> None:
        """Logout current user."""
        self.is_authenticated = False
        self.current_user = None
        self.session_start_time = None
    
    def add_active_alert(self, alert_id: str) -> None:
        """Add an active alert."""
        if alert_id not in self.alerts_active:
            self.alerts_active.append(alert_id)
    
    def remove_active_alert(self, alert_id: str) -> None:
        """Remove an active alert."""
        if alert_id in self.alerts_active:
            self.alerts_active.remove(alert_id)
    
    def get_session_duration(self) -> Optional[float]:
        """Get current session duration in seconds."""
        if self.session_start_time:
            return (datetime.now() - self.session_start_time).total_seconds()
        return None
