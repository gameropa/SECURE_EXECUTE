"""
Security context management for tracking security state.
"""

import time
from typing import List, Dict, Any
from dataclasses import dataclass, field

@dataclass
class SecurityEvent:
    """Individual security event record."""
    timestamp: float
    threat_type: str
    severity: str
    description: str
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

class SecurityContext:
    """
    Security context for tracking threat levels and security events.
    """
    
    def __init__(self):
        self.threat_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
        self.blocked_attempts: int = 0
        self.sanitized_inputs: List[str] = []
        self.security_events: List[SecurityEvent] = []
        self.rate_limit_violations: int = 0
        self.auto_heal_successes: int = 0
        self.created_at: float = time.time()
    
    def add_security_event(self, threat_type: str, severity: str, description: str):
        """Add a security event to the context."""
        event = SecurityEvent(
            timestamp=time.time(),
            threat_type=threat_type,
            severity=severity,
            description=description
        )
        self.security_events.append(event)
        
        # Update threat level if needed
        severity_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        current_level = severity_levels.get(self.threat_level, 0)
        new_level = severity_levels.get(severity, 0)
        
        if new_level > current_level:
            self.threat_level = severity
    
    def get_recent_events(self, minutes: int = 10) -> List[SecurityEvent]:
        """Get security events from the last N minutes."""
        cutoff_time = time.time() - (minutes * 60)
        return [
            event for event in self.security_events 
            if event.timestamp >= cutoff_time
        ]
    
    def is_high_risk(self) -> bool:
        """Check if current context represents high risk."""
        return (
            self.threat_level in ["HIGH", "CRITICAL"] or
            self.blocked_attempts > 5 or
            len(self.get_recent_events(5)) > 10
        )
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of security context."""
        return {
            "threat_level": self.threat_level,
            "blocked_attempts": self.blocked_attempts,
            "sanitized_inputs_count": len(self.sanitized_inputs),
            "total_events": len(self.security_events),
            "recent_events": len(self.get_recent_events()),
            "rate_limit_violations": self.rate_limit_violations,
            "auto_heal_successes": self.auto_heal_successes,
            "session_duration": time.time() - self.created_at,
            "is_high_risk": self.is_high_risk()
        }
