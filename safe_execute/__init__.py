"""
Safe Execute Decorator Package

A robust decorator for safe function execution with comprehensive error handling,
logging, timing, and optional finalization callbacks.
"""

from .core import safe_execute
from .exceptions import (
    set_default_exceptions,
    get_default_exceptions,
    COMMON_EXCEPTIONS
)
from .config import config
from .security import secure_execute, SecurityContext, ThreatDetector, SecurityResponse

__version__ = "1.0.0"
__author__ = "Your Name"

__all__ = [
    'safe_execute',
    'secure_execute',  # New security decorator
    'set_default_exceptions',
    'get_default_exceptions', 
    'COMMON_EXCEPTIONS',
    'config',
    'SecurityContext',
    'ThreatDetector',
    'SecurityResponse'
]