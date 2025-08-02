"""
Core security decorator implementation.
"""

import logging
import time
from functools import wraps
from typing import List, Callable, Any, Dict, Optional

from .threats import ThreatDetector
from .responses import SecurityResponse
from .context import SecurityContext

# Global security context (can be overridden per function)
_global_security_context = SecurityContext()
_threat_detector = ThreatDetector()
_security_response = SecurityResponse()

def secure_execute(
    threats: List[str] = None,
    auto_sanitize: bool = True,
    auto_heal: bool = False,
    rate_limit: int = None,
    security_level: str = "MEDIUM",
    threat_detector: ThreatDetector = None,
    security_response: SecurityResponse = None,
    security_context: SecurityContext = None,
    custom_responses: Dict[str, Callable] = None,
    learning_mode: bool = False
):
    """
    Security decorator for active threat detection and response.
    
    Args:
        threats: List of threat types to detect (default: all)
        auto_sanitize: Automatically sanitize detected threats
        auto_heal: Attempt automatic healing on errors
        rate_limit: Maximum calls per minute (default: no limit)
        security_level: Security level (LOW, MEDIUM, HIGH, CRITICAL)
        threat_detector: Custom threat detector instance
        security_response: Custom security response instance
        security_context: Custom security context instance
        custom_responses: Custom threat response handlers
        learning_mode: Enable learning mode for pattern detection
        
    Returns:
        Decorated function with active security protection
        
    Example:
        @safe_execute()           # Stability layer (outer)
        @secure_execute()         # Security layer (inner)
        def api_endpoint(request):
            return process_request(request)
    """
    
    # Use provided instances or defaults
    detector = threat_detector or _threat_detector
    responder = security_response or _security_response
    context = security_context or _global_security_context
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Rate limiting check
            if rate_limit and not responder.check_rate_limit(func.__name__, rate_limit):
                context.rate_limit_violations += 1
                logging.warning(f"Rate limit exceeded for function '{func.__name__}'")
                raise SecurityError(f"Rate limit exceeded: {rate_limit} calls/minute")
            
            # Pre-execution threat detection
            all_threats = []
            for arg in args:
                threats_found = detector.detect_threats(arg, context.get_security_summary())
                all_threats.extend(threats_found)
            
            for key, value in kwargs.items():
                threats_found = detector.detect_threats(value, context.get_security_summary())
                all_threats.extend(threats_found)
            
            # Process detected threats
            sanitized_args = list(args)
            sanitized_kwargs = dict(kwargs)
            threat_blocked = False
            
            for threat_type, severity, description in all_threats:
                # Filter by requested threat types
                if threats and threat_type not in threats:
                    continue
                
                # Handle threat with custom or default response
                if custom_responses and threat_type in custom_responses:
                    # Use custom response handler
                    try:
                        custom_handler = custom_responses[threat_type]
                        sanitized_data = custom_handler(args, kwargs)
                        if sanitized_data:
                            sanitized_args, sanitized_kwargs = sanitized_data
                    except Exception as e:
                        logging.error(f"Custom response handler failed: {e}")
                        raise SecurityError(f"Custom security handler failed for {threat_type}")
                else:
                    # Use default response handler
                    should_continue, sanitized_data, action = responder.handle_threat(
                        threat_type, severity, (args, kwargs), context
                    )
                    
                    if not should_continue:
                        threat_blocked = True
                        raise SecurityError(f"Security threat blocked: {threat_type} ({severity})")
                    
                    if auto_sanitize and action in ["SANITIZED", "LOGGED"]:
                        # Apply sanitization to individual arguments
                        for i, arg in enumerate(args):
                            if isinstance(arg, str):
                                if threat_type == "SQL_INJECTION":
                                    sanitized_args[i] = responder._sanitize_sql(arg)
                                elif threat_type == "XSS":
                                    sanitized_args[i] = responder._sanitize_xss(arg)
                                elif threat_type == "PATH_TRAVERSAL":
                                    sanitized_args[i] = responder._sanitize_path(arg)
                                elif threat_type == "CODE_INJECTION":
                                    # For code injection, we sanitize more aggressively
                                    sanitized_val = responder._sanitize_sql(arg)
                                    sanitized_val = responder._sanitize_xss(sanitized_val)
                                    sanitized_args[i] = sanitized_val
            
            # Execute function with potentially sanitized arguments
            try:
                result = func(*sanitized_args, **sanitized_kwargs)
                
                # Log successful execution
                if learning_mode:
                    logging.info(f"Secure execution successful: {func.__name__}")
                
                return result
                
            except Exception as e:
                # Auto-healing attempt
                if auto_heal and not threat_blocked:
                    healing_result = responder.auto_heal(func, sanitized_args, sanitized_kwargs, e)
                    if healing_result is not None:
                        context.auto_heal_successes += 1
                        logging.info(f"Auto-healing successful for {func.__name__}")
                        return healing_result
                
                # Re-raise the exception for safe_execute to handle
                raise
        
        return wrapper
    return decorator

class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass
