import logging
import time
import re
import os
from functools import wraps
from logging.handlers import RotatingFileHandler
from .exceptions import COMMON_EXCEPTIONS
from .config import config

# Track if logging has been configured to avoid reconfiguring during tests
_logging_configured = False

def _configure_logging():
    """Configure logging with file and console handlers."""
    global _logging_configured
    
    logger = logging.getLogger()
    
    # Get log file configuration
    log_file = config.get('log_file')
    if log_file:
        # Normalize the path
        log_file = os.path.normpath(log_file)
        
        # Check if we already have a handler for this file
        existing_file_handler = None
        for handler in logger.handlers:
            if isinstance(handler, RotatingFileHandler) and hasattr(handler, 'baseFilename'):
                if os.path.normpath(handler.baseFilename) == log_file:
                    existing_file_handler = handler
                    break
        
        # Only add handler if we don't already have one for this file
        if not existing_file_handler:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except OSError as e:
                    # If we can't create the directory, log to console only
                    print(f"Warning: Could not create log directory {log_dir}: {e}")
                    return
            
            # Create formatter
            formatter = logging.Formatter(
                config.get('log_format', '%(asctime)s [%(levelname)s] %(message)s'),
                datefmt=config.get('date_format', '%Y-%m-%d %H:%M:%S')
            )
            
            try:
                # Add rotating file handler
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=config.get('log_max_bytes', 10 * 1024 * 1024),
                    backupCount=config.get('log_backup_count', 5),
                    encoding='utf-8'
                )
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"Warning: Could not create log file handler: {e}")
    
    # Set log level
    log_level = getattr(logging, config.get('log_level', 'INFO'))
    logger.setLevel(log_level)
    
    _logging_configured = True

# Configure logging on module import
_configure_logging()

def _sanitize_message(message: str) -> str:
    """
    Sanitize log message to remove potentially sensitive information.
    
    Args:
        message: Original message
        
    Returns:
        Sanitized message
    """
    if not config.get('sanitize_logs', False):
        return message
    
    # Remove common sensitive patterns
    patterns = [
        (r'password["\s]*[:=]["\s]*[^"\s,}]+', 'password=***'),
        (r'token["\s]*[:=]["\s]*[^"\s,}]+', 'token=***'),
        (r'key["\s]*[:=]["\s]*[^"\s,}]+', 'key=***'),
        (r'secret["\s]*[:=]["\s]*[^"\s,}]+', 'secret=***'),
        (r'api_key["\s]*[:=]["\s]*[^"\s,}]+', 'api_key=***'),
    ]
    
    sanitized = message
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    # Limit message length if configured
    max_length = config.get('max_exception_message_length')
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... (truncated)"
    
    return sanitized

# Log aggregation tracking
_log_aggregation = {}
_last_log_time = {}

def _should_aggregate_log(func_name, message_type, elapsed):
    """
    Simple aggregation: combine consecutive identical function calls.
    
    Returns: (should_log_now, aggregated_message)
    """
    current_time = time.time()
    key = f"{func_name}_{message_type}"
    
    if key not in _log_aggregation:
        _log_aggregation[key] = {
            'count': 1,
            'first_time': current_time,
            'last_time': current_time,
            'total_elapsed': elapsed
        }
        _last_log_time[key] = current_time
        return True, None
    
    # Check if this is a consecutive call (within 1 second)
    time_since_last = current_time - _last_log_time[key]
    
    if time_since_last < 1.0:  # Aggregate if within 1 second
        _log_aggregation[key]['count'] += 1
        _log_aggregation[key]['last_time'] = current_time
        _log_aggregation[key]['total_elapsed'] += elapsed
        _last_log_time[key] = current_time
        return False, None  # Don't log yet
    else:
        # Time gap - flush previous aggregation and start new
        prev_data = _log_aggregation[key]
        if prev_data['count'] > 1:
            timespan = prev_data['last_time'] - prev_data['first_time']
            avg_time = prev_data['total_elapsed'] / prev_data['count']
            aggregated_msg = f"Function '{func_name}' executed {prev_data['count']}x in {timespan:.2f}s (avg: {avg_time:.4f}s)"
        else:
            aggregated_msg = None
        
        # Reset for new sequence
        _log_aggregation[key] = {
            'count': 1,
            'first_time': current_time,
            'last_time': current_time,
            'total_elapsed': elapsed
        }
        _last_log_time[key] = current_time
        
        return True, aggregated_msg

def safe_execute(exception_types=None, custom_message=None, finally_callback=None):
    """
    Decorator to safely execute a function with error handling, logging, timing, and optional finalization.

    Args:
        exception_types: tuple of Exception classes to catch (default: configured common exceptions)
        custom_message: optional string to log on failure
        finally_callback: optional function to run in the finally block
        
    Returns:
        Decorated function that returns None on exception, original result on success
        
    Example:
        @safe_execute()
        def risky_function():
            return 1 / 0  # Returns None instead of crashing
            
        @safe_execute(exception_types=(ValueError, TypeError))
        def specific_handling():
            raise RuntimeError("This will still crash")  # Not in exception_types
    """
    if exception_types is None:
        exception_types = COMMON_EXCEPTIONS
    else:
        # Ensure Exception is always included
        if Exception not in exception_types:
            exception_types += (Exception,)
    
    # Add SecurityError to exception types if security module is available
    try:
        from .security.core import SecurityError
        if SecurityError not in exception_types:
            exception_types += (SecurityError,)
    except ImportError:
        pass

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Only reconfigure logging if a log file is configured
            if config.get('log_file'):
                _configure_logging()
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                
                # Check aggregation for success logs
                should_log, aggregated_msg = _should_aggregate_log(func.__name__, 'success', elapsed)
                
                if aggregated_msg:
                    logging.info(aggregated_msg)
                
                if should_log:
                    # Check for performance threshold warning
                    threshold = config.get('performance_threshold_warning')
                    if threshold and elapsed > threshold:
                        logging.warning(f"Function '{func.__name__}' took {elapsed:.4f}s (exceeds threshold of {threshold}s)")
                    else:
                        logging.info(f"Function '{func.__name__}' executed successfully in {elapsed:.4f} seconds.")
                
                return result
            except exception_types as e:
                elapsed = time.time() - start_time
                exc_type = type(e).__name__
                
                # Always log errors (no aggregation for errors)
                if custom_message:
                    msg = custom_message
                else:
                    msg = f"Exception [{exc_type}] in function '{func.__name__}': {str(e)}"
                
                # Sanitize the message if configured
                sanitized_msg = _sanitize_message(msg)
                
                logging.error(f"{sanitized_msg} (after {elapsed:.4f} seconds)")
                return None
            finally:
                if finally_callback:
                    try:
                        finally_callback()
                        logging.debug(f"Finalization for '{func.__name__}' completed.")
                    except Exception as final_e:
                        final_msg = _sanitize_message(str(final_e))
                        logging.warning(f"Finalization error in '{func.__name__}': {final_msg}")
        return wrapper
    return decorator
