"""
Exception configuration module for safe_execute decorator.
"""
import os
from typing import Tuple, Type

# Default exception types that are commonly caught
_DEFAULT_EXCEPTIONS = (
    ValueError,
    TypeError,
    ZeroDivisionError,
    IndexError,
    KeyError,
    AttributeError,
    FileNotFoundError,
    IOError,
    RuntimeError,
    Exception  # Always include base Exception
)

# Global variable to store current exceptions
COMMON_EXCEPTIONS = _DEFAULT_EXCEPTIONS

def set_default_exceptions(exception_types: Tuple[Type[Exception], ...]) -> None:
    """Set the default exception types to catch."""
    global COMMON_EXCEPTIONS
    if not isinstance(exception_types, tuple):
        raise TypeError("exception_types must be a tuple")
    
    for exc_type in exception_types:
        if not (isinstance(exc_type, type) and issubclass(exc_type, Exception)):
            raise TypeError(f"All items must be Exception subclasses, got {exc_type}")
    
    # Ensure Exception is always included
    if Exception not in exception_types:
        exception_types += (Exception,)
    
    COMMON_EXCEPTIONS = exception_types

def get_default_exceptions() -> Tuple[Type[Exception], ...]:
    """Get the current default exception types."""
    return COMMON_EXCEPTIONS

def reset_default_exceptions() -> None:
    """Reset default exceptions to the original built-in set."""
    global COMMON_EXCEPTIONS
    COMMON_EXCEPTIONS = _DEFAULT_EXCEPTIONS

def add_exception_type(exception_type: Type[Exception]) -> None:
    """
    Add an exception type to the default list.
    
    Args:
        exception_type: Exception class to add to defaults
    """
    global COMMON_EXCEPTIONS
    
    if not (isinstance(exception_type, type) and issubclass(exception_type, Exception)):
        raise TypeError(f"Must be an Exception subclass, got {exception_type}")
    
    if exception_type not in COMMON_EXCEPTIONS:
        COMMON_EXCEPTIONS = COMMON_EXCEPTIONS + (exception_type,)

def remove_exception_type(exception_type: Type[Exception]) -> None:
    """
    Remove an exception type from the default list.
    
    Args:
        exception_type: Exception class to remove from defaults
        
    Note:
        Cannot remove the base Exception class.
    """
    global COMMON_EXCEPTIONS
    
    if exception_type == Exception:
        raise ValueError("Cannot remove base Exception class from defaults")
    
    COMMON_EXCEPTIONS = tuple(exc for exc in COMMON_EXCEPTIONS if exc != exception_type)

def load_exceptions_from_env() -> None:
    """
    Load exception configuration from environment variables.
    Expected format: SAFE_EXECUTE_EXCEPTIONS=ValueError,TypeError,RuntimeError
    """
    env_exceptions = os.getenv('SAFE_EXECUTE_EXCEPTIONS')
    if env_exceptions:
        try:
            exception_names = [name.strip() for name in env_exceptions.split(',')]
            exception_types = []
            
            for name in exception_names:
                # Get exception class from builtins
                if hasattr(__builtins__, name):
                    exc_class = getattr(__builtins__, name)
                    if isinstance(exc_class, type) and issubclass(exc_class, Exception):
                        exception_types.append(exc_class)
                    else:
                        raise ValueError(f"{name} is not an Exception class")
                else:
                    raise ValueError(f"Unknown exception type: {name}")
            
            set_default_exceptions(tuple(exception_types))
            
        except Exception as e:
            raise ValueError(f"Error loading exceptions from environment: {e}")
