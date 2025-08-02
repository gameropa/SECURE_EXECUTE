"""
Configuration management for safe_execute decorator.
"""
import os
from typing import Dict, Any, Tuple, Type

class SafeExecuteConfig:
    """Configuration manager for safe_execute decorator."""
    
    def __init__(self):
        self.config = {
            'log_level': 'INFO',
            'log_format': '%(asctime)s [%(levelname)s] %(message)s',
            'date_format': '%Y-%m-%d %H:%M:%S',
            'sanitize_logs': False,
            'max_exception_message_length': None,
            'performance_threshold_warning': None,
            'log_file': None,  # Start with None, set by environment or explicit config
            'log_max_bytes': 10 * 1024 * 1024,
            'log_backup_count': 5,
            'log_to_console': True
        }
        # Load environment variables on initialization
        self.load_from_env()
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Load log file from environment
        log_file = os.getenv('SAFE_EXECUTE_LOG_FILE')
        if log_file:
            # Normalize path separators for Windows
            self.config['log_file'] = os.path.normpath(log_file)
        elif not self.config['log_file']:
            # Set default log file location
            self.config['log_file'] = os.path.normpath(r'd:\safe_execute\logs\safe_execute.log')
        
        # Load other settings
        env_mapping = {
            'SAFE_EXECUTE_LOG_LEVEL': 'log_level',
            'SAFE_EXECUTE_LOG_TO_CONSOLE': 'log_to_console',
            'SAFE_EXECUTE_SANITIZE_LOGS': 'sanitize_logs',
            'SAFE_EXECUTE_LOG_MAX_BYTES': 'log_max_bytes',
            'SAFE_EXECUTE_LOG_BACKUP_COUNT': 'log_backup_count',
            'SAFE_EXECUTE_MAX_MSG_LENGTH': 'max_exception_message_length',
            'SAFE_EXECUTE_PERF_THRESHOLD': 'performance_threshold_warning'
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert boolean strings
                if config_key in ('sanitize_logs', 'log_to_console'):
                    value = value.lower() in ('true', '1', 'yes', 'on')
                # Convert numeric values
                elif config_key in ('max_exception_message_length', 'performance_threshold_warning', 'log_max_bytes', 'log_backup_count'):
                    try:
                        value = float(value) if '.' in value else int(value)
                    except ValueError:
                        continue
                
                self.config[config_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self.config[key] = value
    
    def update(self, **kwargs) -> None:
        """Update multiple configuration values."""
        self.config.update(kwargs)

# Global configuration instance
config = SafeExecuteConfig()

def configure_safe_execute(
    exceptions: Tuple[Type[Exception], ...] = None,
    config_file: str = None,
    **config_options
) -> None:
    """
    Configure safe_execute decorator globally.
    
    Args:
        exceptions: Default exception types to catch
        config_file: Path to configuration file
        **config_options: Additional configuration options
    """
    if config_file and os.path.exists(config_file):
        # Simple config file loading could be added here
        pass
    
    config.load_from_env()
    
    if config_options:
        config.update(**config_options)
    
    if exceptions:
        from .exceptions import set_default_exceptions
        set_default_exceptions(exceptions)

    if config_file:
        config.load_from_file(config_file)
    
    config.load_from_env()
    
    if config_options:
        config.update(**config_options)
    
    if exceptions:
        set_default_exceptions(exceptions)
