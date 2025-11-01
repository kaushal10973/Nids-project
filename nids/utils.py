import logging
import sys
from logging.handlers import RotatingFileHandler

def setup_logging(level='INFO', log_file='nids.log'):
    """Configure logging for the application."""
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # Reduce verbosity of some libraries
    logging.getLogger('scapy').setLevel(logging.WARNING)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    logging.info("Logging initialized")

def validate_ip(ip_address):
    """Validate IP address format."""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}
    if re.match(pattern, ip_address):
        parts = ip_address.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def format_bytes(bytes_value):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_timestamp():
    """Get current timestamp in ISO format."""
    from datetime import datetime
    return datetime.now().isoformat()

def sanitize_input(input_string):
    """Sanitize user input to prevent injection attacks."""
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    import re
    sanitized = re.sub(r'[^\w\s\-\.\:\/]', '', input_string)
    return sanitized[:255]  # Limit length