from loguru import logger
import os
import sys

def setup_logger(name=None):
    """Setup logger with optional module name.
    
    Args:
        name (str, optional): Module name for logging. Defaults to None.
    """
    os.makedirs('logs', exist_ok=True)
    
    # Remove default handler
    logger.remove()
    
    # Add file handler
    logger.add(
        os.path.join('logs', 'ids_{time}.log'),
        rotation='1 day',
        retention='7 days',
        format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}',
        level='INFO',
        filter=lambda record: record["extra"].get("name", "") == name if name else True
    )
    
    # Add console handler
    logger.add(
        sys.stderr,
        format='{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}',
        level='INFO',
        filter=lambda record: record["extra"].get("name", "") == name if name else True
    )
    
    # Return logger with module name if provided
    if name:
        return logger.bind(name=name)
    return logger 