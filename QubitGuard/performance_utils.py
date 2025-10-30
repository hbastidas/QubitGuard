"""Performance utilities and optimizations for QubitGuard.

This module provides utility functions to optimize common operations
and reduce overhead in cryptographic operations.
"""

import functools
import time
import logging

def timing_decorator(func):
    """Decorator to measure and log function execution time.
    
    This is useful for identifying performance bottlenecks during development
    and testing. Only logs at DEBUG level to avoid overhead in production.
    
    Args:
        func: The function to be timed
        
    Returns:
        The wrapped function with timing capabilities
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            logging.debug(f"{func.__name__} took {end_time - start_time:.4f} seconds")
            return result
        else:
            return func(*args, **kwargs)
    return wrapper


def batch_read_files(file_paths):
    """Read multiple files efficiently in a batch operation.
    
    This function reads multiple files and returns their contents,
    optimizing I/O operations by reading sequentially.
    
    Args:
        file_paths (list): List of file paths to read
        
    Returns:
        dict: Dictionary mapping file paths to their contents
        
    Example:
        >>> files = batch_read_files(['key1.bin', 'key2.bin'])
        >>> key1_data = files['key1.bin']
    """
    results = {}
    for path in file_paths:
        with open(path, 'rb') as f:
            results[path] = f.read()
    return results


def batch_write_files(file_data):
    """Write multiple files efficiently in a batch operation.
    
    This function writes multiple files in a batch, optimizing I/O operations.
    
    Args:
        file_data (dict): Dictionary mapping file paths to content to write
        
    Example:
        >>> batch_write_files({
        ...     'key1.bin': key1_bytes,
        ...     'key2.bin': key2_bytes
        ... })
    """
    for path, data in file_data.items():
        with open(path, 'wb') as f:
            f.write(data)


class MemoryEfficientBuffer:
    """Memory-efficient buffer for handling large data operations.
    
    This class provides a buffer that can handle large data in chunks,
    reducing memory footprint for operations on large files.
    """
    
    def __init__(self, chunk_size=65536):
        """Initialize the buffer with a specified chunk size.
        
        Args:
            chunk_size (int): Size of chunks to process (default: 64KB)
        """
        self.chunk_size = chunk_size
    
    def read_in_chunks(self, file_path):
        """Read a file in chunks to reduce memory usage.
        
        Args:
            file_path (str): Path to the file to read
            
        Yields:
            bytes: Chunks of data from the file
        """
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk
    
    def write_in_chunks(self, file_path, data_generator):
        """Write data to a file in chunks.
        
        Args:
            file_path (str): Path to the output file
            data_generator: Generator that yields chunks of data
        """
        with open(file_path, 'wb') as f:
            for chunk in data_generator:
                f.write(chunk)
