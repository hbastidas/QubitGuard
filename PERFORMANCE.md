# Performance Optimizations in QubitGuard

This document describes the performance optimizations implemented in QubitGuard to improve efficiency and reduce overhead in cryptographic operations.

## Overview

QubitGuard has been optimized to provide better performance while maintaining security guarantees. The optimizations focus on reducing redundant operations, improving I/O efficiency, and better resource management.

## Key Optimizations

### 1. Lazy ECDSA Key Initialization

**Problem**: ECDSA keys were always generated during `CryptoManager` initialization, even when quantum-safe mode was exclusively used.

**Solution**: Implemented lazy initialization using Python properties. ECDSA keys are now only generated when accessed.

**Impact**:
- Faster initialization when ECDSA keys are not needed
- Reduced memory footprint for quantum-only operations
- No performance penalty when ECDSA keys are required

**Code Example**:
```python
crypto_manager = CryptoManager()
# ECDSA keys are NOT generated yet

# Only generated when accessed
ecdsa_key = crypto_manager.ecdsa_private_key
```

### 2. Optimized Logging Statements

**Problem**: Logging statements with expensive operations (like list comprehensions) were executed even when logging was disabled, causing unnecessary overhead.

**Solution**: Added conditional checks to only execute expensive logging operations when the log level is enabled.

**Before**:
```python
logging.info(f"Content: {[x for x in data[:10]]}...")
```

**After**:
```python
if logging.getLogger().isEnabledFor(logging.INFO):
    logging.info(f"Content: {list(data[:10])}...")
```

**Impact**:
- Eliminates overhead of list comprehensions when logging is disabled
- Reduces CPU usage in production environments
- Maintains full debugging capability when needed

### 3. Database Indexing for Audit Logs

**Problem**: Queries on the audit log table were performing full table scans for each lookup by ID.

**Solution**: Added an index on the `id` column of the `audit_log` table.

**Code**:
```python
self.conn.execute('''CREATE INDEX IF NOT EXISTS idx_audit_log_id 
                     ON audit_log(id)''')
```

**Impact**:
- O(log n) lookup time instead of O(n)
- Significant speedup for large audit logs
- Better scalability for production deployments

### 4. Context Manager for AuditLog

**Problem**: Database connections could be left open if not explicitly closed, leading to resource leaks.

**Solution**: Implemented context manager protocol (`__enter__` and `__exit__`) for `AuditLog` class.

**Usage**:
```python
# Automatically manages connection lifecycle
with AuditLog(crypto_manager, 'audit.db') as audit_log:
    audit_log.log_event("Important event")
# Connection is automatically closed here
```

**Impact**:
- Automatic resource cleanup
- Prevention of connection leaks
- More Pythonic API

### 5. Batch File I/O Operations

**Problem**: Multiple file operations were performed sequentially, each with separate open/close overhead.

**Solution**: Implemented batch read and write operations in the CLI, grouping related file operations together.

**Before** (genkeys command):
```python
with open('key1.bin', 'wb') as f:
    f.write(key1)
with open('key2.bin', 'wb') as f:
    f.write(key2)
# ... more file operations
```

**After**:
```python
key_files = {
    'key1.bin': key1,
    'key2.bin': key2,
    # ... more keys
}
for filepath, key_data in key_files.items():
    with open(filepath, 'wb') as f:
        f.write(key_data)
```

**Impact**:
- Better code organization
- Reduced code duplication
- Easier to maintain and extend

### 6. Performance Utilities Module

**Added**: New `performance_utils.py` module with reusable performance utilities.

**Features**:
- `timing_decorator`: Measure function execution time for profiling
- `batch_read_files`: Efficiently read multiple files
- `batch_write_files`: Efficiently write multiple files
- `MemoryEfficientBuffer`: Handle large files in chunks

**Example Usage**:
```python
from QubitGuard.performance_utils import timing_decorator, batch_read_files

@timing_decorator
def my_crypto_function():
    # Function execution time is automatically logged
    pass

# Batch read multiple key files
files = batch_read_files(['key1.bin', 'key2.bin', 'key3.bin'])
```

## Performance Testing

A comprehensive test suite has been added in `tests/test_performance.py` to:
- Validate performance improvements
- Prevent performance regressions
- Benchmark critical operations
- Document expected performance characteristics

Run performance tests:
```bash
python -m pytest tests/test_performance.py -v -s
```

## Benchmarks

Example performance metrics (actual times may vary by hardware):

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| Key Generation (Kyber512) | < 0.1s | Fast key generation |
| Encryption (2KB) | < 0.5s | Includes signing |
| Decryption (2KB) | < 0.5s | Includes verification |
| Signing | < 0.2s | Dilithium3 signatures |
| Verification | < 0.2s | Signature validation |
| Audit Log Query | < 0.01s | With indexing |

## Best Practices

### For Application Developers

1. **Reuse CryptoManager instances**: Creating a new instance is fast but reusing reduces overhead
   ```python
   # Good: Reuse the same instance
   crypto_manager = CryptoManager()
   for message in messages:
       encrypted = crypto_manager.encrypt_data(message, public_key)
   ```

2. **Use context managers for AuditLog**:
   ```python
   with AuditLog(crypto_manager, db_path) as audit_log:
       audit_log.log_event("Operation completed")
   ```

3. **Batch file operations**: When working with multiple files, group operations
   ```python
   from QubitGuard.performance_utils import batch_read_files
   keys = batch_read_files(['key1.bin', 'key2.bin', 'key3.bin'])
   ```

4. **Enable logging wisely**: Use appropriate log levels in production
   ```python
   import logging
   # In production, use WARNING or ERROR
   logging.basicConfig(level=logging.WARNING)
   ```

### For Contributors

1. **Profile before optimizing**: Use the `timing_decorator` to identify bottlenecks
2. **Add performance tests**: New features should include performance tests
3. **Document performance characteristics**: Note expected behavior in docstrings
4. **Consider memory usage**: Large data operations should use chunking when possible

## Future Optimizations

Potential areas for future performance improvements:

1. **Parallel Processing**: Batch operations on multiple messages in parallel
2. **Hardware Acceleration**: Leverage hardware crypto accelerators when available
3. **Caching**: Cache frequently used public keys
4. **Async Operations**: Support for async/await patterns for I/O operations
5. **Connection Pooling**: For applications with multiple audit logs

## Security Considerations

All performance optimizations maintain the security guarantees of QubitGuard:
- No compromise on cryptographic strength
- Forward secrecy is preserved
- Signature validation remains thorough
- All operations are still auditable

Performance optimizations focus on reducing unnecessary overhead, not on weakening security measures.

## Conclusion

These optimizations make QubitGuard faster and more efficient while maintaining its strong security guarantees. The improvements benefit all users, from CLI operations to embedded applications.

For questions or suggestions about performance, please open an issue on GitHub.
