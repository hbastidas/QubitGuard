import os
import pytest
import sqlite3
from QubitGuard.crypto_manager import CryptoManager, AuditLog

@pytest.fixture
def crypto_manager():
    return CryptoManager()

@pytest.fixture
def temp_db_path(tmp_path):
    return str(tmp_path / "test_audit.db")

@pytest.fixture
def audit_log(crypto_manager, temp_db_path):
    # Generate and set signing keys
    private_key, public_key = crypto_manager.generate_signing_pair()
    crypto_manager.signing_private_key = private_key
    crypto_manager.signing_public_key = public_key
    
    log = AuditLog(crypto_manager, temp_db_path)
    yield log
    log.close()
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)

def test_audit_log_initialization(temp_db_path, audit_log):
    """Test AuditLog initialization and database creation"""
    # Verify database file is created
    assert os.path.exists(temp_db_path)
    
    # Verify table structure
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    
    # Get table info
    cursor.execute("PRAGMA table_info(audit_log)")
    columns = cursor.fetchall()
    
    # Verify expected columns exist
    column_names = [col[1] for col in columns]
    assert "id" in column_names
    assert "event" in column_names
    assert "signature" in column_names
    assert "public_key" in column_names
    
    conn.close()

def test_log_event(audit_log):
    """Test logging an event"""
    test_event = "Test security event"
    audit_log.log_event(test_event)
    
    # Verify event was logged
    cursor = audit_log.conn.cursor()
    cursor.execute("SELECT event, signature, public_key FROM audit_log WHERE event = ?", 
                  (test_event,))
    result = cursor.fetchone()
    
    assert result is not None
    assert result[0] == test_event
    assert result[1] is not None  # Signature exists
    assert result[2] is not None  # Public key exists

def test_verify_log_entry(audit_log):
    """Test verification of logged events"""
    test_event = "Test security event for verification"
    audit_log.log_event(test_event)
    
    # Get the ID of the logged event
    cursor = audit_log.conn.cursor()
    cursor.execute("SELECT id FROM audit_log WHERE event = ?", (test_event,))
    event_id = cursor.fetchone()[0]
    
    # Verify the event
    assert audit_log.verify_log_entry(event_id)

def test_multiple_events(audit_log):
    """Test logging and verifying multiple events"""
    test_events = [
        "First security event",
        "Second security event",
        "Third security event"
    ]
    
    # Log multiple events
    for event in test_events:
        audit_log.log_event(event)
    
    # Verify all events are logged and can be verified
    cursor = audit_log.conn.cursor()
    cursor.execute("SELECT id, event FROM audit_log")
    logged_events = cursor.fetchall()
    
    assert len(logged_events) == len(test_events)
    
    for event_id, event_text in logged_events:
        assert event_text in test_events
        assert audit_log.verify_log_entry(event_id)

def test_tamper_detection(audit_log):
    """Test detection of tampered log entries"""
    test_event = "Test event for tamper detection"
    audit_log.log_event(test_event)
    
    # Get the event ID
    cursor = audit_log.conn.cursor()
    cursor.execute("SELECT id FROM audit_log WHERE event = ?", (test_event,))
    event_id = cursor.fetchone()[0]
    
    # Tamper with the event
    cursor.execute("UPDATE audit_log SET event = ? WHERE id = ?",
                  ("Tampered event", event_id))
    audit_log.conn.commit()
    
    # Verification should fail
    assert not audit_log.verify_log_entry(event_id)

def test_nonexistent_entry(audit_log):
    """Test verification of non-existent entry"""
    # Should return False for non-existent entries
    assert not audit_log.verify_log_entry(999)  # Non-existent ID

def test_database_closure(audit_log):
    """Test proper database closure"""
    audit_log.close()
    
    # Attempting operations after closure should raise an error
    with pytest.raises(sqlite3.ProgrammingError):
        audit_log.log_event("Test event after closure")
