# utils.py - Utility functions for the application
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
import hashlib
import hmac
import base64
import secrets
import datetime
import json
import logging

def role_required(roles):
    """
    Decorator to restrict access based on user role
    Used for implementing least privilege principle (2.402.4.2.(바))
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_password_hash(password):
    """
    Generate a secure password hash using werkzeug's built-in function
    Using the default method as recommended
    """
    from werkzeug.security import generate_password_hash as werkzeug_hash
    return werkzeug_hash(password)

def verify_data_integrity(data, integrity_hash, secret_key):
    """
    Verify the integrity of data using HMAC-SHA256
    Implements 3.401, Item 17 (Integrity protection)
    """
    if not integrity_hash or not secret_key:
        return False
    
    # Ensure data is serialized consistently
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate HMAC using the secret key
    computed_hash = hmac.new(
        secret_key.encode('utf-8'),
        data,
        hashlib.sha256
    ).hexdigest()
    
    # Compare in constant time to prevent timing attacks
    return hmac.compare_digest(computed_hash, integrity_hash)

def generate_integrity_hash(data, secret_key):
    """
    Generate an integrity hash for data using HMAC-SHA256
    Used for implementing 3.401, Item 17
    """
    # Ensure data is serialized consistently
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    # Convert data to bytes if it's a string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate HMAC using the secret key
    return hmac.new(
        secret_key.encode('utf-8'),
        data,
        hashlib.sha256
    ).hexdigest()

def generate_token():
    """Generate a secure random token for use in session validation"""
    return secrets.token_hex(32)

def format_datetime(dt):
    """Format datetime objects for display"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def format_date(dt):
    """Format date objects for display"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d")

def get_severity_bootstrap_class(severity):
    """Get Bootstrap class for alert severity"""
    severity_classes = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'primary',
        'low': 'info',
        'info': 'secondary'
    }
    return severity_classes.get(severity.lower(), 'secondary')

def get_status_bootstrap_class(status):
    """Get Bootstrap class for alert status"""
    status_classes = {
        'new': 'danger',
        'acknowledged': 'warning', 
        'resolved': 'success',
        'closed': 'secondary'
    }
    return status_classes.get(status.lower(), 'secondary')

def log_system_event(db, event_type, user_id=None, vessel_id=None, cbs_id=None, description="System event"):
    """Utility function to log system events to SecurityLog"""
    from models import SecurityLog, EventType
    
    try:
        # Convert string event_type to enum if needed
        if isinstance(event_type, str):
            event_type = EventType[event_type.upper()]
        
        log = SecurityLog(
            event_type=event_type,
            user_id=user_id,
            vessel_id=vessel_id,
            cbs_id=cbs_id,
            description=description,
            timestamp=datetime.datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
        return True
    except Exception as e:
        logging.error(f"Error logging system event: {str(e)}")
        db.session.rollback()
        return False
