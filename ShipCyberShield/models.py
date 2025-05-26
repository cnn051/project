# models.py - SQLAlchemy models for the NMS system
import datetime
import enum
from sqlalchemy import UniqueConstraint, ForeignKey, func
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

# Enumerations for use in models
class UserRole(enum.Enum):
    ADMINISTRATOR = "administrator"
    OPERATOR = "operator"
    READ_ONLY = "read_only"
    
class EventType(enum.Enum):
    ACCESS_CONTROL = "access_control"
    OS_EVENT = "os_event"
    BACKUP_RECOVERY = "backup_recovery"
    CONFIG_CHANGE = "config_change"
    COMM_LOSS = "communication_loss"
    SECURITY_ALARM = "security_alarm"
    DATA_INTEGRITY = "data_integrity"
    MALWARE_DETECTION = "malware_detection"
    API_ACCESS = "api_access"
    ALERT_ACTION = "alert_action"
    SYSTEM_INFO = "system_info"
    SECURITY_WARNING = "security_warning"
    
class AlertStatus(enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"
    
class AlertSeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class User(UserMixin, db.Model):
    """User model for authentication and access control (3.401, Item 1-6, 8)"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.READ_ONLY)
    active = db.Column(db.Boolean, default=True, nullable=False)
    
    @property
    def is_active(self):
        return self.active
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)  # For multi-factor authentication
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def set_password(self, password):
        """Set hashed password for user"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Vessel(db.Model):
    """Vessel model for storing basic vessel information"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    imo_number = db.Column(db.String(7), unique=True, nullable=False)
    call_sign = db.Column(db.String(10))
    vessel_type = db.Column(db.String(64))
    built_date = db.Column(db.Date)
    flag = db.Column(db.String(64))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    assets = db.relationship('CBSAsset', back_populates='vessel', cascade='all, delete-orphan')
    security_zones = db.relationship('SecurityZone', back_populates='vessel', cascade='all, delete-orphan')
    alerts = db.relationship('Alert', back_populates='vessel', cascade='all, delete-orphan')
    sensor_data = db.relationship('SensorData', back_populates='vessel', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Vessel {self.name} (IMO: {self.imo_number})>'

class SecurityZone(db.Model):
    """Security Zone model for logical grouping of CBS (2.402.1)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    risk_level = db.Column(db.String(64))  # e.g., "High", "Medium", "Low"
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    vessel = db.relationship('Vessel', back_populates='security_zones', foreign_keys=[vessel_id])
    assets = db.relationship('CBSAsset', back_populates='security_zone', cascade='all, delete-orphan')
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<SecurityZone {self.name} (Vessel ID: {self.vessel_id})>'

class CBSAsset(db.Model):
    """Computer Based System Asset model for vessel inventory (2.401.1)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    function = db.Column(db.Text)  # Brief function/purpose
    asset_type = db.Column(db.String(64))  # Hardware or Software
    manufacturer = db.Column(db.String(128))
    model = db.Column(db.String(128))
    serial_number = db.Column(db.String(128))
    firmware_version = db.Column(db.String(64))
    software_version = db.Column(db.String(64))
    os_type = db.Column(db.String(64))
    os_version = db.Column(db.String(64))
    patch_level = db.Column(db.String(64))
    physical_location = db.Column(db.String(128))  # Can store IP address
    ip_address = db.Column(db.String(45))  # Dedicated IP address field
    mac_address = db.Column(db.String(17))  # MAC address for asset
    status = db.Column(db.String(20))  # online, offline, warning, critical, etc
    last_scan = db.Column(db.DateTime)  # Last time asset was scanned
    protocols = db.Column(db.String(256))  # Supported communication protocols
    interfaces = db.Column(db.Text)  # Physical interfaces (network, serial)
    installation_date = db.Column(db.Date)
    end_of_life_date = db.Column(db.Date)
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    security_zone_id = db.Column(db.Integer, db.ForeignKey('security_zone.id'), nullable=True)
    parent_asset_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=True)  # For software installed on hardware
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    vessel = db.relationship('Vessel', back_populates='assets', foreign_keys=[vessel_id])
    security_zone = db.relationship('SecurityZone', back_populates='assets')
    parent_asset = db.relationship('CBSAsset', remote_side=[id], backref='installed_software')
    alerts = db.relationship('Alert', back_populates='cbs_asset', cascade='all, delete-orphan')
    sensor_data = db.relationship('SensorData', back_populates='cbs_asset', cascade='all, delete-orphan')
    compensation_measures = db.relationship('CompensationMeasure', back_populates='cbs_asset', cascade='all, delete-orphan')
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<CBSAsset {self.name} (Zone: {self.security_zone_id}{vessel_info})>'

class SensorData(db.Model):
    """Sensor data from vessels"""
    id = db.Column(db.Integer, primary_key=True)
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=False)
    sensor_type = db.Column(db.String(64), nullable=False)
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(32))
    integrity_verified = db.Column(db.Boolean, default=False)
    encryption_status = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    vessel = db.relationship('Vessel', back_populates='sensor_data', foreign_keys=[vessel_id])
    cbs_asset = db.relationship('CBSAsset', back_populates='sensor_data')
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<SensorData {self.sensor_type} (Asset: {self.cbs_id}{vessel_info}, Value: {self.value})>'

class Alert(db.Model):
    """Alert model for security and operational alerts (2.403.1)"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum(AlertStatus), default=AlertStatus.NEW, nullable=False)
    severity = db.Column(db.Enum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False)
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=True)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    vessel = db.relationship('Vessel', back_populates='alerts', foreign_keys=[vessel_id])
    cbs_asset = db.relationship('CBSAsset', back_populates='alerts')
    acknowledger = db.relationship('User', foreign_keys=[acknowledged_by])
    resolver = db.relationship('User', foreign_keys=[resolved_by])
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<Alert {self.title} (Status: {self.status.value}, Severity: {self.severity.value}{vessel_info})>'

class SecurityLog(db.Model):
    """Security log model for audit records (3.401, Item 13-16)"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    event_type = db.Column(db.Enum(EventType), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=True)
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    description = db.Column(db.Text, nullable=False)
    data = db.Column(db.Text)  # JSON data for additional context
    
    # Relationships
    user = db.relationship('User')
    vessel = db.relationship('Vessel')
    cbs_asset = db.relationship('CBSAsset')
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<SecurityLog {self.event_type.value} at {self.timestamp}{vessel_info}>'

class CompensationMeasure(db.Model):
    """Compensation measures for security requirements that cannot be fully met (3.104.4)"""
    id = db.Column(db.Integer, primary_key=True)
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=False)
    security_requirement = db.Column(db.String(256), nullable=False)
    limitation = db.Column(db.Text, nullable=False)
    measure_description = db.Column(db.Text, nullable=False)
    implementation_status = db.Column(db.String(64))  # e.g., "Implemented", "Planned", "Under Review"
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    cbs_asset = db.relationship('CBSAsset', back_populates='compensation_measures')
    approver = db.relationship('User')
    
    def __repr__(self):
        return f'<CompensationMeasure for {self.security_requirement} (Asset: {self.cbs_id})>'

class AlertThreshold(db.Model):
    """Configurable alert thresholds for performance metrics"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    metric_type = db.Column(db.String(64), nullable=False)  # e.g., "cpu_usage", "memory_usage", "disk_usage", etc.
    comparison = db.Column(db.String(16), nullable=False)  # e.g., ">", "<", ">=", "<=", "=="
    threshold_value = db.Column(db.Float, nullable=False)
    duration_minutes = db.Column(db.Integer, default=5)  # Duration the condition must be true before alerting
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=True)  # If null, applies to all assets
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)  # If null, applies to all vessels
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    cbs_asset = db.relationship('CBSAsset', backref=db.backref('alert_thresholds', lazy='dynamic'))
    vessel = db.relationship('Vessel', backref=db.backref('alert_thresholds', lazy='dynamic'))
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<AlertThreshold {self.name} {self.metric_type} {self.comparison} {self.threshold_value}{vessel_info}>'

class NotificationSetting(db.Model):
    """Settings for alert notifications via email and other channels"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    notification_type = db.Column(db.String(32), nullable=False)  # e.g., "email", "sms", "webhook", etc.
    recipient = db.Column(db.String(256), nullable=False)  # Email addresses, separated by comma
    severity_filter = db.Column(db.String(128))  # Optional filter for alert severity, comma-separated
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<NotificationSetting {self.name} type={self.notification_type}>'

class SyslogEntry(db.Model):
    """Syslog message entries collected from network devices and systems"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    facility = db.Column(db.String(32), nullable=False)  # e.g., auth, kernel, etc.
    severity = db.Column(db.String(32), nullable=False)  # e.g., emergency, alert, critical, etc.
    hostname = db.Column(db.String(128), nullable=False)
    sender_ip = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    process = db.Column(db.String(128))
    pid = db.Column(db.String(32), nullable=True)
    message = db.Column(db.Text, nullable=False)
    vessel_id = db.Column(db.Integer, db.ForeignKey('vessel.id'), nullable=True)
    cbs_id = db.Column(db.Integer, db.ForeignKey('cbs_asset.id'), nullable=True)
    received_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    vessel = db.relationship('Vessel', backref=db.backref('syslog_entries', lazy='dynamic'))
    cbs_asset = db.relationship('CBSAsset', backref=db.backref('syslog_entries', lazy='dynamic'))
    
    def __repr__(self):
        vessel_info = f", Vessel ID: {self.vessel_id}" if self.vessel_id else ""
        return f'<SyslogEntry {self.hostname} {self.timestamp}: {self.message[:50]}...{vessel_info}>'


# APIKey model for REST API authentication
class APIKey(db.Model):
    """API Key for authenticating REST API requests"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('api_keys', lazy=True, cascade='all, delete-orphan'))
