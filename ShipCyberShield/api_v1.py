"""
API v1 endpoints for the Maritime Network Management System
Compliant with KR GC-44-K 3.402 requirements for API security
"""
import os
import uuid
import datetime
import functools
from flask import Blueprint, request, jsonify, current_app, g
from sqlalchemy import desc, asc, and_, or_
from werkzeug.security import check_password_hash
from models import (
    User, UserRole, Vessel, CBSAsset, SecurityZone, 
    Alert, AlertStatus, AlertSeverity, SensorData, SecurityLog, 
    EventType, APIKey
)
from app import db

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')


def api_key_required(f):
    """Decorator to require API key for access to API endpoints"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Get API key from request header
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key is required'}), 401
        
        # Find API key in database
        key = APIKey.query.filter_by(key=api_key, is_active=True).first()
        
        if not key:
            # Log failed API access attempt
            SecurityLog(
                event_type=EventType.API_ACCESS,
                description=f"Failed API access attempt with invalid API key",
                ip_address=request.remote_addr,
                data=f"Endpoint: {request.path}, Method: {request.method}"
            )
            return jsonify({'error': 'Invalid or inactive API key'}), 401
        
        # Check if key is expired
        if key.expires_at and key.expires_at < datetime.datetime.utcnow():
            return jsonify({'error': 'API key has expired'}), 401
        
        # Update last used timestamp
        key.last_used_at = datetime.datetime.utcnow()
        db.session.commit()
        
        # Store user in g for access in the endpoint
        g.user = key.user
        
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require administrator role for API key management"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or g.user.role != UserRole.ADMINISTRATOR:
            # Log unauthorized access attempt
            SecurityLog(
                event_type=EventType.API_ACCESS,
                description=f"Unauthorized API access attempt by non-admin user",
                user_id=g.user.id if g.user else None,
                ip_address=request.remote_addr,
                data=f"Endpoint: {request.path}, Method: {request.method}"
            )
            return jsonify({'error': 'Administrator access required'}), 403
        return f(*args, **kwargs)
    return decorated


# === API Key Management ===
@api_v1.route('/keys', methods=['GET'])
@api_key_required
@admin_required
def get_api_keys():
    """Get all API keys (admin only)"""
    keys = APIKey.query.all()
    
    result = [{
        'id': key.id,
        'description': key.description,
        'created_at': key.created_at.isoformat(),
        'expires_at': key.expires_at.isoformat() if key.expires_at else None,
        'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None,
        'is_active': key.is_active
    } for key in keys]
    
    return jsonify(result)


@api_v1.route('/keys', methods=['POST'])
@api_key_required
@admin_required
def create_api_key():
    """Create a new API key (admin only)"""
    data = request.get_json()
    
    if not data or 'description' not in data:
        return jsonify({'error': 'Description is required'}), 400
    
    # Generate a new API key
    api_key = str(uuid.uuid4())
    
    # Calculate expiration date if provided
    expires_at = None
    if 'expires_days' in data and data['expires_days'] > 0:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=data['expires_days'])
    
    # Create new API key record
    new_key = APIKey(
        user_id=g.user.id,
        key=api_key,
        description=data['description'],
        expires_at=expires_at,
        is_active=True
    )
    
    db.session.add(new_key)
    db.session.commit()
    
    # Log API key creation
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API key created",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Key ID: {new_key.id}, Description: {new_key.description}"
    )
    
    return jsonify({
        'id': new_key.id,
        'key': api_key,  # This is the only time the full key will be returned
        'description': new_key.description,
        'created_at': new_key.created_at.isoformat(),
        'expires_at': new_key.expires_at.isoformat() if new_key.expires_at else None,
        'is_active': new_key.is_active
    })


@api_v1.route('/keys/<int:key_id>', methods=['DELETE'])
@api_key_required
@admin_required
def revoke_api_key(key_id):
    """Revoke an API key (admin only)"""
    key = APIKey.query.get_or_404(key_id)
    
    # Don't allow revoking the key being used for the current request
    if key.key == request.headers.get('X-API-Key'):
        return jsonify({'error': 'Cannot revoke the key used for the current request'}), 400
    
    key.is_active = False
    db.session.commit()
    
    # Log API key revocation
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API key revoked",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Key ID: {key.id}, Description: {key.description}"
    )
    
    return jsonify({'success': True, 'message': 'API key revoked successfully'})


# === Device Endpoints ===
@api_v1.route('/devices', methods=['GET'])
@api_key_required
def get_devices():
    """Get all monitored devices (assets) with optional filtering"""
    # Get filter parameters
    vessel_id = request.args.get('vessel_id', type=int)
    status = request.args.get('status')
    device_type = request.args.get('type')
    zone_id = request.args.get('zone_id', type=int)
    
    # Build query with filters
    query = CBSAsset.query
    
    if vessel_id:
        query = query.filter(CBSAsset.vessel_id == vessel_id)
    
    if status:
        if status.lower() == 'online':
            query = query.filter(CBSAsset.status == 'online')
        elif status.lower() == 'offline':
            query = query.filter(CBSAsset.status == 'offline')
    
    if device_type:
        query = query.filter(CBSAsset.asset_type == device_type)
    
    if zone_id:
        query = query.filter(CBSAsset.security_zone_id == zone_id)
    
    # Get the devices
    devices = query.all()
    
    # Prepare results
    results = []
    for device in devices:
        # Get the latest sensor data for CPU and memory if available
        latest_cpu = SensorData.query.filter_by(
            cbs_id=device.id, 
            sensor_type='cpu_usage'
        ).order_by(desc(SensorData.timestamp)).first()
        
        latest_memory = SensorData.query.filter_by(
            cbs_id=device.id, 
            sensor_type='memory_usage'
        ).order_by(desc(SensorData.timestamp)).first()
        
        # Build metrics object
        metrics = {}
        if latest_cpu:
            metrics['cpu'] = {
                'value': latest_cpu.value,
                'unit': '%',
                'timestamp': latest_cpu.timestamp.isoformat()
            }
        
        if latest_memory:
            metrics['memory'] = {
                'value': latest_memory.value,
                'unit': '%',
                'timestamp': latest_memory.timestamp.isoformat()
            }
        
        # Check if device is online (has recent data)
        is_online = device.status == 'online' if device.status else False
        
        # Build the device object
        device_obj = {
            'id': device.id,
            'name': device.name,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'device_type': device.asset_type,
            'is_online': is_online,
            'vessel': {
                'id': device.vessel.id,
                'name': device.vessel.name,
                'imo_number': device.vessel.imo_number
            },
            'security_zone': {
                'id': device.security_zone.id,
                'name': device.security_zone.name,
                'trust_level': device.security_zone.risk_level
            },
            'metrics': metrics,
            'last_seen': device.last_scan.isoformat() if device.last_scan else None
        }
        
        results.append(device_obj)
    
    # Log API access
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API device list retrieved",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Filters: vessel_id={vessel_id}, status={status}, type={device_type}, zone_id={zone_id}"
    )
    
    return jsonify(results)


@api_v1.route('/devices/<int:device_id>', methods=['GET'])
@api_key_required
def get_device(device_id):
    """Get detailed information for a specific device including metrics history"""
    device = CBSAsset.query.get_or_404(device_id)
    
    # Get the last 24 hours of sensor data for CPU and memory
    yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    
    cpu_data = SensorData.query.filter(
        SensorData.cbs_id == device.id,
        SensorData.sensor_type == 'cpu_usage',
        SensorData.timestamp >= yesterday
    ).order_by(asc(SensorData.timestamp)).all()
    
    memory_data = SensorData.query.filter(
        SensorData.cbs_id == device.id,
        SensorData.sensor_type == 'memory_usage',
        SensorData.timestamp >= yesterday
    ).order_by(asc(SensorData.timestamp)).all()
    
    # Get recent alerts for this device
    recent_alerts = Alert.query.filter(
        Alert.cbs_id == device.id,
        Alert.created_at >= yesterday
    ).order_by(desc(Alert.created_at)).limit(5).all()
    
    # Build metrics history
    metrics = {
        'cpu': [{
            'timestamp': data.timestamp.isoformat(),
            'value': data.value,
            'unit': '%'
        } for data in cpu_data],
        'memory': [{
            'timestamp': data.timestamp.isoformat(),
            'value': data.value,
            'unit': '%'
        } for data in memory_data]
    }
    
    # Format alerts
    formatted_alerts = [{
        'id': alert.id,
        'title': alert.title,
        'message': alert.message,
        'severity': alert.severity.value if alert.severity else None,
        'status': alert.status.value if alert.status else None,
        'created_at': alert.created_at.isoformat()
    } for alert in recent_alerts]
    
    # Build the device object with detailed information
    is_online = device.status == 'online' if device.status else False
    
    device_obj = {
        'id': device.id,
        'name': device.name,
        'ip_address': device.ip_address,
        'mac_address': device.mac_address,
        'device_type': device.asset_type,
        'is_online': is_online,
        'os_type': device.os_type,
        'os_version': device.os_version,
        'description': device.function,
        'firmware_version': device.firmware_version,
        'software_version': device.software_version,
        'vessel': {
            'id': device.vessel.id,
            'name': device.vessel.name,
            'imo_number': device.vessel.imo_number
        },
        'security_zone': {
            'id': device.security_zone.id,
            'name': device.security_zone.name,
            'trust_level': device.security_zone.risk_level
        },
        'metrics': metrics,
        'recent_alerts': formatted_alerts,
        'last_seen': device.last_scan.isoformat() if device.last_scan else None
    }
    
    # Log API access
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API device details retrieved",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Device ID: {device_id}, Name: {device.name}"
    )
    
    return jsonify(device_obj)


# === Alert Endpoints ===
@api_v1.route('/alerts', methods=['GET'])
@api_key_required
def get_alerts():
    """Get alerts with optional filtering"""
    # Get filter parameters
    vessel_id = request.args.get('vessel_id', type=int)
    device_id = request.args.get('device_id', type=int)
    severity = request.args.get('severity')
    status = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', 100, type=int)
    
    # Build query with filters
    query = Alert.query
    
    if vessel_id:
        query = query.filter(Alert.vessel_id == vessel_id)
    
    if device_id:
        query = query.filter(Alert.cbs_id == device_id)
    
    if severity:
        try:
            sev = AlertSeverity[severity.upper()]
            query = query.filter(Alert.severity == sev)
        except KeyError:
            pass  # Invalid severity value, ignore the filter
    
    if status:
        try:
            st = AlertStatus[status.upper()]
            query = query.filter(Alert.status == st)
        except KeyError:
            pass  # Invalid status value, ignore the filter
    
    # Parse date filters
    try:
        if start_date:
            start_dt = datetime.datetime.fromisoformat(start_date)
            query = query.filter(Alert.created_at >= start_dt)
        
        if end_date:
            end_dt = datetime.datetime.fromisoformat(end_date)
            query = query.filter(Alert.created_at <= end_dt)
    except ValueError:
        pass  # Invalid date format, ignore the filter
    
    # Get the alerts
    alerts = query.order_by(desc(Alert.created_at)).limit(limit).all()
    
    # Prepare results
    results = []
    for alert in alerts:
        alert_obj = {
            'id': alert.id,
            'title': alert.title,
            'message': alert.message,
            'severity': alert.severity.value if alert.severity else None,
            'status': alert.status.value if alert.status else None,
            'created_at': alert.created_at.isoformat(),
            'vessel': {
                'id': alert.vessel.id,
                'name': alert.vessel.name
            }
        }
        
        # Add device information if available
        if alert.cbs_asset:
            alert_obj['device'] = {
                'id': alert.cbs_asset.id,
                'name': alert.cbs_asset.name,
                'ip_address': alert.cbs_asset.ip_address
            }
        
        # Add resolved/acknowledged info if available
        if alert.resolved_at:
            alert_obj['resolved_at'] = alert.resolved_at.isoformat()
            if alert.resolver:
                alert_obj['resolved_by'] = alert.resolver.username
        
        if alert.acknowledged_at:
            alert_obj['acknowledged_at'] = alert.acknowledged_at.isoformat()
            if alert.acknowledger:
                alert_obj['acknowledged_by'] = alert.acknowledger.username
        
        results.append(alert_obj)
    
    # Log API access
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API alert list retrieved",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Filters: vessel_id={vessel_id}, device_id={device_id}, severity={severity}, status={status}"
    )
    
    return jsonify(results)


@api_v1.route('/alerts/<int:alert_id>', methods=['GET'])
@api_key_required
def get_alert(alert_id):
    """Get detailed information for a specific alert"""
    alert = Alert.query.get_or_404(alert_id)
    
    # Build detailed alert object
    alert_obj = {
        'id': alert.id,
        'title': alert.title,
        'message': alert.message,
        'severity': alert.severity.value if alert.severity else None,
        'status': alert.status.value if alert.status else None,
        'created_at': alert.created_at.isoformat(),
        'vessel': {
            'id': alert.vessel.id,
            'name': alert.vessel.name,
            'imo_number': alert.vessel.imo_number
        }
    }
    
    # Add device information if available
    if alert.cbs_asset:
        alert_obj['device'] = {
            'id': alert.cbs_asset.id,
            'name': alert.cbs_asset.name,
            'ip_address': alert.cbs_asset.ip_address,
            'device_type': alert.cbs_asset.asset_type,
            'security_zone': {
                'id': alert.cbs_asset.security_zone.id,
                'name': alert.cbs_asset.security_zone.name
            }
        }
    
    # Add resolved/acknowledged info if available
    if alert.resolved_at:
        alert_obj['resolved_at'] = alert.resolved_at.isoformat()
        if alert.resolver:
            alert_obj['resolved_by'] = {
                'id': alert.resolver.id,
                'username': alert.resolver.username
            }
    
    if alert.acknowledged_at:
        alert_obj['acknowledged_at'] = alert.acknowledged_at.isoformat()
        if alert.acknowledger:
            alert_obj['acknowledged_by'] = {
                'id': alert.acknowledger.id,
                'username': alert.acknowledger.username
            }
    
    # Log API access
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API alert details retrieved",
        user_id=g.user.id,
        ip_address=request.remote_addr,
        data=f"Alert ID: {alert_id}, Title: {alert.title}"
    )
    
    return jsonify(alert_obj)


@api_v1.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@api_key_required
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    alert = Alert.query.get_or_404(alert_id)
    
    # Check if the alert is already acknowledged
    if alert.status != AlertStatus.NEW:
        return jsonify({
            'error': f'Alert is already {alert.status.value}',
            'status': alert.status.value
        }), 400
    
    # Update the alert status
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_by = g.user.id
    alert.acknowledged_at = datetime.datetime.utcnow()
    
    db.session.commit()
    
    # Log the action
    SecurityLog(
        event_type=EventType.ALERT_ACTION,
        description=f"Alert acknowledged via API",
        user_id=g.user.id,
        vessel_id=alert.vessel_id,
        cbs_id=alert.cbs_id,
        ip_address=request.remote_addr,
        data=f"Alert ID: {alert.id}, Title: {alert.title}"
    )
    
    return jsonify({
        'success': True,
        'message': 'Alert acknowledged successfully',
        'alert_id': alert.id,
        'status': alert.status.value,
        'acknowledged_at': alert.acknowledged_at.isoformat(),
        'acknowledged_by': g.user.username
    })


@api_v1.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@api_key_required
def resolve_alert(alert_id):
    """Resolve an alert"""
    alert = Alert.query.get_or_404(alert_id)
    
    # Check if the alert is already resolved
    if alert.status == AlertStatus.RESOLVED or alert.status == AlertStatus.CLOSED:
        return jsonify({
            'error': f'Alert is already {alert.status.value}',
            'status': alert.status.value
        }), 400
    
    # Update the alert status
    alert.status = AlertStatus.RESOLVED
    alert.resolved_by = g.user.id
    alert.resolved_at = datetime.datetime.utcnow()
    
    db.session.commit()
    
    # Log the action
    SecurityLog(
        event_type=EventType.ALERT_ACTION,
        description=f"Alert resolved via API",
        user_id=g.user.id,
        vessel_id=alert.vessel_id,
        cbs_id=alert.cbs_id,
        ip_address=request.remote_addr,
        data=f"Alert ID: {alert.id}, Title: {alert.title}"
    )
    
    return jsonify({
        'success': True,
        'message': 'Alert resolved successfully',
        'alert_id': alert.id,
        'status': alert.status.value,
        'resolved_at': alert.resolved_at.isoformat(),
        'resolved_by': g.user.username
    })


# === System Status Endpoint ===
@api_v1.route('/status', methods=['GET'])
@api_key_required
def get_system_status():
    """Get system status overview"""
    # Count vessels, assets, online assets
    vessel_count = Vessel.query.count()
    asset_count = CBSAsset.query.count()
    online_asset_count = CBSAsset.query.filter(CBSAsset.status == 'online').count()
    offline_asset_count = asset_count - online_asset_count
    
    # Count alerts
    alert_count = Alert.query.filter(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])).count()
    new_alert_count = Alert.query.filter(Alert.status == AlertStatus.NEW).count()
    
    # Get latest new alerts (limit to 5)
    latest_alerts = Alert.query.filter(
        Alert.status == AlertStatus.NEW
    ).order_by(desc(Alert.created_at)).limit(5).all()
    
    formatted_alerts = [{
        'id': alert.id,
        'title': alert.title,
        'severity': alert.severity.value if alert.severity else None,
        'status': alert.status.value if alert.status else None,
        'created_at': alert.created_at.isoformat()
    } for alert in latest_alerts]
    
    # Build the status object
    status_obj = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'vessel_count': vessel_count,
        'asset_count': asset_count,
        'online_asset_count': online_asset_count,
        'offline_asset_count': offline_asset_count,
        'alert_count': alert_count,
        'new_alert_count': new_alert_count,
        'latest_alerts': formatted_alerts
    }
    
    # Log API access
    SecurityLog(
        event_type=EventType.API_ACCESS,
        description=f"API system status retrieved",
        user_id=g.user.id,
        ip_address=request.remote_addr
    )
    
    return jsonify(status_obj)