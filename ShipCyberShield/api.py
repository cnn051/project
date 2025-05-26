# api.py - API endpoints for data collection and retrieval
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
import datetime
import hashlib
import json
import logging
from app import db
from models import Vessel, CBSAsset, SensorData, SecurityLog, Alert, AlertStatus, AlertSeverity, EventType, UserRole
from utils import role_required

# Create blueprint
bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/sensor_data', methods=['POST'])
def receive_sensor_data():
    """
    Endpoint to receive sensor data from vessels (3.401, Item 17, 21)
    Validates data integrity and handles encrypted data if applicable
    """
    try:
        # Get data from request
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
        
        # Validate required fields
        required_fields = ['vessel_id', 'cbs_id', 'sensor_type', 'value', 'timestamp']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400
        
        # Validate vessel and CBS existence
        vessel = Vessel.query.get(data['vessel_id'])
        if not vessel:
            return jsonify({'status': 'error', 'message': 'Vessel not found'}), 404
        
        cbs = CBSAsset.query.get(data['cbs_id'])
        if not cbs:
            return jsonify({'status': 'error', 'message': 'CBS Asset not found'}), 404
        
        # Integrity verification (3.401, Item 17, 3.402, Item 38)
        integrity_verified = False
        if 'integrity_hash' in data:
            # Calculate hash of the data (excluding the hash itself)
            hash_data = {k: v for k, v in data.items() if k != 'integrity_hash'}
            calculated_hash = hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()
            integrity_verified = (calculated_hash == data['integrity_hash'])
            
            if not integrity_verified:
                # Log integrity failure but still process data
                log = SecurityLog(
                    event_type=EventType.DATA_INTEGRITY,
                    vessel_id=data['vessel_id'],
                    cbs_id=data['cbs_id'],
                    description=f"Sensor data integrity check failed: {data['sensor_type']}"
                )
                db.session.add(log)
        
        # Handle encrypted data if applicable (3.401, Item 21, 3.402, Item 39)
        encryption_status = data.get('encryption_status', 'Not encrypted')
        
        # Parse timestamp
        try:
            timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        except (ValueError, TypeError):
            timestamp = datetime.datetime.utcnow()
        
        # Create new sensor data record
        sensor_data = SensorData(
            vessel_id=data['vessel_id'],
            cbs_id=data['cbs_id'],
            sensor_type=data['sensor_type'],
            value=float(data['value']),
            unit=data.get('unit', ''),
            integrity_verified=integrity_verified,
            encryption_status=encryption_status,
            timestamp=timestamp
        )
        db.session.add(sensor_data)
        
        # Check thresholds and create alerts if necessary
        threshold_exceeded = check_thresholds(sensor_data)
        
        # Commit changes
        db.session.commit()
        
        # Log successful data reception
        log = SecurityLog(
            event_type=EventType.OS_EVENT,
            vessel_id=data['vessel_id'],
            cbs_id=data['cbs_id'],
            description=f"Sensor data received: {data['sensor_type']} = {data['value']}"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': 'Sensor data received',
            'integrity_verified': integrity_verified,
            'threshold_exceeded': threshold_exceeded
        })
        
    except Exception as e:
        logging.error(f"Error processing sensor data: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

def check_thresholds(sensor_data):
    """Check if sensor data exceeds predefined thresholds and create alerts if necessary"""
    # This would be expanded with actual thresholds from configuration
    # Example thresholds for demonstration
    thresholds = {
        'engine_temperature': {'critical': 95.0, 'warning': 85.0, 'unit': '°C'},
        'fuel_level': {'critical': 10.0, 'warning': 20.0, 'unit': '%'},
        'network_latency': {'critical': 500.0, 'warning': 200.0, 'unit': 'ms'},
        'cpu_usage': {'critical': 90.0, 'warning': 75.0, 'unit': '%'},
        'memory_usage': {'critical': 90.0, 'warning': 80.0, 'unit': '%'},
        'disk_usage': {'critical': 90.0, 'warning': 80.0, 'unit': '%'}
    }
    
    sensor_type = sensor_data.sensor_type
    value = sensor_data.value
    
    if sensor_type not in thresholds:
        return False
    
    if value >= thresholds[sensor_type]['critical']:
        # Create critical alert
        alert = Alert(
            title=f"CRITICAL: {sensor_type} exceeds critical threshold",
            message=f"{sensor_type} value {value} {thresholds[sensor_type]['unit']} exceeds critical threshold of {thresholds[sensor_type]['critical']} {thresholds[sensor_type]['unit']}",
            status=AlertStatus.NEW,
            severity=AlertSeverity.CRITICAL,
            vessel_id=sensor_data.vessel_id,
            cbs_id=sensor_data.cbs_id
        )
        db.session.add(alert)
        return True
    elif value >= thresholds[sensor_type]['warning']:
        # Create warning alert
        alert = Alert(
            title=f"WARNING: {sensor_type} exceeds warning threshold",
            message=f"{sensor_type} value {value} {thresholds[sensor_type]['unit']} exceeds warning threshold of {thresholds[sensor_type]['warning']} {thresholds[sensor_type]['unit']}",
            status=AlertStatus.NEW,
            severity=AlertSeverity.HIGH,
            vessel_id=sensor_data.vessel_id,
            cbs_id=sensor_data.cbs_id
        )
        db.session.add(alert)
        return True
    
    return False

@bp.route('/vessel_data', methods=['GET'])
@login_required
def get_vessel_data():
    """API endpoint to get vessel data for dashboard"""
    try:
        vessels = Vessel.query.all()
        result = []
        
        for vessel in vessels:
            # Get asset counts by security zone
            zones = {}
            for zone in vessel.security_zones:
                asset_count = len(zone.assets)
                zones[zone.id] = {
                    'id': zone.id,
                    'name': zone.name,
                    'asset_count': asset_count
                }
            
            # Get alert counts by severity
            alerts = {
                'critical': Alert.query.filter_by(vessel_id=vessel.id, severity=AlertSeverity.CRITICAL, status=AlertStatus.NEW).count(),
                'high': Alert.query.filter_by(vessel_id=vessel.id, severity=AlertSeverity.HIGH, status=AlertStatus.NEW).count(),
                'medium': Alert.query.filter_by(vessel_id=vessel.id, severity=AlertSeverity.MEDIUM, status=AlertStatus.NEW).count(),
                'low': Alert.query.filter_by(vessel_id=vessel.id, severity=AlertSeverity.LOW, status=AlertStatus.NEW).count()
            }
            
            # Get latest sensor readings
            latest_sensors = SensorData.query.filter_by(vessel_id=vessel.id).order_by(
                SensorData.timestamp.desc()).limit(5).all()
            
            sensors = [{
                'id': s.id,
                'sensor_type': s.sensor_type,
                'value': s.value,
                'unit': s.unit,
                'timestamp': s.timestamp.isoformat(),
                'cbs_name': s.cbs_asset.name if s.cbs_asset else 'Unknown'
            } for s in latest_sensors]
            
            result.append({
                'id': vessel.id,
                'name': vessel.name,
                'imo_number': vessel.imo_number,
                'asset_count': len(vessel.assets),
                'zones': list(zones.values()),
                'alerts': alerts,
                'latest_sensors': sensors
            })
        
        return jsonify({
            'status': 'success',
            'vessels': result
        })
    
    except Exception as e:
        logging.error(f"Error retrieving vessel data: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/vessel/<int:vessel_id>/security_zones', methods=['GET'])
@login_required
def get_security_zones(vessel_id):
    """Get security zones for a specific vessel"""
    try:
        vessel = Vessel.query.get_or_404(vessel_id)
        zones = []
        
        for zone in vessel.security_zones:
            # Get asset information for visualization
            assets = []
            for asset in zone.assets:
                assets.append({
                    'id': asset.id,
                    'name': asset.name,
                    'type': asset.asset_type,
                    'function': asset.function
                })
            
            zones.append({
                'id': zone.id,
                'name': zone.name,
                'description': zone.description,
                'risk_level': zone.risk_level,
                'asset_count': len(zone.assets),
                'assets': assets
            })
        
        return jsonify({
            'status': 'success',
            'vessel_id': vessel_id,
            'vessel_name': vessel.name,
            'zones': zones
        })
    
    except Exception as e:
        logging.error(f"Error retrieving security zones: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/alerts/stats', methods=['GET'])
@login_required
def get_alert_stats():
    """Get alert statistics for dashboard"""
    try:
        # Total alerts by status
        status_counts = {
            'new': Alert.query.filter_by(status=AlertStatus.NEW).count(),
            'acknowledged': Alert.query.filter_by(status=AlertStatus.ACKNOWLEDGED).count(),
            'resolved': Alert.query.filter_by(status=AlertStatus.RESOLVED).count(),
            'closed': Alert.query.filter_by(status=AlertStatus.CLOSED).count()
        }
        
        # New alerts by severity
        severity_counts = {
            'critical': Alert.query.filter_by(status=AlertStatus.NEW, severity=AlertSeverity.CRITICAL).count(),
            'high': Alert.query.filter_by(status=AlertStatus.NEW, severity=AlertSeverity.HIGH).count(),
            'medium': Alert.query.filter_by(status=AlertStatus.NEW, severity=AlertSeverity.MEDIUM).count(),
            'low': Alert.query.filter_by(status=AlertStatus.NEW, severity=AlertSeverity.LOW).count(),
            'info': Alert.query.filter_by(status=AlertStatus.NEW, severity=AlertSeverity.INFO).count()
        }
        
        # Recent alerts
        recent = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
        recent_alerts = [{
            'id': a.id,
            'title': a.title,
            'status': a.status.value,
            'severity': a.severity.value,
            'vessel_id': a.vessel_id,
            'vessel_name': a.vessel.name if a.vessel else 'Unknown',
            'created_at': a.created_at.isoformat()
        } for a in recent]
        
        return jsonify({
            'status': 'success',
            'by_status': status_counts,
            'by_severity': severity_counts,
            'recent': recent_alerts
        })
    
    except Exception as e:
        logging.error(f"Error retrieving alert stats: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/performance_data', methods=['GET', 'POST'])
@login_required
def performance_data():
    """
    API endpoint to get or receive performance metrics for CBS assets
    GET: Retrieves performance metrics for a specific asset and metric type
    POST: Receives performance metrics from a monitoring agent
    """
    if request.method == 'GET':
        try:
            # Get query parameters
            asset_id = request.args.get('asset_id')
            metric_type = request.args.get('metric_type')
            hours = request.args.get('hours', 24, type=int)
            
            if not asset_id or not metric_type:
                return jsonify({'status': 'error', 'message': 'Missing required parameters: asset_id and metric_type'}), 400
            
            # Get the asset
            asset = CBSAsset.query.get(asset_id)
            if not asset:
                return jsonify({'status': 'error', 'message': 'Asset not found'}), 404
            
            # Calculate time range
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(hours=hours)
            
            # Query for performance data for the given metric
            if metric_type == 'cpu':
                # For CPU we need to get the 1-minute load data
                data = SensorData.query.filter(
                    SensorData.cbs_id == asset_id,
                    SensorData.sensor_type == 'cpu_load_1min',
                    SensorData.timestamp.between(start_time, end_time)
                ).order_by(SensorData.timestamp.asc()).all()
                
                result = [{
                    'timestamp': d.timestamp.isoformat(),
                    'value': d.value,
                    'unit': d.unit
                } for d in data]
                
            elif metric_type == 'memory':
                # For memory we need the memory usage data
                data = SensorData.query.filter(
                    SensorData.cbs_id == asset_id,
                    SensorData.sensor_type == 'memory_usage',
                    SensorData.timestamp.between(start_time, end_time)
                ).order_by(SensorData.timestamp.asc()).all()
                
                result = [{
                    'timestamp': d.timestamp.isoformat(),
                    'value': d.value,
                    'unit': d.unit
                } for d in data]
                
            elif metric_type == 'disk':
                # For disk we need to find all disk usage metrics for this asset
                # First get unique disk names from recent readings
                disk_readings = SensorData.query.filter(
                    SensorData.cbs_id == asset_id,
                    SensorData.sensor_type.like('disk_usage_%'),
                    SensorData.timestamp > (end_time - datetime.timedelta(hours=1))
                ).all()
                
                disk_types = set()
                for d in disk_readings:
                    disk_types.add(d.sensor_type)
                
                # Now get data for each disk type
                result = {}
                for disk_type in disk_types:
                    data = SensorData.query.filter(
                        SensorData.cbs_id == asset_id,
                        SensorData.sensor_type == disk_type,
                        SensorData.timestamp.between(start_time, end_time)
                    ).order_by(SensorData.timestamp.asc()).all()
                    
                    disk_name = disk_type.replace('disk_usage_', '')
                    result[disk_name] = [{
                        'timestamp': d.timestamp.isoformat(),
                        'value': d.value,
                        'unit': d.unit
                    } for d in data]
                
            elif metric_type == 'network':
                # For network we need to find all network interfaces for this asset
                # First get unique interface names from recent readings
                net_readings = SensorData.query.filter(
                    SensorData.cbs_id == asset_id,
                    SensorData.sensor_type.like('network_%'),
                    SensorData.timestamp > (end_time - datetime.timedelta(hours=1))
                ).all()
                
                interfaces = set()
                for n in net_readings:
                    if n.sensor_type.startswith('network_in_'):
                        interface = n.sensor_type.replace('network_in_', '')
                        interfaces.add(interface)
                
                # Now get data for each interface
                result = {}
                for interface in interfaces:
                    # Get in and out data
                    in_data = SensorData.query.filter(
                        SensorData.cbs_id == asset_id,
                        SensorData.sensor_type == f"network_in_{interface}",
                        SensorData.timestamp.between(start_time, end_time)
                    ).order_by(SensorData.timestamp.asc()).all()
                    
                    out_data = SensorData.query.filter(
                        SensorData.cbs_id == asset_id,
                        SensorData.sensor_type == f"network_out_{interface}",
                        SensorData.timestamp.between(start_time, end_time)
                    ).order_by(SensorData.timestamp.asc()).all()
                    
                    # Prepare the interface data
                    result[interface] = {
                        'in': [{
                            'timestamp': d.timestamp.isoformat(),
                            'value': d.value,
                            'unit': d.unit
                        } for d in in_data],
                        'out': [{
                            'timestamp': d.timestamp.isoformat(),
                            'value': d.value,
                            'unit': d.unit
                        } for d in out_data]
                    }
            
            else:
                return jsonify({'status': 'error', 'message': f'Unknown metric type: {metric_type}'}), 400
            
            return jsonify({
                'status': 'success',
                'asset_id': asset_id,
                'asset_name': asset.name,
                'metric_type': metric_type,
                'data': result
            })
        
        except Exception as e:
            logging.error(f"Error retrieving performance data: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            # Get data from request
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
            
            # Validate required fields
            required_fields = ['vessel_id', 'cbs_id', 'metrics']
            for field in required_fields:
                if field not in data:
                    return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400
            
            # Validate vessel and CBS existence
            vessel = Vessel.query.get(data['vessel_id'])
            if not vessel:
                return jsonify({'status': 'error', 'message': 'Vessel not found'}), 404
            
            cbs = CBSAsset.query.get(data['cbs_id'])
            if not cbs:
                return jsonify({'status': 'error', 'message': 'CBS Asset not found'}), 404
            
            # Process each metric
            processed_count = 0
            alerts_generated = 0
            
            for metric in data['metrics']:
                if 'type' not in metric or 'value' not in metric:
                    continue
                
                # Create new sensor data record
                sensor_data = SensorData(
                    vessel_id=data['vessel_id'],
                    cbs_id=data['cbs_id'],
                    sensor_type=metric['type'],
                    value=float(metric['value']),
                    unit=metric.get('unit', ''),
                    integrity_verified=True,
                    encryption_status='none',
                    timestamp=datetime.datetime.utcnow()
                )
                db.session.add(sensor_data)
                processed_count += 1
                
                # Check thresholds and create alerts if necessary
                if check_thresholds(sensor_data):
                    alerts_generated += 1
            
            # Update asset's last scan timestamp
            cbs.last_scan = datetime.datetime.utcnow()
            
            # Commit all changes
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Processed {processed_count} metrics',
                'alerts_generated': alerts_generated
            })
            
        except Exception as e:
            logging.error(f"Error processing performance data: {str(e)}")
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/admin/create_user', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR])
def create_user():
    """API endpoint to create a new user (admin only)"""
    try:
        if not current_user.role == UserRole.ADMINISTRATOR:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400
        
        # Check if username or email already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'status': 'error', 'message': 'Email already exists'}), 400
        
        # Create new user
        from models import User, UserRole
        
        user = User(
            username=data['username'],
            email=data['email'],
            role=UserRole(data['role']),
            is_active=data.get('is_active', True),
            mfa_enabled=data.get('mfa_enabled', False)
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        
        # Log user creation
        log = SecurityLog(
            event_type=EventType.ACCESS_CONTROL,
            user_id=current_user.id,
            description=f"User created: {data['username']} with role {data['role']}"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'User created successfully',
            'user_id': user.id
        })
    
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
