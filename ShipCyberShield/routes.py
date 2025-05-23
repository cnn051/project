# routes.py - Main application routes
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, send_file
from flask_login import login_required, current_user
from sqlalchemy import desc
from app import app, db
from models import Vessel, CBSAsset, SecurityZone, Alert, SecurityLog, SensorData, SyslogEntry, AlertThreshold, NotificationSetting, AlertStatus, AlertSeverity, UserRole, EventType
from utils import role_required
import datetime
import auth
import report_utils
import socket
import ipaddress
import netifaces
import logging
# Register blueprints
app.register_blueprint(auth.bp)

# Create a simple API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/security_zones', methods=['GET'])
@login_required
def get_security_zones():
    """API endpoint to get security zones for a specific vessel"""
    vessel_id = request.args.get('vessel_id', type=int)
    
    if not vessel_id:
        return jsonify([])
    
    zones = SecurityZone.query.filter_by(vessel_id=vessel_id).all()
    
    # Convert to JSON serializable format
    zone_list = []
    for zone in zones:
        zone_list.append({
            'id': zone.id,
            'name': zone.name,
            'risk_level': zone.risk_level,
            'description': zone.description
        })
    
    return jsonify(zone_list)

@api_bp.route('/topology', methods=['GET'])
@login_required
def get_network_topology():
    """API endpoint to get network topology data for visualization"""
    vessel_id = request.args.get('vessel_id', type=int)
    
    if not vessel_id:
        return jsonify({'error': 'Vessel ID is required'}), 400
        
    # Get vessel
    vessel = Vessel.query.get(vessel_id)
    if not vessel:
        return jsonify({'error': 'Vessel not found'}), 404
        
    # Get security zones for the vessel
    zones = SecurityZone.query.filter_by(vessel_id=vessel_id).all()
    
    # Prepare nodes and links for network graph
    nodes = []
    links = []
    
    # Add vessel as central node
    nodes.append({
        'id': f'vessel_{vessel.id}',
        'name': vessel.name,
        'type': 'vessel',
        'group': 0
    })
    
    # Add security zones
    for zone in zones:
        zone_id = f'zone_{zone.id}'
        nodes.append({
            'id': zone_id,
            'name': zone.name,
            'type': 'security_zone',
            'group': 1,
            'risk_level': zone.risk_level
        })
        
        # Link zone to vessel
        links.append({
            'source': f'vessel_{vessel.id}',
            'target': zone_id,
            'value': 1
        })
        
        # Add assets in this zone
        assets = CBSAsset.query.filter_by(security_zone_id=zone.id).all()
        for asset in assets:
            asset_id = f'asset_{asset.id}'
            nodes.append({
                'id': asset_id,
                'name': asset.name,
                'type': 'asset',
                'group': 2,
                'asset_type': asset.asset_type,
                'ip_address': asset.ip_address
            })
            
            # Link asset to its zone
            links.append({
                'source': zone_id,
                'target': asset_id,
                'value': 1
            })
    
    return jsonify({
        'nodes': nodes,
        'links': links
    })
    
@api_bp.route('/assets', methods=['GET'])
@login_required
def get_assets_api():
    """API endpoint to get assets with optional filtering"""
    vessel_id = request.args.get('vessel_id', type=int)
    security_zone_id = request.args.get('security_zone_id', type=int)
    
    # Base query
    query = CBSAsset.query
    
    # Apply filters
    if vessel_id:
        query = query.filter_by(vessel_id=vessel_id)
    
    if security_zone_id:
        query = query.filter_by(security_zone_id=security_zone_id)
    
    # Get results
    assets = query.all()
    
    # Convert to JSON
    asset_list = []
    for asset in assets:
        asset_list.append({
            'id': asset.id,
            'name': asset.name,
            'type': asset.asset_type,
            'function': asset.function,
            'status': asset.status,
            'ip_address': asset.ip_address,
            'security_zone_id': asset.security_zone_id,
            'vessel_id': asset.vessel_id
        })
    
    return jsonify(asset_list)

app.register_blueprint(api_bp)

@app.route('/')
def index():
    """Landing page with basic information about the NMS"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')
    
@app.route('/network_scan', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def network_scan():
    """Network scanning page"""
    # 자동으로 서버의 IP 대역 감지
    def get_server_subnet():
        try:
            # 기본 게이트웨이 인터페이스 찾기
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            
            # 해당 인터페이스의 IP 주소와 넷마스크 가져오기
            interface_info = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
            ip_address = interface_info['addr']
            netmask = interface_info['netmask']
            
            # CIDR 표기법으로 변환
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
            return str(network)
        except Exception as e:
            logging.error(f"Error detecting server subnet: {str(e)}")
            return "192.168.1.0/24"  # 기본값
    
    # 저장된 모든 장치 가져오기
    saved_devices = CBSAsset.query.filter(
        CBSAsset.asset_type == "Hardware",
        CBSAsset.function == "Discovered Device"
    ).order_by(CBSAsset.last_scan.desc()).all()
    
    return render_template('network_scan_simple.html', 
                         saved_devices=saved_devices,
                         default_subnet=get_server_subnet())

@app.route('/api/scan_network', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def api_scan_network():
    if request.method == 'GET':
        # 서버의 기본 서브넷 반환
        def get_server_subnet():
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways['default'][netifaces.AF_INET][1]
                interface_info = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
                ip_address = interface_info['addr']
                netmask = interface_info['netmask']
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                
                # 너무 큰 네트워크인 경우 더 작은 범위로 제한
                if network.prefixlen < 24:
                    # 현재 IP를 기준으로 /24 서브넷 생성
                    ip_obj = ipaddress.IPv4Address(ip_address)
                    network = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
                
                return str(network)
            except Exception as e:
                logging.error(f"Error detecting server subnet: {str(e)}")
                return "192.168.1.0/24"
        return jsonify({'default_subnet': get_server_subnet()})

    try:
        # 요청 데이터 로깅
        logging.info(f"Received scan request: {request.data}")
        
        # JSON 요청 처리
        data = request.get_json()
        if not data:
            logging.error("Invalid JSON data in request")
            return jsonify({'error': '유효하지 않은 요청 데이터입니다.'}), 400
            
        logging.info(f"Parsed request data: {data}")
        
        subnet = data.get('subnet')
        max_threads = data.get('max_threads', 20)  # 기본값 20 스레드
        add_all_to_assets = data.get('add_all_to_assets', False)  # 모든 장치를 자산에 추가할지 여부
        
        if not subnet:
            logging.error("Subnet parameter is missing")
            return jsonify({'error': 'Subnet is required'}), 400
            
        # 서브넷 유효성 검사
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            if network.prefixlen < 16:  # /16보다 큰 네트워크는 제한
                logging.error(f"Subnet too large: {subnet}")
                return jsonify({'error': '스캔 범위가 너무 큽니다. /16 이상의 서브넷만 스캔 가능합니다.'}), 400
        except ValueError as e:
            logging.error(f"Invalid subnet format: {subnet}, error: {str(e)}")
            return jsonify({'error': f'잘못된 서브넷 형식입니다: {str(e)}'}), 400
            
        logging.info(f"Starting network scan on subnet: {subnet} with {max_threads} threads")
        
        # 기본 Vessel과 SecurityZone 확인
        if add_all_to_assets:
            vessel = Vessel.query.first()
            if not vessel:
                logging.error("No vessel found in database")
                return jsonify({'error': '기본 선박(Vessel)이 없습니다. 선박을 먼저 등록해주세요.'}), 400
                
            zone = SecurityZone.query.filter_by(vessel_id=vessel.id).first()
            if not zone:
                logging.error("No security zone found in database")
                return jsonify({'error': '기본 보안 영역(Security Zone)이 없습니다. 보안 영역을 먼저 등록해주세요.'}), 400
        
        # 네트워크 스캔 실행
        from simplified_scanner import scan_network
        results, added_count = scan_network(subnet, max_threads=max_threads)
        logging.info(f"Scan completed. Found {len(results)} devices")
        
        # 모든 장치를 자산에 추가
        if add_all_to_assets and results:
            logging.info(f"Adding {len(results)} discovered devices to assets")
            added_devices = []
            
            # 기본 Vessel과 SecurityZone 가져오기 (이미 위에서 확인했으므로 다시 쿼리하지 않음)
            vessel = Vessel.query.first()
            zone = SecurityZone.query.filter_by(vessel_id=vessel.id).first()
            
            for device in results:
                # 이미 존재하는지 확인
                existing = CBSAsset.query.filter_by(ip_address=device['ip']).first()
                if not existing:
                    # 새 자산 생성
                    asset = CBSAsset()
                    asset.name = device['hostname'] if device['hostname'] and device['hostname'] != 'Unknown' else f"Device-{device['ip']}"
                    asset.asset_type = "Hardware"
                    asset.function = device['device_type'] if device['device_type'] else "Discovered Device"
                    asset.ip_address = device['ip']
                    asset.physical_location = device['ip']
                    asset.status = "online"
                    asset.vessel_id = vessel.id
                    asset.security_zone_id = zone.id
                    asset.last_scan = datetime.datetime.utcnow()
                    
                    db.session.add(asset)
                    added_devices.append(device['ip'])
                    
                    # 보안 로그 추가
                    log = SecurityLog()
                    log.event_type = EventType.CONFIG_CHANGE
                    log.user_id = current_user.id
                    log.vessel_id = vessel.id
                    log.description = f"Device {asset.name} (IP: {asset.ip_address}) automatically added from network scan by {current_user.username}"
                    db.session.add(log)
            
            # 변경사항 저장
            db.session.commit()
            logging.info(f"Added {len(added_devices)} new devices to assets")
        
        # 저장된 장치 목록 가져오기
        saved_devices = CBSAsset.query.filter(
            CBSAsset.asset_type == "Hardware"
        ).order_by(CBSAsset.last_scan.desc()).all()
        
        return jsonify({
            'success': True,
            'results': results,
            'added_count': added_count,
            'saved_devices': [{
                'ip_address': device.ip_address,
                'name': device.name,
                'status': device.status,
                'last_scan': device.last_scan.strftime('%Y-%m-%d %H:%M:%S') if device.last_scan else None
            } for device in saved_devices]
        })
    except Exception as e:
        logging.exception(f"Error during network scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_to_inventory', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def add_to_inventory():
    """Add a scanned device to inventory"""
    import json
    
    try:
        device_json = request.form.get('device_json')
        vessel_id = request.form.get('vessel_id')
        zone_id = request.form.get('zone_id')
        
        if not (device_json and vessel_id and zone_id):
            flash("Missing required information", "danger")
            return redirect(url_for('network_scan'))
        
        device = json.loads(device_json)
        
        # Check if the asset already exists
        existing = CBSAsset.query.filter_by(
            vessel_id=vessel_id,
            ip_address=device["ip"]
        ).first()
        
        if existing:
            flash(f"Asset with IP {device['ip']} already exists", "warning")
        else:
            # Create new asset
            asset = CBSAsset()
            asset.name = device["hostname"]
            asset.vessel_id = vessel_id
            asset.security_zone_id = zone_id
            asset.asset_type = "Hardware"
            asset.physical_location = device["ip"]
            asset.ip_address = device["ip"]
            asset.function = device["device_type"]
            asset.status = "online"
            
            # Add port information to protocols field
            if device.get("ports"):
                port_info = [f"{info['port']} ({info['service']})" for port, info in device["ports"].items()]
                asset.protocols = ", ".join(port_info)
            
            db.session.add(asset)
            db.session.commit()
            
            flash(f"Asset {device['hostname']} ({device['ip']}) added to inventory", "success")
        
        return redirect(url_for('network_scan'))
        
    except Exception as e:
        flash(f"Error adding device to inventory: {str(e)}", "danger")
        return redirect(url_for('network_scan'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing overview of vessels and alerts"""
    # Get vessels
    vessels = Vessel.query.all()
    
    # Get latest alerts
    alerts = Alert.query.filter_by(status=AlertStatus.NEW).order_by(desc(Alert.created_at)).limit(10).all()
    
    # Get alert statistics
    alert_stats = {
        'critical': Alert.query.filter_by(severity=AlertSeverity.CRITICAL, status=AlertStatus.NEW).count(),
        'high': Alert.query.filter_by(severity=AlertSeverity.HIGH, status=AlertStatus.NEW).count(),
        'medium': Alert.query.filter_by(severity=AlertSeverity.MEDIUM, status=AlertStatus.NEW).count(),
        'low': Alert.query.filter_by(severity=AlertSeverity.LOW, status=AlertStatus.NEW).count(),
        'info': Alert.query.filter_by(severity=AlertSeverity.INFO, status=AlertStatus.NEW).count()
    }
    
    # Get latest sensor data for quick view
    recent_data = SensorData.query.order_by(desc(SensorData.timestamp)).limit(20).all()
    
    return render_template('dashboard.html', 
                          vessels=vessels, 
                          alerts=alerts, 
                          alert_stats=alert_stats,
                          recent_data=recent_data)

@app.route('/assets')
@login_required
def assets():
    """View of all CBS assets"""
    # 모든 장치 가져오기
    assets = CBSAsset.query.all()
    
    return render_template('assets.html', 
                          assets=assets)

@app.route('/security_zones')
@login_required
def security_zones():
    """View and manage security zones"""
    vessel_id = request.args.get('vessel_id', type=int)
    
    if vessel_id:
        vessel = Vessel.query.get_or_404(vessel_id)
        zones = SecurityZone.query.filter_by(vessel_id=vessel_id).all()
    else:
        vessel = None
        zones = []
    
    vessels = Vessel.query.all()
    
    return render_template('security_zones.html',
                          vessels=vessels,
                          zones=zones,
                          selected_vessel=vessel)

@app.route('/api/security_zones', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def add_security_zone():
    """API endpoint to add a new security zone"""
    try:
        # Get data from request
        data = request.json
        if data is None:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
            
        name = data.get('name')
        description = data.get('description', '')
        risk_level = data.get('risk_level', 'medium')
        vessel_id = data.get('vessel_id')
        
        # Validate required fields
        if not name or not vessel_id:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Check if vessel exists
        vessel = Vessel.query.get(vessel_id)
        if not vessel:
            return jsonify({'success': False, 'error': 'Vessel not found'}), 404
            
        # Create new security zone
        zone = SecurityZone(
            name=name,
            description=description,
            risk_level=risk_level,
            vessel_id=vessel_id
        )
        
        db.session.add(zone)
        db.session.commit()
        
        # Log the event
        log = SecurityLog(
            event_type=EventType.CONFIG_CHANGE,
            user_id=current_user.id,
            vessel_id=vessel_id,
            description=f"Security zone '{name}' created by {current_user.username}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Return success with zone data
        return jsonify({
            'success': True, 
            'zone': {
                'id': zone.id,
                'name': zone.name,
                'description': zone.description,
                'risk_level': zone.risk_level,
                'vessel_id': zone.vessel_id
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
        
@app.route('/api/security_zones/<int:zone_id>', methods=['PUT'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def update_security_zone(zone_id):
    """API endpoint to update an existing security zone"""
    try:
        # Get the zone to update
        zone = SecurityZone.query.get(zone_id)
        if not zone:
            return jsonify({'success': False, 'error': 'Security zone not found'}), 404
        
        # Get data from request
        data = request.json
        if data is None:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400
            
        name = data.get('name')
        description = data.get('description')
        risk_level = data.get('risk_level')
        
        # Validate required fields
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400
        
        # Update zone fields
        zone.name = name
        if description is not None:
            zone.description = description
        if risk_level is not None:
            zone.risk_level = risk_level
        
        db.session.commit()
        
        # Log the event
        log = SecurityLog(
            event_type=EventType.CONFIG_CHANGE,
            user_id=current_user.id,
            vessel_id=zone.vessel_id,
            description=f"Security zone '{zone.name}' updated by {current_user.username}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Return success with updated zone data
        return jsonify({
            'success': True, 
            'zone': {
                'id': zone.id,
                'name': zone.name,
                'description': zone.description,
                'risk_level': zone.risk_level,
                'vessel_id': zone.vessel_id
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/alerts')
@login_required
def alerts():
    """View and manage alerts"""
    status = request.args.get('status', default='all')
    severity = request.args.get('severity', default='all')
    vessel_id = request.args.get('vessel_id', type=int)
    
    # Start with base query
    query = Alert.query
    
    # Apply filters
    if status != 'all':
        status_enum = AlertStatus(status)
        query = query.filter_by(status=status_enum)
    
    if severity != 'all':
        severity_enum = AlertSeverity(severity)
        query = query.filter_by(severity=severity_enum)
    
    if vessel_id:
        query = query.filter_by(vessel_id=vessel_id)
    
    # Order by created_at (newest first)
    alerts = query.order_by(desc(Alert.created_at)).all()
    
    # Get vessels for filter dropdown
    vessels = Vessel.query.all()
    
    return render_template('alerts.html', 
                          alerts=alerts, 
                          vessels=vessels,
                          status_filter=status,
                          severity_filter=severity,
                          vessel_filter=vessel_id)

@app.route('/alert/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged"""
    alert = Alert.query.get_or_404(alert_id)
    
    if alert.status != AlertStatus.NEW:
        flash('This alert has already been acknowledged or resolved.', 'warning')
        return redirect(url_for('alerts'))
    
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.datetime.utcnow()
    db.session.commit()
    
    # Log the event
    log = SecurityLog(
        event_type=EventType.SECURITY_ALARM,
        user_id=current_user.id,
        vessel_id=alert.vessel_id,
        cbs_id=alert.cbs_id,
        description=f"Alert '{alert.title}' acknowledged by {current_user.username}"
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Alert acknowledged successfully.', 'success')
    return redirect(url_for('alerts'))

@app.route('/alert/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    alert = Alert.query.get_or_404(alert_id)
    
    if alert.status == AlertStatus.RESOLVED or alert.status == AlertStatus.CLOSED:
        flash('This alert has already been resolved or closed.', 'warning')
        return redirect(url_for('alerts'))
    
    alert.status = AlertStatus.RESOLVED
    alert.resolved_by = current_user.id
    alert.resolved_at = datetime.datetime.utcnow()
    db.session.commit()
    
    # Log the event
    log = SecurityLog(
        event_type=EventType.SECURITY_ALARM,
        user_id=current_user.id,
        vessel_id=alert.vessel_id,
        cbs_id=alert.cbs_id,
        description=f"Alert '{alert.title}' resolved by {current_user.username}"
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Alert resolved successfully.', 'success')
    return redirect(url_for('alerts'))

@app.route('/logs')
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def logs():
    """View security logs (restricted to admin and operators)"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    event_type = request.args.get('event_type', 'all')
    vessel_id = request.args.get('vessel_id', type=int)
    
    # Base query
    query = SecurityLog.query
    
    # Apply filters
    if start_date:
        start = datetime.datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(SecurityLog.timestamp >= start)
    
    if end_date:
        end = datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1)
        query = query.filter(SecurityLog.timestamp < end)
    
    if event_type != 'all':
        query = query.filter_by(event_type=event_type)
    
    if vessel_id:
        query = query.filter_by(vessel_id=vessel_id)
    
    # Order by timestamp (newest first)
    logs = query.order_by(desc(SecurityLog.timestamp)).all()
    
    # Get vessels for filter dropdown
    vessels = Vessel.query.all()
    
    return render_template('logs.html', 
                          logs=logs, 
                          vessels=vessels,
                          event_type_filter=event_type,
                          vessel_filter=vessel_id,
                          start_date=start_date,
                          end_date=end_date)

@app.route('/reports/performance', methods=['GET', 'POST'])
@login_required
def performance_report():
    """On-demand performance report page"""
    vessels = Vessel.query.all()
    assets = []
    selected_vessel_id = None
    selected_asset_id = None
    time_range = request.args.get('time_range', '24h')
    export_format = request.args.get('export', None)
    
    # Get vessel_id from query params or form
    vessel_id = request.args.get('vessel_id', type=int)
    if vessel_id is None and request.method == 'POST':
        vessel_id = request.form.get('vessel_id', type=int)
    
    if vessel_id:
        selected_vessel_id = vessel_id
        assets = CBSAsset.query.filter_by(vessel_id=vessel_id).all()
    
    # Get asset_id from query params or form
    asset_id = request.args.get('asset_id', type=int)
    if asset_id is None and request.method == 'POST':
        asset_id = request.form.get('asset_id', type=int)
    
    # Set selected asset
    if asset_id:
        selected_asset_id = asset_id
    
    # Get time range from query params or form
    if request.method == 'POST':
        time_range = request.form.get('time_range', '24h')
    
    report_data = None
    raw_data = None
    
    # Generate report if we have an asset
    if selected_asset_id:
        report_data, raw_data = report_utils.get_performance_report(selected_asset_id, time_range)
        
        # Export to CSV if requested
        if export_format == 'csv' and report_data:
            # Flatten data for CSV export
            csv_data = []
            
            # Add summary row
            csv_data.append({
                'Report Type': 'Performance Report',
                'Asset': report_data.get('asset_name', ''),
                'Vessel': report_data.get('vessel_name', ''),
                'Start Time': report_data.get('start_time', ''),
                'End Time': report_data.get('end_time', ''),
                'Data Points': report_data.get('data_points', 0)
            })
            
            # Add metric data
            for metric_type, metric_data in report_data.get('metrics', {}).items():
                row = {
                    'Metric Type': metric_type,
                    'Minimum': metric_data.get('min', ''),
                    'Maximum': metric_data.get('max', ''),
                    'Average': metric_data.get('avg', ''),
                    'Count': metric_data.get('count', ''),
                    'Unit': metric_data.get('unit', ''),
                    'Last Value': metric_data.get('last_value', '')
                }
                csv_data.append(row)
            
            # Return CSV
            filename = f"performance_report_{selected_asset_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return report_utils.generate_csv_response(csv_data, filename)
    
    return render_template('performance_report.html',
                          vessels=vessels,
                          assets=assets,
                          selected_vessel_id=selected_vessel_id,
                          selected_asset_id=selected_asset_id,
                          time_range=time_range,
                          report_data=report_data,
                          raw_data=raw_data)


@app.route('/reports/alerts', methods=['GET', 'POST'])
@login_required
def alert_report():
    """Historical alert report page"""
    vessels = Vessel.query.all()
    assets = []
    selected_vessel_id = None
    selected_asset_id = None
    selected_severity = None
    selected_status = None
    export_format = request.args.get('export', None)
    
    # Get parameters from query params or form
    if request.method == 'POST':
        vessel_id = request.form.get('vessel_id', type=int)
        asset_id = request.form.get('asset_id', type=int)
        severity = request.form.get('severity')
        status = request.form.get('status')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
    else:
        vessel_id = request.args.get('vessel_id', type=int)
        asset_id = request.args.get('asset_id', type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
    
    # Parse dates
    start_date = None
    if start_date_str:
        try:
            start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid start date format. Use YYYY-MM-DD.', 'warning')
    
    end_date = None
    if end_date_str:
        try:
            end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid end date format. Use YYYY-MM-DD.', 'warning')
    
    # Set selected values
    if vessel_id:
        selected_vessel_id = vessel_id
        assets = CBSAsset.query.filter_by(vessel_id=vessel_id).all()
    
    if asset_id:
        selected_asset_id = asset_id
    
    if severity:
        selected_severity = severity
    
    if status:
        selected_status = status
    
    # Generate report
    alerts = report_utils.get_alert_report(
        vessel_id=selected_vessel_id,
        asset_id=selected_asset_id,
        severity=selected_severity,
        status=selected_status,
        start_date=start_date,
        end_date=end_date
    )
    
    # Export to CSV if requested
    if export_format == 'csv' and alerts:
        filename = f"alert_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return report_utils.generate_csv_response(alerts, filename)
    
    return render_template('alert_report.html',
                          vessels=vessels,
                          assets=assets,
                          selected_vessel_id=selected_vessel_id,
                          selected_asset_id=selected_asset_id,
                          selected_severity=selected_severity,
                          selected_status=selected_status,
                          start_date=start_date_str,
                          end_date=end_date_str,
                          alerts=alerts,
                          alert_severities=AlertSeverity,
                          alert_statuses=AlertStatus)


@app.route('/database/retention', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR])
def database_retention():
    """Database retention management page"""
    # Get current database statistics
    stats = report_utils.get_retention_statistics()
    cleanup_results = None
    
    if request.method == 'POST':
        # Get retention settings from form
        sensor_data_days = request.form.get('sensor_data_days', type=int, default=90)
        security_log_days = request.form.get('security_log_days', type=int, default=365)
        alert_days = request.form.get('alert_days', type=int, default=180)
        
        # Validate settings
        if sensor_data_days < 30:
            flash('Sensor data retention must be at least 30 days for operational purposes.', 'danger')
        elif security_log_days < 180:
            flash('Security log retention must be at least 180 days for compliance with KR GC-44-K.', 'danger')
        elif alert_days < 90:
            flash('Alert retention must be at least 90 days for incident investigation.', 'danger')
        else:
            # Perform cleanup
            cleanup_results = report_utils.cleanup_old_data(
                sensor_data_days=sensor_data_days,
                security_log_days=security_log_days,
                alert_days=alert_days
            )
            
            flash('Database cleanup completed successfully.', 'success')
            
            # Refresh statistics
            stats = report_utils.get_retention_statistics()
    
    # Default retention settings
    settings = {
        'sensor_data_days': 90,
        'security_log_days': 365,
        'alert_days': 180
    }
    
    return render_template('database_retention.html',
                          stats=stats,
                          settings=settings,
                          cleanup_results=cleanup_results)


@app.route('/performance_monitoring')
@login_required
def performance_monitoring():
    """Performance monitoring dashboard showing CPU, memory, disk, and network metrics"""
    # Get vessels for dropdown selection
    vessels = Vessel.query.all()
    
    # Get all the assets that have performance data
    # We'll filter for assets that have had data collected in the last 24 hours
    time_threshold = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    
    # Find assets with recent performance data
    performance_assets = db.session.query(CBSAsset).join(SensorData, CBSAsset.id == SensorData.cbs_id)\
        .filter(SensorData.timestamp > time_threshold)\
        .filter(SensorData.sensor_type.in_(['cpu_load_1min', 'memory_usage', 'disk_usage', 'network_in']))\
        .distinct().all()
    
    # Default to the first asset if any exist
    selected_asset_id = request.args.get('asset_id', type=int)
    selected_asset = None
    
    if selected_asset_id:
        selected_asset = CBSAsset.query.get(selected_asset_id)
    elif performance_assets:
        selected_asset = performance_assets[0]
        selected_asset_id = selected_asset.id
    
    # Get latest metrics for the selected asset
    latest_metrics = {}
    if selected_asset:
        # Get latest CPU usage
        cpu_data = SensorData.query.filter(
            SensorData.cbs_id == selected_asset.id,
            SensorData.sensor_type == 'cpu_load_1min'
        ).order_by(SensorData.timestamp.desc()).first()
        
        if cpu_data:
            latest_metrics['cpu'] = {
                'value': cpu_data.value,
                'unit': cpu_data.unit,
                'timestamp': cpu_data.timestamp.isoformat()
            }
        
        # Get latest memory usage
        memory_data = SensorData.query.filter(
            SensorData.cbs_id == selected_asset.id,
            SensorData.sensor_type == 'memory_usage'
        ).order_by(SensorData.timestamp.desc()).first()
        
        if memory_data:
            latest_metrics['memory'] = {
                'value': memory_data.value,
                'unit': memory_data.unit,
                'timestamp': memory_data.timestamp.isoformat()
            }
        
        # Get latest disk usage metrics (might be multiple disks)
        disk_data = SensorData.query.filter(
            SensorData.cbs_id == selected_asset.id,
            SensorData.sensor_type.like('disk_usage_%')
        ).order_by(SensorData.timestamp.desc()).limit(5).all()
        
        if disk_data:
            latest_metrics['disk'] = {}
            for disk in disk_data:
                disk_name = disk.sensor_type.replace('disk_usage_', '')
                if disk_name not in latest_metrics['disk']:
                    latest_metrics['disk'][disk_name] = {
                        'value': disk.value,
                        'unit': disk.unit,
                        'timestamp': disk.timestamp.isoformat()
                    }
    
    # Get all active alert thresholds
    thresholds = AlertThreshold.query.filter_by(enabled=True).all()
    
    # Check metrics against thresholds and generate alerts if needed
    if latest_metrics and selected_asset:
        # Check CPU metrics against thresholds
        if 'cpu' in latest_metrics:
            check_data = {
                'metric_type': 'cpu_usage',
                'value': latest_metrics['cpu']['value']
            }
            from notification_utils import check_alert_thresholds
            check_alert_thresholds(check_data, selected_asset.id, selected_asset.vessel_id)
        
        # Check memory metrics against thresholds
        if 'memory' in latest_metrics:
            check_data = {
                'metric_type': 'memory_usage',
                'value': latest_metrics['memory']['value']
            }
            from notification_utils import check_alert_thresholds
            check_alert_thresholds(check_data, selected_asset.id, selected_asset.vessel_id)
        
        # Check disk metrics against thresholds
        if 'disk' in latest_metrics:
            for disk_name, disk_data in latest_metrics['disk'].items():
                check_data = {
                    'metric_type': 'disk_usage',
                    'value': disk_data['value']
                }
                from notification_utils import check_alert_thresholds
                check_alert_thresholds(check_data, selected_asset.id, selected_asset.vessel_id)
    
    return render_template('performance_monitoring.html',
                          vessels=vessels,
                          performance_assets=performance_assets,
                          thresholds=thresholds,
                          selected_asset=selected_asset,
                          latest_metrics=latest_metrics)

@app.route('/active_monitoring', methods=['GET', 'POST'])
@login_required
def active_monitoring():
    """Active monitoring page for device up/down status and service checks"""
    import active_monitor
    
    # Get all vessels
    vessels = Vessel.query.all()
    
    # Get the selected vessel
    vessel_id = request.args.get('vessel_id', type=int)
    vessel = None
    
    if vessel_id:
        vessel = Vessel.query.get_or_404(vessel_id)
        # Get all assets for this vessel with IP addresses
        assets = CBSAsset.query.filter(
            CBSAsset.vessel_id == vessel_id,
            CBSAsset.ip_address.isnot(None)
        ).all()
    else:
        # No vessel selected, get first one if exists
        if vessels:
            vessel = vessels[0]
            vessel_id = vessel.id
            # Get all assets for the first vessel
            assets = CBSAsset.query.filter(
                CBSAsset.vessel_id == vessel_id,
                CBSAsset.ip_address.isnot(None)
            ).all()
        else:
            assets = []
    
    # Handle form submission to start/stop monitoring
    if request.method == 'POST':
        action = request.form.get('action')
        asset_id = request.form.get('asset_id', type=int)
        interval = request.form.get('interval', 60, type=int)
        
        if action == 'start' and asset_id:
            # Start monitoring for the asset
            success = active_monitor.start_monitoring(asset_id, interval)
            if success:
                flash(f"Started monitoring asset (ID: {asset_id}) at {interval}s intervals", "success")
            else:
                flash(f"Asset (ID: {asset_id}) is already being monitored", "warning")
                
        elif action == 'stop' and asset_id:
            # Stop monitoring for the asset
            success = active_monitor.stop_monitoring(asset_id)
            if success:
                flash(f"Stopped monitoring asset (ID: {asset_id})", "success")
            else:
                flash(f"Asset (ID: {asset_id}) is not being monitored", "warning")
                
        elif action == 'start_all' and vessel_id:
            # Start monitoring all assets for this vessel
            count = 0
            for asset in assets:
                if active_monitor.start_monitoring(asset.id, interval):
                    count += 1
            
            if count > 0:
                flash(f"Started monitoring {count} assets at {interval}s intervals", "success")
            else:
                flash("No new assets to monitor", "info")
                
        elif action == 'stop_all' and vessel_id:
            # Stop monitoring all assets for this vessel
            count = 0
            for asset in assets:
                if active_monitor.stop_monitoring(asset.id):
                    count += 1
            
            if count > 0:
                flash(f"Stopped monitoring {count} assets", "success")
            else:
                flash("No assets were being monitored", "info")
    
    # Get current monitoring status
    monitoring_status = active_monitor.get_monitoring_status()
    
    # Filter assets that are being monitored
    for asset in assets:
        asset.is_monitored = asset.id in monitoring_status and monitoring_status[asset.id]["running"]
        if asset.is_monitored:
            asset.monitor_interval = monitoring_status[asset.id]["interval"]
            asset.monitor_start_time = monitoring_status[asset.id]["start_time"]
    
    # For quick test, perform a single ping check on request
    test_results = {}
    if request.args.get('test_ping'):
        asset_id = request.args.get('test_ping', type=int)
        asset = CBSAsset.query.get(asset_id)
        if asset and asset.ip_address:
            # Do a ping test
            success, result = active_monitor.ping_host(asset.ip_address)
            test_results[asset_id] = {
                'type': 'ping',
                'success': success,
                'result': result
            }
    
    # For quick test, perform a single port check on request
    if request.args.get('test_port'):
        asset_id, port = request.args.get('test_port').split(':')
        asset_id = int(asset_id)
        port = int(port)
        asset = CBSAsset.query.get(asset_id)
        if asset and asset.ip_address:
            # Do a port test
            success, result = active_monitor.check_port(asset.ip_address, port)
            if asset_id not in test_results:
                test_results[asset_id] = {}
            test_results[asset_id] = {
                'type': 'port',
                'port': port,
                'success': success,
                'result': result
            }
    
    return render_template('active_monitoring.html',
                          vessels=vessels,
                          selected_vessel=vessel,
                          assets=assets,
                          monitoring_status=monitoring_status,
                          test_results=test_results)

@app.route('/syslog', methods=['GET', 'POST'])
@login_required
def syslog_management():
    """Syslog management and log viewing page"""
    import syslog_receiver
    
    # Get server status
    server_status = syslog_receiver.get_syslog_server_status()
    
    # Handle form submissions (server start/stop)
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start_server':
            # Get parameters
            host = request.form.get('host', '0.0.0.0')
            port = request.form.get('port', 514, type=int)
            
            # Start server
            success = syslog_receiver.start_syslog_server(host, port)
            if success:
                flash(f"Syslog server started on {host}:{port}", "success")
            else:
                flash("Failed to start Syslog server. Check if port is available.", "danger")
                
        elif action == 'stop_server':
            # Stop server
            success = syslog_receiver.stop_syslog_server()
            if success:
                flash("Syslog server stopped", "success")
            else:
                flash("Failed to stop Syslog server", "danger")
        
        # Get updated status
        server_status = syslog_receiver.get_syslog_server_status()
    
    # Get filter parameters
    facility = request.args.get('facility', 'all')
    severity = request.args.get('severity', 'all')
    hostname = request.args.get('hostname', '')
    process = request.args.get('process', '')
    vessel_id = request.args.get('vessel_id', type=int)
    message_contains = request.args.get('message', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Base query
    query = SyslogEntry.query
    
    # Apply filters
    if facility != 'all':
        query = query.filter_by(facility=facility)
    
    if severity != 'all':
        query = query.filter_by(severity=severity)
    
    if hostname:
        query = query.filter(SyslogEntry.hostname.like(f'%{hostname}%'))
    
    if process:
        query = query.filter(SyslogEntry.process.like(f'%{process}%'))
    
    if vessel_id:
        query = query.filter_by(vessel_id=vessel_id)
    
    if message_contains:
        query = query.filter(SyslogEntry.message.like(f'%{message_contains}%'))
    
    if start_date:
        start = datetime.datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(SyslogEntry.timestamp >= start)
    
    if end_date:
        end = datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1)
        query = query.filter(SyslogEntry.timestamp < end)
    
    # Get vessels for dropdown
    vessels = Vessel.query.all()
    
    # Get unique facilities and severities for dropdowns
    all_facilities = db.session.query(SyslogEntry.facility).distinct().all()
    facilities = [f[0] for f in all_facilities]
    
    all_severities = db.session.query(SyslogEntry.severity).distinct().all()
    severities = [s[0] for s in all_severities]
    
    # Add pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    logs_pagination = query.order_by(SyslogEntry.timestamp.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('syslog.html',
                          server_status=server_status,
                          logs=logs_pagination,
                          vessels=vessels,
                          facilities=facilities,
                          severities=severities,
                          facility_filter=facility,
                          severity_filter=severity,
                          hostname_filter=hostname,
                          process_filter=process,
                          vessel_filter=vessel_id,
                          message_filter=message_contains,
                          start_date=start_date,
                          end_date=end_date)

@app.route('/alert_thresholds', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def alert_thresholds():
    """Alert threshold management"""
    # Handle form submission for new threshold
    if request.method == 'POST':
        if 'add_threshold' in request.form:
            # Add new threshold
            name = request.form.get('name')
            description = request.form.get('description', '')
            metric_type = request.form.get('metric_type')
            comparison = request.form.get('comparison')
            threshold_value = request.form.get('threshold_value', type=float)
            duration_minutes = request.form.get('duration_minutes', type=int, default=5)
            cbs_id = request.form.get('cbs_id', type=int)
            vessel_id = request.form.get('vessel_id', type=int)
            
            if not name or not metric_type or not comparison or threshold_value is None:
                flash('All required fields must be filled out', 'danger')
            else:
                threshold = AlertThreshold()
                threshold.name = name
                threshold.description = description
                threshold.metric_type = metric_type
                threshold.comparison = comparison
                threshold.threshold_value = threshold_value
                threshold.duration_minutes = duration_minutes
                
                if cbs_id:
                    threshold.cbs_id = cbs_id
                if vessel_id:
                    threshold.vessel_id = vessel_id
                
                db.session.add(threshold)
                
                # Log to security log
                security_log = SecurityLog()
                security_log.event_type = EventType.CONFIG_CHANGE
                security_log.user_id = current_user.id
                security_log.description = f"Created alert threshold: {name}"
                db.session.add(security_log)
                
                db.session.commit()
                flash(f'Alert threshold "{name}" added successfully', 'success')
                return redirect(url_for('alert_thresholds'))
        
        elif 'edit_threshold' in request.form:
            # Edit existing threshold
            threshold_id = request.form.get('threshold_id', type=int)
            threshold = AlertThreshold.query.get_or_404(threshold_id)
            
            threshold.name = request.form.get('name')
            threshold.description = request.form.get('description', '')
            threshold.metric_type = request.form.get('metric_type')
            threshold.comparison = request.form.get('comparison')
            threshold.threshold_value = request.form.get('threshold_value', type=float)
            threshold.duration_minutes = request.form.get('duration_minutes', type=int, default=5)
            
            cbs_id = request.form.get('cbs_id', type=int)
            vessel_id = request.form.get('vessel_id', type=int)
            
            threshold.cbs_id = cbs_id if cbs_id else None
            threshold.vessel_id = vessel_id if vessel_id else None
            threshold.enabled = 'enabled' in request.form
            
            # Log to security log
            security_log = SecurityLog()
            security_log.event_type = EventType.CONFIG_CHANGE
            security_log.user_id = current_user.id
            security_log.description = f"Updated alert threshold: {threshold.name}"
            db.session.add(security_log)
            
            db.session.commit()
            flash(f'Alert threshold "{threshold.name}" updated successfully', 'success')
            return redirect(url_for('alert_thresholds'))
        
        elif 'delete_threshold' in request.form:
            # Delete threshold
            threshold_id = request.form.get('threshold_id', type=int)
            threshold = AlertThreshold.query.get_or_404(threshold_id)
            
            name = threshold.name
            db.session.delete(threshold)
            
            # Log to security log
            security_log = SecurityLog()
            security_log.event_type = EventType.CONFIG_CHANGE
            security_log.user_id = current_user.id
            security_log.description = f"Deleted alert threshold: {name}"
            db.session.add(security_log)
            
            db.session.commit()
            flash(f'Alert threshold "{name}" deleted successfully', 'success')
            return redirect(url_for('alert_thresholds'))
    
    # Get all thresholds with related assets and vessels
    thresholds = AlertThreshold.query.all()
    vessels = Vessel.query.all()
    assets = CBSAsset.query.all()
    
    # Define available metric types
    metric_types = [
        'cpu_usage',
        'memory_usage',
        'disk_usage',
        'network_in',
        'network_out',
        'packet_loss',
        'response_time',
        'uptime'
    ]
    
    # Define available comparison operators
    comparison_operators = [
        ('>', 'Greater than'),
        ('>=', 'Greater than or equal to'),
        ('<', 'Less than'),
        ('<=', 'Less than or equal to'),
        ('==', 'Equal to')
    ]
    
    return render_template('alert_thresholds.html',
                          thresholds=thresholds,
                          vessels=vessels,
                          assets=assets,
                          metric_types=metric_types,
                          comparison_operators=comparison_operators)


@app.route('/notifications', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def notification_settings():
    """Email and other notification settings"""
    # Handle form submission
    if request.method == 'POST':
        if 'add_notification' in request.form:
            # Add new notification setting
            name = request.form.get('name')
            description = request.form.get('description', '')
            notification_type = request.form.get('notification_type')
            recipient = request.form.get('recipient')
            severity_filter = request.form.get('severity_filter', '')
            
            if not name or not notification_type or not recipient:
                flash('All required fields must be filled out', 'danger')
            else:
                setting = NotificationSetting()
                setting.name = name
                setting.description = description
                setting.notification_type = notification_type
                setting.recipient = recipient
                setting.severity_filter = severity_filter
                
                db.session.add(setting)
                
                # Log to security log
                security_log = SecurityLog()
                security_log.event_type = EventType.CONFIG_CHANGE
                security_log.user_id = current_user.id
                security_log.description = f"Created notification setting: {name}"
                db.session.add(security_log)
                
                db.session.commit()
                flash(f'Notification setting "{name}" added successfully', 'success')
                return redirect(url_for('notification_settings'))
        
        elif 'edit_notification' in request.form:
            # Edit existing notification setting
            setting_id = request.form.get('setting_id', type=int)
            setting = NotificationSetting.query.get_or_404(setting_id)
            
            setting.name = request.form.get('name')
            setting.description = request.form.get('description', '')
            setting.notification_type = request.form.get('notification_type')
            setting.recipient = request.form.get('recipient')
            setting.severity_filter = request.form.get('severity_filter', '')
            setting.enabled = 'enabled' in request.form
            
            # Log to security log
            security_log = SecurityLog()
            security_log.event_type = EventType.CONFIG_CHANGE
            security_log.user_id = current_user.id
            security_log.description = f"Updated notification setting: {setting.name}"
            db.session.add(security_log)
            
            db.session.commit()
            flash(f'Notification setting "{setting.name}" updated successfully', 'success')
            return redirect(url_for('notification_settings'))
        
        elif 'delete_notification' in request.form:
            # Delete notification setting
            setting_id = request.form.get('setting_id', type=int)
            setting = NotificationSetting.query.get_or_404(setting_id)
            
            name = setting.name
            db.session.delete(setting)
            
            # Log to security log
            security_log = SecurityLog()
            security_log.event_type = EventType.CONFIG_CHANGE
            security_log.user_id = current_user.id
            security_log.description = f"Deleted notification setting: {name}"
            db.session.add(security_log)
            
            db.session.commit()
            flash(f'Notification setting "{name}" deleted successfully', 'success')
            return redirect(url_for('notification_settings'))
    
    # Get all notification settings
    settings = NotificationSetting.query.all()
    
    # Define available notification types
    notification_types = [
        ('email', 'Email'),
        # Add more notification types as they are implemented
        # ('sms', 'SMS'),
        # ('webhook', 'Webhook')
    ]
    
    # Get severity levels for dropdown
    severity_levels = [s.value for s in AlertSeverity]
    
    return render_template('notification_settings.html',
                          settings=settings,
                          notification_types=notification_types,
                          severity_levels=severity_levels)


@app.route('/admin')
@login_required
@role_required([UserRole.ADMINISTRATOR])
def admin():
    """Admin panel for system configuration (admin only)"""
    return render_template('admin.html')

@app.route('/api/docs')
@login_required
def api_documentation():
    """API documentation page"""
    return render_template('api_documentation.html')


@app.route('/documentation')
@login_required
def documentation():
    """Documentation page for SDLC and system reference"""
    return render_template('documentation.html')
