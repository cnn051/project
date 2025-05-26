"""
Simplified API Endpoints for Network Scanning
"""
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app import db
from models import Vessel, SecurityZone, CBSAsset, UserRole, EventType, SecurityLog
from utils import role_required
from simplified_scanner import scan_network, collect_device_data
import json
import logging
from datetime import datetime

# Create blueprint
bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/security_zones', methods=['GET'])
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

@bp.route('/network_scan', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def network_scan():
    """API endpoint to perform network scan"""
    subnet = request.form.get('subnet')
    scan_type = request.form.get('scan_type')
    vessel_id = request.form.get('vessel_id', type=int)
    zone_id = request.form.get('zone_id', type=int)
    
    if not subnet:
        return jsonify({'error': 'Subnet is required'}), 400
    
    # Log the scan
    log = SecurityLog()
    log.event_type = EventType.CONFIG_CHANGE
    log.user_id = current_user.id
    log.ip_address = request.remote_addr
    log.description = f"Network scan initiated by {current_user.username} on subnet {subnet}"
    db.session.add(log)
    db.session.commit()
    
    # Only add to database if requested and vessel/zone provided
    add_to_db = scan_type == 'discover_and_add' and vessel_id and zone_id
    
    # Perform the network scan
    try:
        discovered_devices, added_count = scan_network(subnet, 
                                                vessel_id if add_to_db else None, 
                                                zone_id if add_to_db else None)
        
        return jsonify({'success': True, 'devices': discovered_devices, 'added_count': added_count})
    except Exception as e:
        logging.error(f"Error during network scan: {str(e)}")
        return jsonify({'error': f'Network scan failed: {str(e)}'}), 500

@bp.route('/add_asset', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def add_asset_from_scan():
    """API endpoint to add asset from scan results"""
    try:
        ip = request.form.get('ip')
        name = request.form.get('name')
        vessel_id = request.form.get('vessel_id', type=int)
        zone_id = request.form.get('zone_id', type=int)
        device_type = request.form.get('device_type', 'Unknown')
        
        if not (ip and name and vessel_id and zone_id):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Check if asset already exists
        existing = CBSAsset.query.filter_by(
            vessel_id=vessel_id,
            ip_address=ip
        ).first()
        
        if existing:
            return jsonify({'success': False, 'error': 'Asset with this IP already exists'}), 400
        
        # Create new asset
        asset = CBSAsset()
        asset.name = name
        asset.vessel_id = vessel_id
        asset.security_zone_id = zone_id
        asset.asset_type = "Hardware"
        asset.physical_location = ip
        asset.ip_address = ip
        asset.function = device_type
        asset.status = "online"
        asset.last_scan = datetime.utcnow()
        
        # Add to database
        db.session.add(asset)
        db.session.commit()
        
        # Log the addition
        log = SecurityLog()
        log.event_type = EventType.CONFIG_CHANGE
        log.user_id = current_user.id
        log.vessel_id = vessel_id
        log.cbs_id = asset.id
        log.ip_address = request.remote_addr
        log.description = f"Asset {name} (IP: {ip}) added by {current_user.username}"
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'asset_id': asset.id})
    except Exception as e:
        logging.error(f"Error adding asset: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/poll_device', methods=['POST'])
@login_required
@role_required([UserRole.ADMINISTRATOR, UserRole.OPERATOR])
def poll_device():
    """API endpoint to poll a device"""
    asset_id = request.form.get('asset_id', type=int)
    
    if not asset_id:
        return jsonify({'error': 'Asset ID is required'}), 400
    
    # Get the asset
    asset = CBSAsset.query.get_or_404(asset_id)
    
    # Poll the device
    success = collect_device_data(asset)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to poll device'}), 500