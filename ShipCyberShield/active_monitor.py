"""
Active Monitoring for Maritime Network Management System
Provides continuous monitoring of devices and services via ping and port checks
"""
import subprocess
import socket
import time
import threading
import logging
import datetime
from app import db
from models import CBSAsset, Alert, AlertStatus, AlertSeverity, SecurityLog, EventType

# Dictionary to store monitoring tasks
# Format: {asset_id: {"thread": thread_object, "running": boolean}}
monitoring_tasks = {}

def ping_host(ip_address, count=1, timeout=1):
    """
    Ping a host to check if it's online
    
    Args:
        ip_address (str): Target IP address
        count (int): Number of ping attempts
        timeout (int): Timeout in seconds
        
    Returns:
        tuple: (success, response_time or error message)
    """
    try:
        # Different ping command options based on platform
        ping_params = ['ping']
        
        # Add count parameter
        ping_params.extend(['-c', str(count)])
        
        # Add timeout parameter (in seconds)
        ping_params.extend(['-W', str(timeout)])
        
        # Add target
        ping_params.append(ip_address)
        
        # Execute ping command
        result = subprocess.run(ping_params, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True, 
                               timeout=timeout+1)
        
        # Check if ping was successful (return code 0)
        if result.returncode == 0:
            # Extract response time if possible
            response_time = None
            for line in result.stdout.splitlines():
                if 'time=' in line:
                    try:
                        time_part = line.split('time=')[1].split()[0]
                        response_time = float(time_part)
                        break
                    except (IndexError, ValueError):
                        pass
            
            return True, response_time or 0
        else:
            return False, result.stderr or "Host unreachable"
    
    except subprocess.TimeoutExpired:
        return False, "Ping timed out"
    except Exception as e:
        return False, str(e)

def check_port(ip_address, port, timeout=1):
    """
    Check if a TCP port is open
    
    Args:
        ip_address (str): Target IP address
        port (int): TCP port to check
        timeout (int): Timeout in seconds
        
    Returns:
        tuple: (success, response_time or error message)
    """
    try:
        start_time = time.time()
        
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Attempt to connect
        result = s.connect_ex((ip_address, port))
        response_time = (time.time() - start_time) * 1000  # Convert to ms
        
        # Close socket
        s.close()
        
        if result == 0:
            return True, response_time
        else:
            return False, f"Port {port} is closed"
    
    except socket.timeout:
        return False, "Connection timed out"
    except socket.gaierror:
        return False, "DNS resolution failed"
    except Exception as e:
        return False, str(e)

def handle_status_change(asset, is_online, message=None):
    """
    Handle a change in asset status (online/offline)
    
    Args:
        asset (CBSAsset): The asset that changed status
        is_online (bool): True if asset is now online, False if offline
        message (str): Additional message to include
    """
    old_status = asset.status
    new_status = "online" if is_online else "offline"
    
    # If status has changed, update it and create an alert
    if old_status != new_status:
        asset.status = new_status
        db.session.commit()
        
        # Create appropriate alert
        if is_online:
            # Device came back online
            alert = Alert(
                title=f"Device {asset.name} is back ONLINE",
                message=f"Device {asset.name} ({asset.ip_address}) is now reachable. {message or ''}",
                status=AlertStatus.NEW,
                severity=AlertSeverity.INFO,
                vessel_id=asset.vessel_id,
                cbs_id=asset.id
            )
        else:
            # Device went offline
            alert = Alert(
                title=f"Device {asset.name} is OFFLINE",
                message=f"Device {asset.name} ({asset.ip_address}) is not responding. {message or ''}",
                status=AlertStatus.NEW,
                severity=AlertSeverity.HIGH,
                vessel_id=asset.vessel_id,
                cbs_id=asset.id
            )
        
        db.session.add(alert)
        
        # Log the event
        log = SecurityLog(
            event_type=EventType.COMM_LOSS if not is_online else EventType.OS_EVENT,
            vessel_id=asset.vessel_id,
            cbs_id=asset.id,
            description=f"Device {asset.name} ({asset.ip_address}) status changed from {old_status} to {new_status}"
        )
        db.session.add(log)
        db.session.commit()
        
        logging.info(f"Status change for {asset.name}: {old_status} -> {new_status}")

def monitor_asset(asset_id, interval=60, stop_event=None):
    """
    Continuously monitor an asset at the specified interval
    
    Args:
        asset_id (int): ID of the asset to monitor
        interval (int): Interval between checks in seconds
        stop_event (threading.Event): Event to signal monitoring to stop
    """
    while not stop_event.is_set():
        try:
            # Get the asset
            asset = CBSAsset.query.get(asset_id)
            if not asset or not asset.ip_address:
                logging.error(f"Asset {asset_id} not found or has no IP address")
                time.sleep(interval)
                continue
            
            # Perform ping check
            ping_success, ping_result = ping_host(asset.ip_address)
            
            # Update asset last_scan timestamp
            asset.last_scan = datetime.datetime.utcnow()
            
            # Handle status change based on ping result
            if ping_success:
                # Check any open ports if the ping was successful
                if asset.protocols:
                    # Parse port information from protocols field
                    # Format example: "22 (SSH), 80 (HTTP)"
                    try:
                        port_checks = []
                        port_parts = asset.protocols.split(',')
                        for port_part in port_parts:
                            port_str = port_part.strip().split()[0]
                            port = int(port_str.split('(')[0].strip())
                            port_checks.append(port)
                        
                        # Check each port
                        all_ports_ok = True
                        failed_ports = []
                        
                        for port in port_checks:
                            port_success, port_result = check_port(asset.ip_address, port)
                            if not port_success:
                                all_ports_ok = False
                                failed_ports.append(port)
                        
                        # Device is online, but some services might be down
                        if not all_ports_ok:
                            message = f"Device is reachable but ports {failed_ports} are not responding"
                            handle_status_change(asset, True, message)
                            
                            # Create a warning alert for the service
                            alert = Alert(
                                title=f"Service on port(s) {failed_ports} DOWN on {asset.name}",
                                message=f"Device {asset.name} ({asset.ip_address}) is reachable but service(s) on port(s) {failed_ports} are not responding",
                                status=AlertStatus.NEW,
                                severity=AlertSeverity.MEDIUM,
                                vessel_id=asset.vessel_id,
                                cbs_id=asset.id
                            )
                            db.session.add(alert)
                            db.session.commit()
                            
                        else:
                            # Everything is up and running
                            handle_status_change(asset, True)
                            
                    except (ValueError, IndexError):
                        # Couldn't parse port information, but device is pingable
                        handle_status_change(asset, True)
                else:
                    # No port information, but device is pingable
                    handle_status_change(asset, True)
            else:
                # Ping failed, mark device as offline
                handle_status_change(asset, False, ping_result)
        
        except Exception as e:
            logging.error(f"Error monitoring asset {asset_id}: {str(e)}")
        
        # Wait for the next check
        time.sleep(interval)

def start_monitoring(asset_id, interval=60):
    """
    Start monitoring an asset
    
    Args:
        asset_id (int): ID of the asset to monitor
        interval (int): Interval between checks in seconds
        
    Returns:
        bool: True if monitoring started, False otherwise
    """
    # Check if already monitoring
    if asset_id in monitoring_tasks and monitoring_tasks[asset_id]["running"]:
        return False
    
    # Create stop event
    stop_event = threading.Event()
    
    # Create and start monitoring thread
    monitor_thread = threading.Thread(
        target=monitor_asset,
        args=(asset_id, interval, stop_event),
        daemon=True
    )
    monitor_thread.start()
    
    # Store thread and status
    monitoring_tasks[asset_id] = {
        "thread": monitor_thread,
        "stop_event": stop_event,
        "running": True,
        "interval": interval,
        "start_time": datetime.datetime.utcnow()
    }
    
    logging.info(f"Started monitoring asset {asset_id} at {interval}s intervals")
    return True

def stop_monitoring(asset_id):
    """
    Stop monitoring an asset
    
    Args:
        asset_id (int): ID of the asset to stop monitoring
        
    Returns:
        bool: True if monitoring stopped, False otherwise
    """
    if asset_id not in monitoring_tasks or not monitoring_tasks[asset_id]["running"]:
        return False
    
    # Signal thread to stop
    monitoring_tasks[asset_id]["stop_event"].set()
    monitoring_tasks[asset_id]["running"] = False
    
    logging.info(f"Stopped monitoring asset {asset_id}")
    return True

def get_monitoring_status():
    """
    Get status of all monitoring tasks
    
    Returns:
        dict: Dictionary of all monitoring tasks with status
    """
    result = {}
    
    for asset_id, task in monitoring_tasks.items():
        # Get asset information
        asset = CBSAsset.query.get(asset_id)
        asset_name = asset.name if asset else f"Asset {asset_id}"
        
        result[asset_id] = {
            "asset_name": asset_name,
            "running": task["running"],
            "interval": task["interval"],
            "start_time": task["start_time"].isoformat() if task["running"] else None
        }
    
    return result

def monitor_all_assets(interval=60):
    """
    Start monitoring all assets with IP addresses
    
    Args:
        interval (int): Interval between checks in seconds
        
    Returns:
        dict: Number of assets being monitored by vessel
    """
    assets = CBSAsset.query.filter(CBSAsset.ip_address.isnot(None)).all()
    
    vessel_counts = {}
    for asset in assets:
        # Start monitoring if not already
        if asset.id not in monitoring_tasks or not monitoring_tasks[asset.id]["running"]:
            start_monitoring(asset.id, interval)
            
            # Count by vessel
            if asset.vessel_id not in vessel_counts:
                vessel_counts[asset.vessel_id] = 0
            vessel_counts[asset.vessel_id] += 1
    
    return vessel_counts