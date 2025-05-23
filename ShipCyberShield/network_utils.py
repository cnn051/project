"""
Network Utilities for Maritime Network Management System
Provides simple network scanning and monitoring functions
"""
import logging
import socket
import subprocess
import ipaddress
from datetime import datetime
from app import db
from models import CBSAsset, SensorData, SecurityLog, EventType

def ping_host(ip):
    """Simple ping implementation to check if host is alive"""
    try:
        # Using subprocess for cross-platform ping
        param = '-c'  # Linux/macOS
        command = ['ping', param, '1', str(ip)]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        logging.error(f"Error pinging host {ip}: {str(e)}")
        return False

def scan_port(ip, port, timeout=1):
    """Check if a specific port is open on the given IP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        sock.close()
        return False

def scan_common_ports(ip):
    """Scan common ports on a device"""
    common_ports = {
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        161: "SNMP",
        502: "Modbus",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    
    results = {}
    for port, service in common_ports.items():
        is_open = scan_port(ip, port)
        results[port] = {
            "port": port,
            "service": service,
            "is_open": is_open
        }
    
    return results

def identify_device_type(open_ports):
    """Attempt to identify device type based on open ports"""
    # Check if any ports are open
    if not any(port_info["is_open"] for port_info in open_ports.values()):
        return "Unknown (No open ports)"
        
    # Simple heuristic rules for device identification
    if open_ports.get(161, {}).get("is_open", False):
        return "Network Device (SNMP)"
    elif open_ports.get(502, {}).get("is_open", False):  
        return "Control System (Modbus)"
    elif open_ports.get(80, {}).get("is_open", False) or open_ports.get(443, {}).get("is_open", False):
        return "Web Server"
    elif open_ports.get(22, {}).get("is_open", False):
        return "Linux/Unix System"
    elif open_ports.get(23, {}).get("is_open", False):
        return "Legacy System (Telnet)"
    else:
        return "Unknown Device"

def get_hostname(ip):
    """Attempt to get hostname for an IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""

def scan_network(subnet, max_ips=255):
    """
    Scan a network subnet for devices
    
    Args:
        subnet (str): Subnet to scan (e.g., "192.168.1.0/24")
        max_ips (int): Maximum number of IPs to scan
        
    Returns:
        list: List of discovered devices
    """
    discovered_devices = []
    
    try:
        network = ipaddress.ip_network(subnet)
        
        # Limit scan size for performance
        if network.num_addresses > max_ips:
            logging.warning(f"Network {subnet} too large, limiting scan to {max_ips} addresses")
            hosts = list(network.hosts())[:max_ips]
        else:
            hosts = list(network.hosts())
        
        for ip in hosts:
            ip_str = str(ip)
            if ping_host(ip_str):
                hostname = get_hostname(ip_str)
                ports = scan_common_ports(ip_str)
                device_type = identify_device_type(ports)
                
                # Create device info
                device = {
                    "ip": ip_str,
                    "hostname": hostname if hostname else "Unknown",
                    "device_type": device_type,
                    "ports": {p: info for p, info in ports.items() if info["is_open"]}
                }
                
                discovered_devices.append(device)
                logging.info(f"Discovered device: {ip_str} ({hostname or 'Unknown'}) - {device_type}")
                
        return discovered_devices
    
    except Exception as e:
        logging.error(f"Error scanning network: {str(e)}")
        return []

def add_device_to_inventory(device_info, vessel_id, zone_id):
    """
    Add discovered device to the CBS Asset inventory
    
    Args:
        device_info (dict): Device information from scan
        vessel_id (int): ID of the vessel
        zone_id (int): ID of the security zone
        
    Returns:
        tuple: (success, asset_id or error message)
    """
    try:
        ip = device_info["ip"]
        
        # Check if asset already exists
        existing = CBSAsset.query.filter_by(
            vessel_id=vessel_id,
            ip_address=ip
        ).first()
        
        if existing:
            return False, f"Asset with IP {ip} already exists"
        
        # Create new asset
        asset = CBSAsset()
        asset.name = device_info["hostname"] if device_info["hostname"] != "Unknown" else f"Device-{ip}"
        asset.vessel_id = vessel_id
        asset.security_zone_id = zone_id
        asset.asset_type = "Hardware"
        asset.physical_location = ip
        asset.ip_address = ip
        asset.function = device_info["device_type"]
        asset.status = "online"
        asset.last_scan = datetime.utcnow()
        
        # Add ports to protocols field
        if device_info["ports"]:
            port_info = [f"{info['port']} ({info['service']})" for info in device_info["ports"].values()]
            asset.protocols = ", ".join(port_info)
        
        db.session.add(asset)
        db.session.commit()
        
        return True, asset.id
    
    except Exception as e:
        logging.error(f"Error adding device to inventory: {str(e)}")
        return False, str(e)

def poll_device(asset_id):
    """
    Poll a device to check status and collect basic metrics
    
    Args:
        asset_id (int): ID of the asset to poll
        
    Returns:
        tuple: (success, result or error message)
    """
    try:
        # Get the asset
        asset = CBSAsset.query.get(asset_id)
        if not asset:
            return False, "Asset not found"
        
        # Check if device is online
        ip = asset.ip_address
        if not ip:
            return False, "Asset has no IP address"
        
        # Ping the device
        if ping_host(ip):
            asset.status = "online"
            asset.last_scan = datetime.utcnow()
            
            # Simulate collecting metrics
            # In a real implementation, you would use SNMP, HTTP API, or other protocols
            import random
            
            # Add some simulated sensor data
            metrics = [
                {"type": "cpu_usage", "value": random.randint(10, 90), "unit": "%"},
                {"type": "memory_usage", "value": random.randint(20, 80), "unit": "%"},
                {"type": "temperature", "value": random.randint(25, 45), "unit": "°C"}
            ]
            
            # Store the metrics
            for metric in metrics:
                sensor_data = SensorData()
                sensor_data.vessel_id = asset.vessel_id
                sensor_data.cbs_id = asset.id
                sensor_data.sensor_type = metric["type"]
                sensor_data.value = metric["value"]
                sensor_data.unit = metric["unit"]
                sensor_data.integrity_verified = True
                sensor_data.timestamp = datetime.utcnow()
                db.session.add(sensor_data)
            
            db.session.commit()
            
            return True, {"status": "online", "metrics": metrics}
        else:
            asset.status = "offline"
            asset.last_scan = datetime.utcnow()
            db.session.commit()
            
            return False, "Device is offline"
    
    except Exception as e:
        logging.error(f"Error polling device: {str(e)}")
        return False, str(e)