"""
Asset Scanner for Maritime Network Management System
Provides network scanning and asset discovery functions
"""
import logging
import os
import json
import socket
import ipaddress
import time
from datetime import datetime
from scapy.all import ARP, Ether, srp
from app import db, app
from models import Vessel, SecurityZone, CBSAsset
from snmp_utils import start_snmp_discovery, get_snmp_data, SYSTEM_OID

def arp_scan(subnet):
    """
    Perform an ARP scan to discover devices on the network
    
    Args:
        subnet (str): Subnet to scan (e.g., "192.168.1.0/24")
        
    Returns:
        list: List of discovered devices with MAC and IP addresses
    """
    # Create ARP request packet
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    try:
        # Send packet and capture response
        logging.info(f"Starting ARP scan on subnet {subnet}")
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Parse response
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
        logging.info(f"ARP scan complete. Found {len(devices)} devices")
        return devices
    except Exception as e:
        logging.error(f"Error during ARP scan: {str(e)}")
        return []

def scan_port(ip, port, timeout=1):
    """
    Check if a specific port is open on the given IP
    
    Args:
        ip (str): IP address to scan
        port (int): Port to check
        timeout (int): Socket timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        sock.close()
        return False

def port_scan(ip, ports=[22, 23, 80, 443, 161, 502, 8080, 8443]):
    """
    Scan common ports on a device
    
    Args:
        ip (str): IP address to scan
        ports (list): List of ports to check
        
    Returns:
        dict: Dictionary with ports as keys and boolean values indicating if open
    """
    results = {}
    for port in ports:
        results[port] = scan_port(ip, port)
    return results

def identify_device_type(ports_open):
    """
    Attempt to identify device type based on open ports
    
    Args:
        ports_open (dict): Results from port_scan
        
    Returns:
        str: Likely device type
    """
    # Simple heuristic rules for device identification
    if ports_open.get(161, False):  # SNMP
        return "Network Device"
    elif ports_open.get(502, False):  # Modbus
        return "Control System"
    elif ports_open.get(80, False) or ports_open.get(443, False):  # HTTP/HTTPS
        return "Web Server"
    elif ports_open.get(22, False):  # SSH
        return "Linux/Unix System"
    elif ports_open.get(23, False):  # Telnet
        return "Legacy System"
    else:
        return "Unknown"

def get_device_hostname(ip):
    """
    Attempt to get hostname for an IP address
    
    Args:
        ip (str): IP address
        
    Returns:
        str: Hostname or empty string if not found
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""

def full_network_scan(subnet, vessel_id=None, zone_id=None):
    """
    Perform a full network scan and device identification
    
    Args:
        subnet (str): Subnet to scan (e.g., "192.168.1.0/24")
        vessel_id (int): Optional vessel ID to associate with discovered assets
        zone_id (int): Optional security zone ID to associate with discovered assets
        
    Returns:
        tuple: (discovered_devices, added_to_database_count)
    """
    logging.info(f"Starting full network scan on {subnet}")
    discovered_devices = []
    added_count = 0
    
    # First do an ARP scan to find live hosts
    arp_results = arp_scan(subnet)
    
    # Next, enhance with SNMP discovery
    snmp_results = start_snmp_discovery(subnet)
    snmp_data = {device['ip']: device for device in snmp_results}
    
    # Process all discovered devices
    for device in arp_results:
        ip = device['ip']
        mac = device['mac']
        
        # Get additional info
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': get_device_hostname(ip)
        }
        
        # Add SNMP data if available
        if ip in snmp_data:
            device_info.update(snmp_data[ip])
        
        # Scan ports
        ports = port_scan(ip)
        device_info['open_ports'] = ports
        
        # Identify device type
        device_info['device_type'] = identify_device_type(ports)
        
        discovered_devices.append(device_info)
        
        # If vessel_id and zone_id are provided, add to database
        if vessel_id and zone_id:
            try:
                with app.app_context():
                    # Check if device already exists
                    existing = CBSAsset.query.filter_by(
                        vessel_id=vessel_id,
                        physical_location=ip
                    ).first()
                    
                    if not existing:
                        # Create new asset
                        asset = CBSAsset()
                        asset.name = device_info.get('name', device_info.get('hostname', f"Discovered Device {ip}"))
                        asset.vessel_id = vessel_id
                        asset.security_zone_id = zone_id
                        asset.asset_type = "Hardware"
                        asset.physical_location = ip
                        asset.protocols = ", ".join([f"Port {p}" for p, is_open in ports.items() if is_open])
                        asset.function = device_info.get('device_type', 'Unknown')
                        
                        # Set additional fields if available
                        if 'mac' in device_info:
                            asset.interfaces = f"MAC: {device_info['mac']}"
                        
                        db.session.add(asset)
                        db.session.commit()
                        added_count += 1
                        logging.info(f"Added new asset: {asset.name} (IP: {ip})")
            except Exception as e:
                logging.error(f"Error adding asset to database: {str(e)}")
    
    logging.info(f"Network scan complete. Discovered {len(discovered_devices)} devices, added {added_count} to database")
    return discovered_devices, added_count

def fingerprint_device(ip, ports_open):
    """
    Attempt to fingerprint a device based on open ports and responses
    
    Args:
        ip (str): IP address to fingerprint
        ports_open (dict): Dict of open ports from port_scan
        
    Returns:
        dict: Device fingerprint information
    """
    fingerprint = {
        'os_type': 'Unknown',
        'os_version': 'Unknown',
        'vendor': 'Unknown',
        'model': 'Unknown',
        'services': []
    }
    
    # Check for HTTP/HTTPS services
    if ports_open.get(80, False) or ports_open.get(443, False):
        port = 443 if ports_open.get(443, False) else 80
        protocol = 'https' if port == 443 else 'http'
        
        try:
            import urllib.request
            import urllib.error
            
            url = f"{protocol}://{ip}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Maritime-NMS Asset Scanner')
            
            try:
                response = urllib.request.urlopen(req, timeout=3)
                headers = response.info()
                
                fingerprint['services'].append({
                    'port': port,
                    'protocol': protocol,
                    'server': headers.get('Server', 'Unknown')
                })
                
                # Try to identify vendor from headers
                server_header = headers.get('Server', '')
                if 'nginx' in server_header.lower():
                    fingerprint['vendor'] = 'Nginx'
                elif 'apache' in server_header.lower():
                    fingerprint['vendor'] = 'Apache'
                elif 'microsoft' in server_header.lower():
                    fingerprint['vendor'] = 'Microsoft'
                    fingerprint['os_type'] = 'Windows'
                
            except urllib.error.URLError:
                fingerprint['services'].append({
                    'port': port,
                    'protocol': protocol,
                    'status': 'Error connecting'
                })
        except Exception as e:
            logging.error(f"Error fingerprinting HTTP service: {str(e)}")
    
    # If SNMP is available, get system information
    if ports_open.get(161, False):
        success, system_data = get_snmp_data(ip, oid=SYSTEM_OID)
        if success:
            fingerprint['services'].append({
                'port': 161,
                'protocol': 'snmp',
                'status': 'Available'
            })
            
            # Parse system data
            if isinstance(system_data, dict):
                fingerprint['os_type'] = system_data.get('sysDescr', 'Unknown')
                fingerprint['vendor'] = system_data.get('sysContact', 'Unknown')
    
    return fingerprint