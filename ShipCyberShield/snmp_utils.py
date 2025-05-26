"""
SNMP Utilities for Maritime Network Management System
Provides functions for SNMP monitoring and data collection from vessels
"""
import logging
from pysnmp.hlapi import *
from app import db
from models import CBSAsset, SensorData, SecurityLog, EventType
from datetime import datetime

# Common SNMP OIDs for maritime systems
SYSTEM_OID = '1.3.6.1.2.1.1'
SYSTEM_NAME_OID = '1.3.6.1.2.1.1.5.0'
SYSTEM_UPTIME_OID = '1.3.6.1.2.1.1.3.0'
SYSTEM_LOCATION_OID = '1.3.6.1.2.1.1.6.0'
SYSTEM_CONTACT_OID = '1.3.6.1.2.1.1.4.0'

# Performance monitoring OIDs (Standard MIB-II OIDs)
# CPU Load
CPU_LOAD_OID = '1.3.6.1.4.1.2021.10.1.3.1'  # UCD-SNMP-MIB::laLoad.1 (1 minute load)
CPU_LOAD_5MIN_OID = '1.3.6.1.4.1.2021.10.1.3.2'  # UCD-SNMP-MIB::laLoad.2 (5 minute load)
CPU_LOAD_15MIN_OID = '1.3.6.1.4.1.2021.10.1.3.3'  # UCD-SNMP-MIB::laLoad.3 (15 minute load)

# Memory
MEMORY_TOTAL_OID = '1.3.6.1.4.1.2021.4.5.0'  # UCD-SNMP-MIB::memTotalReal.0
MEMORY_AVAILABLE_OID = '1.3.6.1.4.1.2021.4.6.0'  # UCD-SNMP-MIB::memAvailReal.0
MEMORY_BUFFER_OID = '1.3.6.1.4.1.2021.4.14.0'  # UCD-SNMP-MIB::memBuffer.0
MEMORY_CACHED_OID = '1.3.6.1.4.1.2021.4.15.0'  # UCD-SNMP-MIB::memCached.0

# Disk usage
DISK_STORAGE_OID = '1.3.6.1.2.1.25.2.3.1'  # HOST-RESOURCES-MIB::hrStorageEntry
DISK_INDEX_OID = '1.3.6.1.2.1.25.2.3.1.1'  # Storage index
DISK_TYPE_OID = '1.3.6.1.2.1.25.2.3.1.2'  # Storage type
DISK_DESC_OID = '1.3.6.1.2.1.25.2.3.1.3'  # Storage descriptor
DISK_ALLOC_OID = '1.3.6.1.2.1.25.2.3.1.4'  # Storage allocation unit
DISK_SIZE_OID = '1.3.6.1.2.1.25.2.3.1.5'  # Storage size
DISK_USED_OID = '1.3.6.1.2.1.25.2.3.1.6'  # Storage used

# Network interfaces
IF_TABLE_OID = '1.3.6.1.2.1.2.2.1'  # ifTable
IF_INDEX_OID = '1.3.6.1.2.1.2.2.1.1'  # ifIndex
IF_DESC_OID = '1.3.6.1.2.1.2.2.1.2'  # ifDescr
IF_TYPE_OID = '1.3.6.1.2.1.2.2.1.3'  # ifType
IF_MTU_OID = '1.3.6.1.2.1.2.2.1.4'  # ifMtu
IF_SPEED_OID = '1.3.6.1.2.1.2.2.1.5'  # ifSpeed
IF_PHYS_ADDR_OID = '1.3.6.1.2.1.2.2.1.6'  # ifPhysAddress
IF_ADMIN_STATUS_OID = '1.3.6.1.2.1.2.2.1.7'  # ifAdminStatus
IF_OPER_STATUS_OID = '1.3.6.1.2.1.2.2.1.8'  # ifOperStatus
IF_IN_OCTETS_OID = '1.3.6.1.2.1.2.2.1.10'  # ifInOctets
IF_OUT_OCTETS_OID = '1.3.6.1.2.1.2.2.1.16'  # ifOutOctets
IF_IN_ERRORS_OID = '1.3.6.1.2.1.2.2.1.14'  # ifInErrors
IF_OUT_ERRORS_OID = '1.3.6.1.2.1.2.2.1.20'  # ifOutErrors

# Marine-specific OIDs (examples, would be replaced with actual vendor OIDs)
MARINE_ENGINE_TEMP_OID = '1.3.6.1.4.1.99999.1.1.1.0'  # Example OID
MARINE_FUEL_LEVEL_OID = '1.3.6.1.4.1.99999.1.1.2.0'   # Example OID
MARINE_GPS_LAT_OID = '1.3.6.1.4.1.99999.1.2.1.0'      # Example OID
MARINE_GPS_LONG_OID = '1.3.6.1.4.1.99999.1.2.2.0'     # Example OID

def get_snmp_data(ip_address, community='public', port=161, oid=SYSTEM_NAME_OID, timeout=1, retries=3):
    """
    Retrieve data from an SNMP agent using GetCmd
    
    Args:
        ip_address (str): Target device IP
        community (str): SNMP community string
        port (int): SNMP port
        oid (str): Object Identifier to query
        timeout (int): Timeout in seconds
        retries (int): Number of retries
        
    Returns:
        tuple: (success, value or error message)
    """
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip_address, port), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        
        if errorIndication:
            logging.error(f"SNMP Error: {errorIndication}")
            return False, str(errorIndication)
        elif errorStatus:
            error_message = f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            logging.error(error_message)
            return False, error_message
        else:
            # Successfully received SNMP data
            for varBind in varBinds:
                return True, varBind[1].prettyPrint()
                
    except Exception as e:
        logging.error(f"Exception during SNMP query: {str(e)}")
        return False, str(e)
    
    return False, "Unknown error"

def snmp_walk(ip_address, community='public', port=161, oid=SYSTEM_OID, timeout=1, retries=3):
    """
    Perform an SNMP walk to retrieve multiple OIDs under a base OID
    
    Args:
        ip_address (str): Target device IP
        community (str): SNMP community string
        port (int): SNMP port
        oid (str): Base Object Identifier to walk
        timeout (int): Timeout in seconds
        retries (int): Number of retries
        
    Returns:
        tuple: (success, list of OID-value pairs or error message)
    """
    result = []
    
    try:
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip_address, port), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
             ):
            
            if errorIndication:
                logging.error(f"SNMP Walk Error: {errorIndication}")
                return False, str(errorIndication)
            elif errorStatus:
                error_message = f"SNMP Walk Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                logging.error(error_message)
                return False, error_message
            else:
                # Successfully received SNMP data
                for varBind in varBinds:
                    result.append((varBind[0].prettyPrint(), varBind[1].prettyPrint()))
                
        return True, result
                
    except Exception as e:
        logging.error(f"Exception during SNMP walk: {str(e)}")
        return False, str(e)
    
    return False, "Unknown error"

def poll_device_snmp(asset, community='public'):
    """
    Poll a CBS asset via SNMP and store the data
    
    Args:
        asset (CBSAsset): The asset to poll
        community (str): SNMP community string
        
    Returns:
        bool: Success or failure
    """
    if not asset.ip_address:
        logging.error(f"Asset {asset.name} (ID: {asset.id}) has no IP address configured")
        return False
    
    # Get system information
    success, system_name = get_snmp_data(asset.ip_address, community, oid=SYSTEM_NAME_OID)
    if not success:
        logging.error(f"Failed to poll {asset.name} (ID: {asset.id}): {system_name}")
        return False
    
    # Log successful connection
    logging.info(f"Successfully polled {asset.name} (ID: {asset.id}), system name: {system_name}")
    
    # Update asset status to online
    asset.status = "online"
    asset.last_scan = datetime.utcnow()
    db.session.commit()
    
    # Poll specific data points and store in SensorData
    data_points = [
        (SYSTEM_UPTIME_OID, "uptime", "seconds"),
        (MARINE_ENGINE_TEMP_OID, "engine_temperature", "celsius"),
        (MARINE_FUEL_LEVEL_OID, "fuel_level", "percentage"),
        (MARINE_GPS_LAT_OID, "gps_latitude", "degrees"),
        (MARINE_GPS_LONG_OID, "gps_longitude", "degrees")
    ]
    
    for oid, sensor_type, unit in data_points:
        success, value = get_snmp_data(asset.ip_address, community, oid=oid)
        if success:
            try:
                # Convert value to float if possible
                float_value = float(value)
                
                # Create sensor data entry
                sensor_data = SensorData()
                sensor_data.vessel_id = asset.vessel_id
                sensor_data.cbs_id = asset.id
                sensor_data.sensor_type = sensor_type
                sensor_data.value = float_value
                sensor_data.unit = unit
                sensor_data.integrity_verified = True
                sensor_data.encryption_status = "none"
                sensor_data.timestamp = datetime.utcnow()
                
                db.session.add(sensor_data)
                db.session.commit()
                
                logging.info(f"Stored {sensor_type} data for {asset.name}: {float_value} {unit}")
            except ValueError:
                logging.warning(f"Could not convert SNMP value to float: {value}")
    
    # Also collect performance metrics
    collect_performance_metrics(asset, community)
    
    return True

def collect_performance_metrics(asset, community='public'):
    """
    Collect performance metrics (CPU, Memory, Disk, Network) from a device using SNMP
    and store as sensor data
    
    Args:
        asset (CBSAsset): The asset to monitor
        community (str): SNMP community string
        
    Returns:
        bool: Success or failure
    """
    if not asset.ip_address:
        logging.error(f"Asset {asset.name} (ID: {asset.id}) has no IP address configured")
        return False
    
    timestamp = datetime.utcnow()
    metrics_collected = False
    
    # 1. CPU Load (1 min, 5 min, 15 min averages)
    cpu_metrics = [
        (CPU_LOAD_OID, "cpu_load_1min", "load"),
        (CPU_LOAD_5MIN_OID, "cpu_load_5min", "load"),
        (CPU_LOAD_15MIN_OID, "cpu_load_15min", "load")
    ]
    
    for oid, sensor_type, unit in cpu_metrics:
        success, value = get_snmp_data(asset.ip_address, community, oid=oid)
        if success:
            try:
                float_value = float(value)
                
                # Create sensor data entry
                sensor_data = SensorData()
                sensor_data.vessel_id = asset.vessel_id
                sensor_data.cbs_id = asset.id
                sensor_data.sensor_type = sensor_type
                sensor_data.value = float_value
                sensor_data.unit = unit
                sensor_data.integrity_verified = True
                sensor_data.encryption_status = "none"
                sensor_data.timestamp = timestamp
                
                db.session.add(sensor_data)
                db.session.commit()
                
                logging.info(f"Stored {sensor_type} for {asset.name}: {float_value}")
                metrics_collected = True
            except ValueError:
                logging.warning(f"Could not convert CPU load value to float: {value}")
    
    # 2. Memory Usage
    success, total_mem = get_snmp_data(asset.ip_address, community, oid=MEMORY_TOTAL_OID)
    success2, avail_mem = get_snmp_data(asset.ip_address, community, oid=MEMORY_AVAILABLE_OID)
    
    if success and success2:
        try:
            total = float(total_mem)
            available = float(avail_mem)
            used = total - available
            percent_used = (used / total) * 100 if total > 0 else 0
            
            # Store memory usage percentage
            sensor_data = SensorData()
            sensor_data.vessel_id = asset.vessel_id
            sensor_data.cbs_id = asset.id
            sensor_data.sensor_type = "memory_usage"
            sensor_data.value = percent_used
            sensor_data.unit = "percent"
            sensor_data.integrity_verified = True
            sensor_data.encryption_status = "none"
            sensor_data.timestamp = timestamp
            
            db.session.add(sensor_data)
            db.session.commit()
            
            logging.info(f"Stored memory usage for {asset.name}: {percent_used:.2f}%")
            metrics_collected = True
            
        except (ValueError, ZeroDivisionError) as e:
            logging.warning(f"Error calculating memory usage: {str(e)}")
    
    # 3. Get network interface statistics using SNMP walk
    success, interfaces = snmp_walk(asset.ip_address, community, oid=IF_DESC_OID)
    
    if success:
        # For each interface, get the in/out octets
        for if_oid, if_name in interfaces:
            # Extract the interface index from the OID
            # The format of the returned OID is typically something like 1.3.6.1.2.1.2.2.1.2.X where X is the interface index
            parts = if_oid.split('.')
            if_index = parts[-1]  # Get the last part which should be the index
            
            # Get input and output octets for this interface
            in_octets_oid = f"{IF_IN_OCTETS_OID}.{if_index}"
            out_octets_oid = f"{IF_OUT_OCTETS_OID}.{if_index}"
            
            success1, in_octets = get_snmp_data(asset.ip_address, community, oid=in_octets_oid)
            success2, out_octets = get_snmp_data(asset.ip_address, community, oid=out_octets_oid)
            
            if success1 and success2:
                try:
                    # Store network in octets
                    sensor_data = SensorData()
                    sensor_data.vessel_id = asset.vessel_id
                    sensor_data.cbs_id = asset.id
                    sensor_data.sensor_type = f"network_in_{if_name.replace(' ', '_')}"
                    sensor_data.value = float(in_octets)
                    sensor_data.unit = "octets"
                    sensor_data.integrity_verified = True
                    sensor_data.encryption_status = "none"
                    sensor_data.timestamp = timestamp
                    
                    db.session.add(sensor_data)
                    
                    # Store network out octets
                    sensor_data = SensorData()
                    sensor_data.vessel_id = asset.vessel_id
                    sensor_data.cbs_id = asset.id
                    sensor_data.sensor_type = f"network_out_{if_name.replace(' ', '_')}"
                    sensor_data.value = float(out_octets)
                    sensor_data.unit = "octets"
                    sensor_data.integrity_verified = True
                    sensor_data.encryption_status = "none"
                    sensor_data.timestamp = timestamp
                    
                    db.session.add(sensor_data)
                    db.session.commit()
                    
                    logging.info(f"Stored network traffic for {asset.name}, interface {if_name}")
                    metrics_collected = True
                except ValueError:
                    logging.warning(f"Could not convert network octets to float")
    
    # 4. Get disk usage using SNMP walk
    success, disks = snmp_walk(asset.ip_address, community, oid=DISK_DESC_OID)
    
    if success:
        for disk_oid, disk_name in disks:
            # Get only disk storage types (skip memory, etc.)
            # Typically, we want to focus on hrStorageFixedDisk (type = .1.3.6.1.2.1.25.2.1.4)
            parts = disk_oid.split('.')
            disk_index = parts[-1]
            
            disk_type_oid = f"{DISK_TYPE_OID}.{disk_index}"
            success_type, disk_type = get_snmp_data(asset.ip_address, community, oid=disk_type_oid)
            
            # Only process fixed disks
            if success_type and disk_type == ".1.3.6.1.2.1.25.2.1.4":
                size_oid = f"{DISK_SIZE_OID}.{disk_index}"
                used_oid = f"{DISK_USED_OID}.{disk_index}"
                alloc_oid = f"{DISK_ALLOC_OID}.{disk_index}"
                
                success1, size = get_snmp_data(asset.ip_address, community, oid=size_oid)
                success2, used = get_snmp_data(asset.ip_address, community, oid=used_oid)
                success3, alloc = get_snmp_data(asset.ip_address, community, oid=alloc_oid)
                
                if success1 and success2 and success3:
                    try:
                        # Calculate total size and used space in bytes
                        total_size = float(size) * float(alloc)
                        used_space = float(used) * float(alloc)
                        
                        # Calculate percentage
                        percent_used = (used_space / total_size) * 100 if total_size > 0 else 0
                        
                        # Store disk usage percentage
                        disk_name_clean = disk_name.replace(' ', '_').replace('/', '_')
                        sensor_data = SensorData()
                        sensor_data.vessel_id = asset.vessel_id
                        sensor_data.cbs_id = asset.id
                        sensor_data.sensor_type = f"disk_usage_{disk_name_clean}"
                        sensor_data.value = percent_used
                        sensor_data.unit = "percent"
                        sensor_data.integrity_verified = True
                        sensor_data.encryption_status = "none"
                        sensor_data.timestamp = timestamp
                        
                        db.session.add(sensor_data)
                        db.session.commit()
                        
                        logging.info(f"Stored disk usage for {asset.name}, disk {disk_name}: {percent_used:.2f}%")
                        metrics_collected = True
                    except (ValueError, ZeroDivisionError) as e:
                        logging.warning(f"Error calculating disk usage: {str(e)}")
    
    return metrics_collected

def start_snmp_discovery(subnet, community='public'):
    """
    Start SNMP discovery on a subnet to find devices
    
    Args:
        subnet (str): Subnet to scan (e.g., "192.168.1.0/24")
        community (str): SNMP community string
        
    Returns:
        list: List of discovered devices with their basic information
    """
    from netaddr import IPNetwork
    import concurrent.futures
    
    discovered_devices = []
    
    def check_device(ip):
        """Check if a device responds to SNMP queries"""
        ip_str = str(ip)
        success, result = get_snmp_data(ip_str, community, oid=SYSTEM_NAME_OID)
        if success:
            device_info = {"ip": ip_str, "name": result}
            
            # Get additional system info
            success, location = get_snmp_data(ip_str, community, oid=SYSTEM_LOCATION_OID)
            if success:
                device_info["location"] = location
                
            success, contact = get_snmp_data(ip_str, community, oid=SYSTEM_CONTACT_OID)
            if success:
                device_info["contact"] = contact
                
            success, uptime = get_snmp_data(ip_str, community, oid=SYSTEM_UPTIME_OID)
            if success:
                device_info["uptime"] = uptime
                
            return device_info
        return None
    
    # Use thread pool to scan IPs in parallel
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            ip_network = IPNetwork(subnet)
            future_to_ip = {executor.submit(check_device, ip): ip for ip in ip_network if ip != ip_network.network and ip != ip_network.broadcast}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    discovered_devices.append(result)
                    logging.info(f"Discovered device: {result['ip']} ({result.get('name', 'Unknown')})")
    
    except Exception as e:
        logging.error(f"Error during SNMP discovery: {str(e)}")
    
    return discovered_devices