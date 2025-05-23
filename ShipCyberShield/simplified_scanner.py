"""
Simplified Network Scanner for Maritime Network Management System
Provides basic network scanning functionality without external dependencies
"""
import logging
import socket
import ipaddress
import subprocess
import time
from datetime import datetime
from app import db
from models import Vessel, SecurityZone, CBSAsset, SensorData, EventType, SecurityLog
import threading
from queue import Queue

def ping_host(ip, timeout=0.5):
    """Simple ping implementation to check if host is alive"""
    try:
        # 플랫폼 확인
        import platform
        system = platform.system().lower()
        
        # 플랫폼별 ping 명령 조정
        if system == 'windows':
            param = '-n'
            timeout_param = '-w'
            timeout_value = str(int(timeout * 1000))
        else:  # Linux, MacOS
            param = '-c'
            timeout_param = '-W'
            timeout_value = str(int(timeout))
        
        # ping 명령 실행
        command = ['ping', param, '1', timeout_param, timeout_value, str(ip)]
        logging.debug(f"Running ping command: {' '.join(command)}")
        
        result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        return result
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

def port_scan(ip, ports=[22, 23, 80, 443, 161, 502, 8080, 8443]):
    """Scan common ports on a device"""
    results = {}
    for port in ports:
        results[port] = scan_port(ip, port)
    return results

def identify_device_type(ip, ports_open=None):
    """Attempt to identify device type based on open ports or other characteristics"""
    if not ports_open:
        # 기본 포트 스캔 수행
        common_ports = {22, 23, 80, 443, 161, 502, 8080, 8443}
        ports_open = {}
        for port in common_ports:
            ports_open[port] = scan_port(ip, port)
    
    # 포트 기반 장치 유형 식별
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
    elif ports_open.get(8080, False) or ports_open.get(8443, False):  # Alternative HTTP/HTTPS
        return "Web Application"
    
    # 호스트명 기반 추측
    hostname = get_hostname(ip).lower()
    if any(s in hostname for s in ['router', 'gateway', 'switch']):
        return "Network Device"
    elif any(s in hostname for s in ['server', 'srv']):
        return "Server"
    elif any(s in hostname for s in ['printer', 'print']):
        return "Printer"
    elif any(s in hostname for s in ['cam', 'camera', 'cctv']):
        return "IP Camera"
    elif any(s in hostname for s in ['plc', 'controller']):
        return "Control System"
    
    return "Unknown Device"

def get_hostname(ip):
    """Attempt to get hostname for an IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""

def scan_host(ip, results_queue):
    """단일 호스트 스캔"""
    try:
        # 호스트명 확인
        hostname = socket.getfqdn(ip)
        if hostname == ip:
            hostname = f"Discovered Device {ip}"

        # 먼저 ping으로 응답 확인
        if not ping_host(ip):
            # 응답 없는 장비는 저장하지 않음
            return

        # vessel/zone 자동 할당
        vessel = Vessel.query.first()
        zone = SecurityZone.query.first()
        if not vessel or not zone:
            print("No vessel or security zone found in DB.")
            return

        # 이미 존재하는지 확인
        existing = CBSAsset.query.filter_by(ip_address=ip).first()
        if not existing:
            asset = CBSAsset()
            asset.name = hostname
            asset.asset_type = "Hardware"
            asset.physical_location = ip
            asset.ip_address = ip
            asset.function = "Discovered Device"
            asset.status = "online"
            asset.last_scan = datetime.utcnow()
            asset.vessel_id = vessel.id
            asset.security_zone_id = zone.id
            db.session.add(asset)
            db.session.commit()
            # 보안 로그 기록
            log = SecurityLog(
                event_type=EventType.CONFIG_CHANGE,
                description=f"New device discovered: {hostname} ({ip})"
            )
            db.session.add(log)
            db.session.commit()
            print(f"[+] Added device: {hostname} ({ip})")
        else:
            print(f"[-] Device already exists: {ip}")

        # 장치 정보 큐에 추가
        device_info = {
            'ip': ip,
            'hostname': hostname,
            'device_type': 'Unknown',
            'ports': {}
        }
        results_queue.put(device_info)
    except Exception as e:
        print(f"Error scanning {ip}: {str(e)}")

def scan_worker(ip_list, results_queue):
    """스레드 워커 함수 - 여러 IP를 처리"""
    for ip in ip_list:
        # 간단한 ping 체크만 수행
        if ping_host(ip):
            # 기본 정보만 수집
            hostname = get_hostname(ip)
            
            # 장치 유형 식별
            device_type = identify_device_type(ip)
            
            device_info = {
                'ip': ip,
                'hostname': hostname if hostname else f"Device-{ip}",
                'device_type': device_type,
                'status': 'online'
            }
            results_queue.put(device_info)
            print(f"Found device: {ip} ({device_type})")

def scan_network(subnet, max_threads=20):
    """네트워크 스캔 실행"""
    try:
        print(f"Starting network scan on subnet: {subnet}")
        # 서브넷 파싱
        network = ipaddress.IPv4Network(subnet, strict=False)
        
        # 결과를 저장할 큐
        results_queue = Queue()
        threads = []
        
        # 스캔할 IP 주소 목록 (최대 255개로 제한)
        hosts = [str(ip) for ip in list(network.hosts())[:255]]
        total_hosts = len(hosts)
        print(f"Scanning {total_hosts} hosts in subnet {subnet}")
        
        if total_hosts == 0:
            logging.warning(f"No hosts to scan in subnet {subnet}")
            return [], 0
        
        # 작업을 스레드 수에 맞게 분할
        chunk_size = max(1, total_hosts // max_threads)
        ip_chunks = [hosts[i:i + chunk_size] for i in range(0, total_hosts, chunk_size)]
        
        # 각 IP 청크에 대해 스레드 생성
        for chunk in ip_chunks:
            thread = threading.Thread(target=scan_worker, args=(chunk, results_queue))
            thread.daemon = True
            threads.append(thread)
            thread.start()
        
        # 모든 스레드 완료 대기
        for thread in threads:
            thread.join(timeout=10)  # 10초 타임아웃 설정
        
        # 결과 수집
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
            
        print(f"Scan completed. Found {len(results)} devices.")
        return results, len(results)
        
    except ValueError as e:
        error_msg = f"Invalid subnet format: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        raise ValueError(error_msg)
    except Exception as e:
        error_msg = f"Error in network scan: {str(e)}"
        print(error_msg)
        logging.error(error_msg)
        return [], 0

def collect_device_data(asset):
    """
    Collect data from a device and store in database
    
    Args:
        asset (CBSAsset): The asset to collect data from
        
    Returns:
        bool: Success or failure
    """
    try:
        if not asset.ip_address:
            logging.error(f"Asset {asset.name} has no IP address")
            return False
        
        # Check if device is online
        if ping_host(asset.ip_address):
            asset.status = "online"
            
            # Simple data collection - CPU load simulation
            # In a real implementation, you would use SNMP or other protocols
            cpu_load = hash(asset.ip_address + str(time.time())) % 100
            
            # Create sensor data
            sensor_data = SensorData()
            sensor_data.vessel_id = asset.vessel_id
            sensor_data.cbs_id = asset.id
            sensor_data.sensor_type = "cpu_load"
            sensor_data.value = cpu_load
            sensor_data.unit = "%"
            sensor_data.integrity_verified = True
            sensor_data.timestamp = datetime.utcnow()
            
            db.session.add(sensor_data)
            
            # Update last scan time
            asset.last_scan = datetime.utcnow()
            db.session.commit()
            
            logging.info(f"Collected data from {asset.name}: CPU Load {cpu_load}%")
            return True
        else:
            asset.status = "offline"
            asset.last_scan = datetime.utcnow()
            db.session.commit()
            
            logging.warning(f"Device {asset.name} ({asset.ip_address}) is offline")
            return False
            
    except Exception as e:
        logging.error(f"Error collecting data from {asset.name}: {str(e)}")
        return False