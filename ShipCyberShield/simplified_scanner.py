# simplified_scanner.py

import logging
import socket
import ipaddress
import subprocess
import time # time 모듈 임포트 추가
from datetime import datetime # datetime 임포트 추가
from queue import Queue # Queue 임포트 추가
import threading # threading 임포트 추가

# Flask App 컨텍스트 및 DB 관련 모듈 임포트
# 이 파일이 Flask 앱의 일부로 실행될 때 app, db 객체를 올바르게 가져와야 합니다.
# 일반적으로 app.py에서 app = Flask(__name__) 등으로 생성된 app 객체와
# db = SQLAlchemy(app) 등으로 생성된 db 객체를 사용합니다.
# 여기서는 app.py 또는 Flask 앱을 초기화하는 다른 파일에서 해당 객체들이
# export 되어 있다고 가정하고 import 합니다.
# 실제 프로젝트 구조에 맞게 수정이 필요할 수 있습니다.
try:
    from app import app, db
    from models import SecurityZone, CBSAsset, SensorData, EventType, SecurityLog
except ImportError:
    # 테스트 또는 독립 실행 환경을 위한 폴백 (실제 운영에서는 위 import가 성공해야 함)
    logging.warning("Flask app or models could not be imported directly in simplified_scanner.py. DB operations might fail if not run within app context.")
    app = None
    db = None
    SecurityZone = None
    CBSAsset = None
    SensorData = None
    EventType = None
    SecurityLog = None


def ping_host(ip, timeout=0.5): # 기존 함수 유지
    """Simple ping implementation to check if host is alive"""
    try:
        import platform
        system = platform.system().lower()
        if system == 'windows':
            param = '-n'
            timeout_param = '-w'
            timeout_value = str(int(timeout * 1000))
        else:
            param = '-c'
            timeout_param = '-W'
            timeout_value = str(int(timeout))
        command = ['ping', param, '1', timeout_param, timeout_value, str(ip)]
        logging.debug(f"Running ping command: {' '.join(command)}")
        result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        return result
    except Exception as e:
        logging.error(f"Error pinging host {ip}: {str(e)}")
        return False

def scan_port(ip, port, timeout=1): # 기존 함수 유지
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

def port_scan(ip, ports=[22, 23, 80, 443, 161, 502, 8080, 8443]): # 기존 함수 유지
    """Scan common ports on a device"""
    results = {}
    for port in ports:
        results[port] = scan_port(ip, port)
    return results

def identify_device_type(ip, ports_open=None): # 기존 함수 유지 (get_hostname 호출 부분 확인)
    """Attempt to identify device type based on open ports or other characteristics"""
    if not ports_open:
        common_ports = {22, 23, 80, 443, 161, 502, 8080, 8443}
        ports_open = {}
        for port in common_ports:
            ports_open[port] = scan_port(ip, port)
    if ports_open.get(161, False): return "Network Device"
    if ports_open.get(502, False): return "Control System"
    if ports_open.get(80, False) or ports_open.get(443, False): return "Web Server"
    if ports_open.get(22, False): return "Linux/Unix System"
    if ports_open.get(23, False): return "Legacy System"
    if ports_open.get(8080, False) or ports_open.get(8443, False): return "Web Application"

    hostname = get_hostname(ip).lower() # get_hostname 함수가 이 파일 내에 정의되어 있어야 함
    if any(s in hostname for s in ['router', 'gateway', 'switch']): return "Network Device"
    if any(s in hostname for s in ['server', 'srv']): return "Server"
    if any(s in hostname for s in ['printer', 'print']): return "Printer"
    if any(s in hostname for s in ['cam', 'camera', 'cctv']): return "IP Camera"
    if any(s in hostname for s in ['plc', 'controller']): return "Control System"
    return "Unknown Device"

def get_hostname(ip): # 기존 함수 유지
    """Attempt to get hostname for an IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ""

def get_or_create_default_security_zone():
    """기본 보안 영역을 가져오거나 없으면 생성합니다. app 컨텍스트 내에서 호출되어야 합니다."""
    if not app or not db or not SecurityZone: # 모듈 임포트 실패 시
        logging.error("Cannot get/create default zone: Flask app/db/SecurityZone model not initialized.")
        return None

    # SecurityZone 모델이 db.Model을 상속하고, db 객체에 등록되어 있어야 함
    zone = SecurityZone.query.filter_by(name="Default Security Zone").first()
    if not zone:
        # 기존 보안 영역 중 첫 번째 항목 사용 시도 (선박 ID 연결 문제 있을 수 있음)
        # zone = SecurityZone.query.first()
        # if not zone:
        try:
            logging.info("Default Security Zone not found. Creating a new one.")
            zone = SecurityZone(
                name="Default Security Zone",
                description="Automatically created default security zone for scanned devices.",
                risk_level="Medium", # 또는 적절한 기본값
                # vessel_id는 이 함수에서 특정하지 않음.
                # 스캔된 장비가 특정 선박에 속해야 한다면, 해당 선박 ID를 이 zone에 연결하거나,
                # 장비를 추가할 때 선박별 기본 zone을 찾는 로직 필요.
                # 현재는 vessel_id 없이 생성 (SecurityZone 모델에서 vessel_id가 nullable=True여야 함)
            )
            db.session.add(zone)
            db.session.commit()
            app.logger.info("Created default security zone.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating default security zone: {str(e)}")
            return None
    return zone

# 장치 정보를 저장하기 위한 전역 큐 (scan_network 함수 내부로 이동 또는 그대로 사용)
# discovered_devices_queue = Queue() # scan_network 함수 내에서 지역적으로 사용하는 것이 스레드 안전성 면에서 더 나을 수 있음

def add_device_to_inventory(device_info):
    """
    스캔된 장치 정보를 기반으로 CBSAsset을 추가하거나 업데이트합니다.
    새로 추가되거나 정보가 업데이트된 경우 True를 반환하고, 그렇지 않으면 False를 반환합니다.
    이 함수는 Flask 앱 컨텍스트 내에서 호출되어야 합니다.
    """
    if not app or not db or not CBSAsset or not SecurityLog or not EventType: # 모듈 임포트 실패 시
        logging.error("Cannot add/update device to inventory: Flask app/db or models not initialized.")
        return False

    try:
        ip = device_info['ip']
        hostname = device_info.get('hostname', f"Discovered-{ip}")
        device_type = device_info.get('device_type', 'Unknown')
        mac_address = device_info.get('mac')
        current_status = 'online' # 스캔으로 발견되면 일단 'online'
        scan_time = datetime.utcnow()

        existing_asset = CBSAsset.query.filter_by(ip_address=ip).first()
        changed_or_added = False

        if existing_asset:
            # 이미 존재하는 장비: 정보 업데이트
            if existing_asset.name != hostname:
                existing_asset.name = hostname
                changed_or_added = True
            if existing_asset.mac_address != mac_address and mac_address: # MAC 주소가 있고, 기존과 다를 때만 업데이트
                existing_asset.mac_address = mac_address
                changed_or_added = True
            if existing_asset.function != device_type: # 'function' 필드에 장치 유형 저장
                existing_asset.function = device_type
                changed_or_added = True
            if existing_asset.status != current_status:
                existing_asset.status = current_status
                changed_or_added = True

            existing_asset.last_scan = scan_time
            # vessel_id나 security_zone_id는 스캔만으로 변경하지 않는다고 가정.
            # 필요하다면 업데이트 로직 추가.

            if changed_or_added:
                db.session.commit()
                app.logger.info(f"Asset {ip} ('{hostname}') updated. Status: {current_status}, Last scan: {scan_time}")
            else:
                # last_scan 시간만 업데이트 되었을 수 있으므로 커밋은 필요.
                db.session.commit()
                app.logger.info(f"Asset {ip} ('{hostname}') scan time updated. No other changes detected.")
            return changed_or_added # 변경/추가 여부 반환
        else:
            # 새로운 장비: DB에 추가
            default_zone = get_or_create_default_security_zone() # app 컨텍스트 내에서 호출됨
            if not default_zone:
                app.logger.error(f"Failed to add new asset {ip}: Default security zone not found or could not be created.")
                return False

            new_asset = CBSAsset(
                name=hostname,
                ip_address=ip,
                mac_address=mac_address,
                asset_type="Hardware", # 스캔된 장비는 기본적으로 하드웨어로 가정
                function=device_type, # 'function' 필드에 장치 유형 저장
                status=current_status,
                last_scan=scan_time,
                security_zone_id=default_zone.id,
                # protocols 필드는 port_scan 결과 등을 파싱하여 채울 수 있음
                # vessel_id는 default_zone에 연결된 vessel_id를 사용하거나,
                # 또는 스캔 시 특정 vessel_id를 지정받아 사용해야 함.
                # 현재 get_or_create_default_security_zone는 vessel_id를 설정하지 않으므로,
                # SecurityZone 모델에서 vessel_id가 nullable=True이고,
                # CBSAsset 모델에서도 vessel_id가 nullable=True 여야 함. (또는 다른 로직)
                vessel_id=default_zone.vessel_id if hasattr(default_zone, 'vessel_id') else None
            )
            db.session.add(new_asset)
            db.session.commit() # 새 자산 추가 후 ID를 얻기 위해 커밋
            app.logger.info(f"New asset {ip} ('{hostname}') added to inventory in zone '{default_zone.name}'. Asset ID: {new_asset.id}")

            # SecurityLog에 새 장비 발견 기록
            log_description = f"New device discovered and added via scan: {new_asset.name} ({new_asset.ip_address})"
            if new_asset.vessel_id:
                log_description += f" for vessel ID {new_asset.vessel_id}"

            log = SecurityLog(
                event_type=EventType.CONFIG_CHANGE,
                description=log_description,
                cbs_id=new_asset.id,
                vessel_id=new_asset.vessel_id,
                ip_address=new_asset.ip_address # 발견된 장비의 IP를 기록
            )
            db.session.add(log)
            db.session.commit()
            return True # 새로 추가됨
    except Exception as e:
        if db: # db 객체가 초기화 되었다면 롤백 시도
            db.session.rollback()
        logging.error(f"Error in add_device_to_inventory for IP {device_info.get('ip')}: {str(e)}")
        if app and app.logger: # app 객체가 초기화 되었다면 로거 사용
             app.logger.error(f"Error in add_device_to_inventory for IP {device_info.get('ip')}: {str(e)}")
        return False


def scan_worker(ip_list, results_queue, discovered_devices_for_db_queue): # DB 저장을 위한 큐 추가
    """스레드 워커 함수 - 여러 IP를 처리"""
    for ip_str in ip_list:
        if ping_host(ip_str):
            hostname = get_hostname(ip_str)
            # 포트 스캔은 시간이 오래 걸릴 수 있으므로, 자동 스캔에서는 선택적으로 수행하거나 간단한 정보만 수집
            # open_ports = port_scan(ip_str)
            # device_type = identify_device_type(ip_str, open_ports)
            device_type = identify_device_type(ip_str) # 간단 버전

            device_info = {
                'ip': ip_str,
                'hostname': hostname if hostname else f"Device-{ip_str}",
                'device_type': device_type,
                'status': 'online',
                # 'mac': "XX:XX:XX:XX:XX:XX" # MAC 주소 수집 로직 추가 필요 (예: ARP 테이블 파싱)
            }
            results_queue.put(device_info)
            discovered_devices_for_db_queue.put(device_info) # DB 저장을 위해 큐에 추가

            # 로깅은 메인 스레드나 별도 로깅 스레드에서 처리하는 것이 더 효율적일 수 있음
            logging.info(f"Scan worker found device: {ip_str} ({device_type})")


def scan_network(subnet, max_threads=20):
    """
    네트워크 스캔 실행.
    반환값: (발견된 장치 정보 리스트, DB에 새로 추가되거나 업데이트된 장치 수)
    """
    if not app or not db: # Flask app 또는 db 객체가 초기화되지 않았다면 오류 로깅
        logging.error("scan_network called without Flask app/db context.")
        return [], 0

    try:
        logging.info(f"Starting network scan on subnet: {subnet}")
        network = ipaddress.IPv4Network(subnet, strict=False)
        
        results_queue = Queue() # 스캔 결과(UI용)를 위한 큐
        discovered_devices_for_db_queue = Queue() # DB 저장을 위한 장치 정보 큐

        threads = []
        
        hosts_to_scan = [str(ip) for ip in network.hosts()]
        # 개발/테스트 환경에서는 스캔 대상 IP 수를 제한하여 빠르게 테스트 가능
        # if app.debug:
        # hosts_to_scan = hosts_to_scan[:10]

        total_hosts = len(hosts_to_scan)
        logging.info(f"Scanning {total_hosts} hosts in subnet {subnet}")
        
        if total_hosts == 0:
            logging.warning(f"No hosts to scan in subnet {subnet}")
            return [], 0
        
        # 작업을 스레드 수에 맞게 분할
        # 스레드당 최소 1개의 IP는 할당되도록 보장
        chunk_size = (total_hosts + max_threads - 1) // max_threads if total_hosts > 0 else 1
        ip_chunks = [hosts_to_scan[i:i + chunk_size] for i in range(0, total_hosts, chunk_size)]
        
        for chunk in ip_chunks:
            if not chunk: continue # 빈 청크는 건너뜀
            thread = threading.Thread(target=scan_worker, args=(chunk, results_queue, discovered_devices_for_db_queue))
            thread.daemon = True # 메인 프로그램 종료 시 스레드도 함께 종료
            threads.append(thread)
            thread.start()
        
        # 모든 스레드 완료 대기 (타임아웃 설정 가능)
        # 각 스레드의 작업 시간에 따라 전체 스캔 시간이 길어질 수 있으므로 적절한 타임아웃 설정 고려
        # 예: 스레드당 평균 작업 시간 * 스레드 수의 일부
        scan_timeout_per_thread = 15 # 스레드당 최대 15초 대기 (조정 필요)
        for thread in threads:
            thread.join(timeout=scan_timeout_per_thread)

        # 결과 수집 (UI 표시용)
        discovered_devices_for_ui = []
        while not results_queue.empty():
            try:
                discovered_devices_for_ui.append(results_queue.get_nowait())
            except Queue.Empty:
                break
            
        logging.info(f"Scan phase completed. Found {len(discovered_devices_for_ui)} potential devices.")
        
        # 발견된 장치를 자산에 추가/업데이트 (Flask 앱 컨텍스트 내에서 실행되어야 함)
        # 이 부분은 scheduler.py의 _perform_automatic_network_scan 함수에서 app_context와 함께 호출됨
        processed_count = 0
        #Flask 앱 컨텍스트가 scan_network 함수를 호출하는 상위 함수(_perform_automatic_network_scan)에
        #이미 적용되어 있다고 가정하고 add_device_to_inventory를 직접 호출합니다.
        #만약 아니라면, 여기서 with app.app_context(): 를 사용해야 합니다.
        while not discovered_devices_for_db_queue.empty():
            try:
                device_info_for_db = discovered_devices_for_db_queue.get_nowait()
                if add_device_to_inventory(device_info_for_db): # 이 함수는 내부적으로 app 컨텍스트를 사용해야 함
                    processed_count += 1
            except Queue.Empty:
                break
            except Exception as e_db:
                # 개별 장치 DB 처리 중 오류 발생 시 로깅하고 계속 진행
                logging.error(f"Error processing device for DB: {device_info_for_db.get('ip') if device_info_for_db else 'Unknown'}, Error: {str(e_db)}")
        
        logging.info(f"DB processing complete. Added/Updated {processed_count} assets in inventory.")
            
        return discovered_devices_for_ui, processed_count
        
    except ValueError as e:
        error_msg = f"Invalid subnet format: {subnet}. Error: {str(e)}"
        logging.error(error_msg)
        raise ValueError(error_msg) # 오류를 다시 발생시켜 호출한 쪽에서 처리하도록 함
    except Exception as e:
        error_msg = f"Error in network scan for subnet {subnet}: {str(e)}"
        logging.error(error_msg)
        # 프로덕션에서는 상세 오류 메시지 대신 일반 메시지를 반환하고 로깅에 집중할 수 있음
        return [], 0


# collect_device_data 함수는 현재 자동 스캔 로직에서는 직접 사용되지 않지만,
# 개별 자산 폴링 등에 사용될 수 있으므로 유지합니다.
# 만약 자동 스캔 시 더 상세한 정보 수집이 필요하다면 scan_worker 내에서 호출할 수 있습니다.
def collect_device_data(asset):
    """
    Collect data from a device and store in database
    This function should also be called within a Flask app context if it uses db.session or app.logger.
    """
    if not app or not db or not CBSAsset or not SensorData: # 모듈 임포트 실패 시
        logging.error("Cannot collect device data: Flask app/db or models not initialized.")
        return False

    try:
        if not asset.ip_address:
            logging.error(f"Asset {asset.name} has no IP address")
            return False
        
        if ping_host(asset.ip_address): # ping_host는 외부 명령 실행이므로 app 컨텍스트 불필요
            asset.status = "online"
            
            # CPU load simulation (실제 구현에서는 SNMP 등 사용)
            cpu_load = hash(asset.ip_address + str(time.time())) % 100
            
            sensor_data = SensorData(
                cbs_id=asset.id,
                sensor_type="cpu_load", # 예시 센서 타입
                value=float(cpu_load),
                unit="%",
                integrity_verified=True, # 실제 검증 로직 필요
                timestamp=datetime.utcnow(),
                vessel_id=asset.vessel_id # SensorData에 vessel_id 추가
            )
            db.session.add(sensor_data)
            asset.last_scan = datetime.utcnow()
            db.session.commit()
            
            app.logger.info(f"Collected data from {asset.name}: CPU Load {cpu_load}%")
            return True
        else:
            asset.status = "offline"
            asset.last_scan = datetime.utcnow()
            db.session.commit()
            app.logger.warning(f"Device {asset.name} ({asset.ip_address}) is offline")
            return False
            
    except Exception as e:
        if db: db.session.rollback()
        logging.error(f"Error collecting data from {asset.name}: {str(e)}")
        if app and app.logger: app.logger.error(f"Error collecting data from {asset.name}: {str(e)}")
        return False