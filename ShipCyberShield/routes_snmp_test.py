"""
PC 기반 장비를 위한 SNMP 테스트 및 모니터링 기능
Maritime Network Management System
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import logging
from datetime import datetime
import socket
import time

from app import db
from models import CBSAsset, SecurityLog, EventType, SensorData
from snmp_utils import (
    get_snmp_data, 
    snmp_walk, 
    SYSTEM_NAME_OID, 
    SYSTEM_UPTIME_OID, 
    SYSTEM_LOCATION_OID,
    SYSTEM_CONTACT_OID,
    CPU_LOAD_OID,
    CPU_LOAD_5MIN_OID,
    CPU_LOAD_15MIN_OID,
    MEMORY_TOTAL_OID,
    MEMORY_AVAILABLE_OID,
    IF_DESC_OID,
    IF_OPER_STATUS_OID,
    IF_IN_OCTETS_OID,
    IF_OUT_OCTETS_OID
)
from active_monitor import start_monitoring

# SNMP 테스트 블루프린트 생성
snmp_bp = Blueprint('snmp', __name__)

@snmp_bp.route('/snmp/test', methods=['POST'])
@login_required
def test_snmp_connection():
    """
    SNMP 연결 테스트 API 엔드포인트
    
    POST 요청으로 다음 데이터 필요:
    - ip_address: 테스트할 장비의 IP 주소
    - community: SNMP 커뮤니티 문자열 (기본값: 'public')
    - port: SNMP 포트 (기본값: 161)
    - version: SNMP 버전 (기본값: '2c')
    - test_type: 테스트 유형 (basic, resources, network, all)
    - asset_id: (선택) 자산 ID
    """
    data = request.json

    # 필수 파라미터 확인
    if not data or 'ip_address' not in data:
        return jsonify({
            'success': False,
            'message': 'IP 주소가 필요합니다.'
        }), 400
    
    # 파라미터 추출
    ip_address = data.get('ip_address')
    community = data.get('community', 'public')
    port = int(data.get('port', 161))
    version = data.get('version', '2c')
    test_type = data.get('test_type', 'basic')
    asset_id = data.get('asset_id')

    # SNMPv3 설정 (구현 시 추가)
    snmpv3_settings = data.get('snmpv3', {})
    
    # 먼저 기본 연결 테스트 - 시스템 이름 가져오기
    success, system_name = get_snmp_data(
        ip_address=ip_address,
        community=community,
        port=port,
        oid=SYSTEM_NAME_OID
    )
    
    if not success:
        # 연결 실패 로그 기록
        logging.error(f"SNMP 연결 실패: {ip_address} - {system_name}")
        
        # 자산이 지정된 경우 보안 로그에 기록
        if asset_id:
            try:
                asset = CBSAsset.query.get(asset_id)
                if asset:
                    security_log = SecurityLog(
                        user_id=current_user.id,
                        event_type=EventType.SECURITY_WARNING,
                        event_source="SNMP Test",
                        vessel_id=asset.vessel_id,
                        message=f"SNMP 연결 테스트 실패: {asset.name} ({ip_address})",
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(security_log)
                    db.session.commit()
            except Exception as e:
                logging.error(f"보안 로그 기록 실패: {str(e)}")
        
        return jsonify({
            'success': False,
            'message': f'SNMP 연결 실패: {system_name}',
            'ip_address': ip_address
        })
    
    # 응답 데이터 준비
    response_data = {
        'success': True,
        'ip_address': ip_address,
        'system_info': {
            'name': system_name
        }
    }
    
    # 기본 시스템 정보 수집
    _, system_uptime = get_snmp_data(ip_address, community, port=port, oid=SYSTEM_UPTIME_OID)
    _, system_location = get_snmp_data(ip_address, community, port=port, oid=SYSTEM_LOCATION_OID)
    _, system_contact = get_snmp_data(ip_address, community, port=port, oid=SYSTEM_CONTACT_OID)
    
    response_data['system_info']['uptime'] = system_uptime
    response_data['system_info']['location'] = system_location
    response_data['system_info']['contact'] = system_contact
    
    # 추가 테스트 실행 (resources, network, all)
    if test_type in ['resources', 'all']:
        # CPU 및 메모리 정보 수집
        resources = {}
        
        # CPU 부하 (1분)
        _, cpu_load = get_snmp_data(ip_address, community, port=port, oid=CPU_LOAD_OID)
        try:
            resources['cpu_load_1min'] = float(cpu_load)
        except (ValueError, TypeError):
            resources['cpu_load_1min'] = None
        
        # 메모리 사용률 계산
        _, total_mem = get_snmp_data(ip_address, community, port=port, oid=MEMORY_TOTAL_OID)
        _, avail_mem = get_snmp_data(ip_address, community, port=port, oid=MEMORY_AVAILABLE_OID)
        
        try:
            total = float(total_mem)
            available = float(avail_mem)
            if total > 0:
                used = total - available
                memory_usage = (used / total) * 100
                resources['memory_usage'] = round(memory_usage, 2)
            else:
                resources['memory_usage'] = None
        except (ValueError, TypeError):
            resources['memory_usage'] = None
        
        response_data['resources'] = resources
    
    if test_type in ['network', 'all']:
        # 네트워크 인터페이스 정보 수집
        interfaces = []
        
        # 인터페이스 목록 가져오기
        success, if_descriptions = snmp_walk(ip_address, community, port=port, oid=IF_DESC_OID)
        
        if success:
            for if_oid, if_name in if_descriptions:
                # 인터페이스 인덱스 추출
                parts = if_oid.split('.')
                if_index = parts[-1]
                
                # 인터페이스 상태 확인
                _, if_status = get_snmp_data(
                    ip_address, community, port=port,
                    oid=f"{IF_OPER_STATUS_OID}.{if_index}"
                )
                
                # 인터페이스 트래픽 정보
                _, in_octets = get_snmp_data(
                    ip_address, community, port=port,
                    oid=f"{IF_IN_OCTETS_OID}.{if_index}"
                )
                
                _, out_octets = get_snmp_data(
                    ip_address, community, port=port,
                    oid=f"{IF_OUT_OCTETS_OID}.{if_index}"
                )
                
                # 인터페이스 정보 추가
                interface_data = {
                    'name': if_name,
                    'status': 'up' if if_status == '1' else 'down',
                    'in_octets': int(in_octets) if in_octets and in_octets.isdigit() else 0,
                    'out_octets': int(out_octets) if out_octets and out_octets.isdigit() else 0
                }
                
                interfaces.append(interface_data)
            
            response_data['interfaces'] = interfaces
    
    # 자산이 지정된 경우 보안 로그에 기록
    if asset_id:
        try:
            asset = CBSAsset.query.get(asset_id)
            if asset:
                security_log = SecurityLog(
                    user_id=current_user.id,
                    event_type=EventType.SYSTEM_INFO,
                    event_source="SNMP Test",
                    vessel_id=asset.vessel_id,
                    message=f"SNMP 연결 테스트 성공: {asset.name} ({ip_address})",
                    timestamp=datetime.utcnow()
                )
                db.session.add(security_log)
                db.session.commit()
        except Exception as e:
            logging.error(f"보안 로그 기록 실패: {str(e)}")
    
    return jsonify(response_data)

@snmp_bp.route('/snmp/monitor', methods=['POST'])
@login_required
def start_asset_monitoring():
    """
    자산을 능동 모니터링에 추가하는 API 엔드포인트
    
    POST 요청으로 다음 데이터 필요:
    - asset_id: 자산 ID
    - interval: (선택) 모니터링 간격 (초, 기본값: 60)
    """
    data = request.json
    
    if not data or 'asset_id' not in data:
        return jsonify({
            'success': False,
            'message': '자산 ID가 필요합니다.'
        }), 400
    
    asset_id = data.get('asset_id')
    interval = int(data.get('interval', 60))
    
    # 자산 존재 여부 확인
    asset = CBSAsset.query.get(asset_id)
    if not asset:
        return jsonify({
            'success': False,
            'message': '자산을 찾을 수 없습니다.'
        }), 404
    
    # 자산에 IP 주소가 있는지 확인
    if not asset.ip_address:
        return jsonify({
            'success': False,
            'message': '자산에 IP 주소가 없습니다. 모니터링을 위해 IP 주소가 필요합니다.'
        }), 400
    
    # active_monitor 모듈로 모니터링 시작
    result = start_monitoring(asset_id, interval)
    
    if result:
        # 보안 로그에 기록
        security_log = SecurityLog(
            user_id=current_user.id,
            event_type=EventType.SYSTEM_INFO,
            event_source="Active Monitoring",
            vessel_id=asset.vessel_id,
            message=f"모니터링 시작: {asset.name} ({asset.ip_address}), 간격: {interval}초",
            timestamp=datetime.utcnow()
        )
        db.session.add(security_log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{asset.name} 자산의 모니터링이 시작되었습니다.',
            'asset_name': asset.name,
            'interval': interval
        })
    else:
        return jsonify({
            'success': False,
            'message': '모니터링 시작에 실패했습니다. 이미 모니터링 중이거나 시스템 오류가 발생했습니다.'
        }), 500

# 이 모듈을 직접 실행하는 경우 테스트 코드
if __name__ == '__main__':
    # 테스트를 위한 코드 (실제 애플리케이션에서는 실행되지 않음)
    test_ip = '127.0.0.1'  # 로컬 호스트
    
    # 기본 SNMP 테스트
    success, result = get_snmp_data(test_ip)
    print(f"테스트 결과: {success}, {result}")