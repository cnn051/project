"""
Translations module for Maritime Network Management System
Handles multi-language support (Korean/English)
"""

# Translations dictionary - organized by pages/sections
translations = {
    # Common UI elements
    'common': {
        'dashboard': {
            'en': 'Dashboard',
            'ko': '대시보드'
        },
        'assets': {
            'en': 'Assets',
            'ko': '자산 목록'
        },
        'security_zones': {
            'en': 'Security Zones',
            'ko': '보안 구역'
        },
        'alerts': {
            'en': 'Alerts',
            'ko': '알림'
        },
        'network_scanner': {
            'en': 'Network Scanner',
            'ko': '네트워크 스캐너'
        },
        'security_logs': {
            'en': 'Security Logs',
            'ko': '보안 로그'
        },
        'admin_panel': {
            'en': 'Admin Panel',
            'ko': '관리자 패널'
        },
        'change_password': {
            'en': 'Change Password',
            'ko': '비밀번호 변경'
        },
        'login': {
            'en': 'Login',
            'ko': '로그인'
        },
        'logout': {
            'en': 'Logout',
            'ko': '로그아웃'
        },
        'documentation': {
            'en': 'Documentation',
            'ko': '문서'
        },
        'save': {
            'en': 'Save',
            'ko': '저장'
        },
        'cancel': {
            'en': 'Cancel',
            'ko': '취소'
        },
        'delete': {
            'en': 'Delete',
            'ko': '삭제'
        },
        'edit': {
            'en': 'Edit',
            'ko': '편집'
        },
        'add': {
            'en': 'Add',
            'ko': '추가'
        },
        'view': {
            'en': 'View',
            'ko': '보기'
        },
        'search': {
            'en': 'Search',
            'ko': '검색'
        },
        'filter': {
            'en': 'Filter',
            'ko': '필터'
        },
        'status': {
            'en': 'Status',
            'ko': '상태'
        }
    },
    
    # Login page
    'login': {
        'title': {
            'en': 'Login to Maritime NMS',
            'ko': '해양 NMS 로그인'
        },
        'username': {
            'en': 'Username',
            'ko': '사용자 이름'
        },
        'password': {
            'en': 'Password',
            'ko': '비밀번호'
        },
        'remember_me': {
            'en': 'Remember me',
            'ko': '로그인 상태 유지'
        },
        'submit': {
            'en': 'Login',
            'ko': '로그인'
        },
        'failed': {
            'en': 'Invalid username or password',
            'ko': '사용자 이름 또는 비밀번호가 잘못되었습니다'
        }
    },
    
    # Dashboard page
    'dashboard': {
        'title': {
            'en': 'System Dashboard',
            'ko': '시스템 대시보드'
        },
        'vessel_overview': {
            'en': 'Vessel Overview',
            'ko': '선박 개요'
        },
        'alert_summary': {
            'en': 'Alert Summary',
            'ko': '알림 요약'
        },
        'recent_alerts': {
            'en': 'Recent Alerts',
            'ko': '최근 알림'
        },
        'security_status': {
            'en': 'Security Status',
            'ko': '보안 상태'
        },
        'system_health': {
            'en': 'System Health',
            'ko': '시스템 상태'
        },
        'no_vessels': {
            'en': 'No vessels configured',
            'ko': '구성된 선박이 없습니다'
        },
        'no_alerts': {
            'en': 'No alerts to display',
            'ko': '표시할 알림이 없습니다'
        }
    },
    
    # Assets page
    'assets': {
        'title': {
            'en': 'CBS Asset Inventory',
            'ko': 'CBS 자산 인벤토리'
        },
        'add_asset': {
            'en': 'Add New Asset',
            'ko': '새 자산 추가'
        },
        'asset_details': {
            'en': 'Asset Details',
            'ko': '자산 세부정보'
        },
        'name': {
            'en': 'Name',
            'ko': '이름'
        },
        'function': {
            'en': 'Function',
            'ko': '기능'
        },
        'type': {
            'en': 'Type',
            'ko': '유형'
        },
        'manufacturer': {
            'en': 'Manufacturer',
            'ko': '제조업체'
        },
        'model': {
            'en': 'Model',
            'ko': '모델'
        },
        'serial_number': {
            'en': 'Serial Number',
            'ko': '일련번호'
        },
        'ip_address': {
            'en': 'IP Address',
            'ko': 'IP 주소'
        },
        'mac_address': {
            'en': 'MAC Address',
            'ko': 'MAC 주소'
        },
        'firmware': {
            'en': 'Firmware',
            'ko': '펌웨어'
        },
        'software': {
            'en': 'Software',
            'ko': '소프트웨어'
        },
        'os_type': {
            'en': 'OS Type',
            'ko': 'OS 유형'
        },
        'os_version': {
            'en': 'OS Version',
            'ko': 'OS 버전'
        },
        'location': {
            'en': 'Location',
            'ko': '위치'
        },
        'zone': {
            'en': 'Security Zone',
            'ko': '보안 구역'
        },
        'vessel': {
            'en': 'Vessel',
            'ko': '선박'
        },
        'status': {
            'en': 'Status',
            'ko': '상태'
        },
        'last_scan': {
            'en': 'Last Scan',
            'ko': '마지막 스캔'
        }
    },
    
    # Network Scanner page
    'network_scanner': {
        'title': {
            'en': 'Network Scanner',
            'ko': '네트워크 스캐너'
        },
        'scan_subnet': {
            'en': 'Scan Subnet',
            'ko': '서브넷 스캔'
        },
        'subnet': {
            'en': 'Subnet (CIDR)',
            'ko': '서브넷 (CIDR)'
        },
        'select_vessel': {
            'en': 'Select Vessel',
            'ko': '선박 선택'
        },
        'select_zone': {
            'en': 'Select Security Zone',
            'ko': '보안 구역 선택'
        },
        'start_scan': {
            'en': 'Start Scan',
            'ko': '스캔 시작'
        },
        'scan_results': {
            'en': 'Scan Results',
            'ko': '스캔 결과'
        },
        'ip_address': {
            'en': 'IP Address',
            'ko': 'IP 주소'
        },
        'mac_address': {
            'en': 'MAC Address',
            'ko': 'MAC 주소'
        },
        'hostname': {
            'en': 'Hostname',
            'ko': '호스트명'
        },
        'open_ports': {
            'en': 'Open Ports',
            'ko': '열린 포트'
        },
        'device_type': {
            'en': 'Device Type',
            'ko': '장치 유형'
        },
        'add_to_inventory': {
            'en': 'Add to Inventory',
            'ko': '인벤토리에 추가'
        },
        'scan_in_progress': {
            'en': 'Scan in progress...',
            'ko': '스캔 진행 중...'
        },
        'scan_complete': {
            'en': 'Scan Complete',
            'ko': '스캔 완료'
        },
        'no_devices': {
            'en': 'No devices found',
            'ko': '장치를 찾을 수 없습니다'
        }
    },
    
    # Security Zones page
    'security_zones': {
        'title': {
            'en': 'Security Zones',
            'ko': '보안 구역'
        },
        'add_zone': {
            'en': 'Add New Zone',
            'ko': '새 구역 추가'
        },
        'zone_details': {
            'en': 'Zone Details',
            'ko': '구역 세부정보'
        },
        'name': {
            'en': 'Name',
            'ko': '이름'
        },
        'description': {
            'en': 'Description',
            'ko': '설명'
        },
        'risk_level': {
            'en': 'Risk Level',
            'ko': '위험 수준'
        },
        'vessel': {
            'en': 'Vessel',
            'ko': '선박'
        },
        'asset_count': {
            'en': 'Asset Count',
            'ko': '자산 수'
        },
        'high_risk': {
            'en': 'High Risk',
            'ko': '높은 위험'
        },
        'medium_risk': {
            'en': 'Medium Risk',
            'ko': '중간 위험'
        },
        'low_risk': {
            'en': 'Low Risk',
            'ko': '낮은 위험'
        }
    },
    
    # Alerts page
    'alerts': {
        'title': {
            'en': 'Security Alerts',
            'ko': '보안 알림'
        },
        'alert_details': {
            'en': 'Alert Details',
            'ko': '알림 세부정보'
        },
        'title_field': {
            'en': 'Title',
            'ko': '제목'
        },
        'message': {
            'en': 'Message',
            'ko': '메시지'
        },
        'severity': {
            'en': 'Severity',
            'ko': '심각도'
        },
        'status': {
            'en': 'Status',
            'ko': '상태'
        },
        'vessel': {
            'en': 'Vessel',
            'ko': '선박'
        },
        'asset': {
            'en': 'Asset',
            'ko': '자산'
        },
        'created_at': {
            'en': 'Created',
            'ko': '생성일'
        },
        'acknowledged_by': {
            'en': 'Acknowledged By',
            'ko': '확인자'
        },
        'resolved_by': {
            'en': 'Resolved By',
            'ko': '해결자'
        },
        'acknowledge': {
            'en': 'Acknowledge',
            'ko': '확인'
        },
        'resolve': {
            'en': 'Resolve',
            'ko': '해결'
        },
        'critical': {
            'en': 'Critical',
            'ko': '심각'
        },
        'high': {
            'en': 'High',
            'ko': '높음'
        },
        'medium': {
            'en': 'Medium',
            'ko': '중간'
        },
        'low': {
            'en': 'Low',
            'ko': '낮음'
        },
        'info': {
            'en': 'Info',
            'ko': '정보'
        },
        'new': {
            'en': 'New',
            'ko': '신규'
        },
        'acknowledged': {
            'en': 'Acknowledged',
            'ko': '확인됨'
        },
        'resolved': {
            'en': 'Resolved',
            'ko': '해결됨'
        },
        'closed': {
            'en': 'Closed',
            'ko': '종료됨'
        }
    },
    
    # Security Logs page
    'security_logs': {
        'title': {
            'en': 'Security Logs',
            'ko': '보안 로그'
        },
        'timestamp': {
            'en': 'Timestamp',
            'ko': '타임스탬프'
        },
        'event_type': {
            'en': 'Event Type',
            'ko': '이벤트 유형'
        },
        'user': {
            'en': 'User',
            'ko': '사용자'
        },
        'vessel': {
            'en': 'Vessel',
            'ko': '선박'
        },
        'asset': {
            'en': 'Asset',
            'ko': '자산'
        },
        'ip_address': {
            'en': 'IP Address',
            'ko': 'IP 주소'
        },
        'description': {
            'en': 'Description',
            'ko': '설명'
        },
        'export': {
            'en': 'Export Logs',
            'ko': '로그 내보내기'
        },
        'filter': {
            'en': 'Filter Logs',
            'ko': '로그 필터링'
        },
        'from_date': {
            'en': 'From Date',
            'ko': '시작일'
        },
        'to_date': {
            'en': 'To Date',
            'ko': '종료일'
        },
        'event_types': {
            'access_control': {
                'en': 'Access Control',
                'ko': '접근 제어'
            },
            'os_event': {
                'en': 'OS Event',
                'ko': 'OS 이벤트'
            },
            'backup_recovery': {
                'en': 'Backup/Recovery',
                'ko': '백업/복구'
            },
            'config_change': {
                'en': 'Config Change',
                'ko': '구성 변경'
            },
            'comm_loss': {
                'en': 'Communication Loss',
                'ko': '통신 손실'
            },
            'security_alarm': {
                'en': 'Security Alarm',
                'ko': '보안 경보'
            },
            'data_integrity': {
                'en': 'Data Integrity',
                'ko': '데이터 무결성'
            },
            'malware_detection': {
                'en': 'Malware Detection',
                'ko': '맬웨어 감지'
            }
        }
    },
    
    # Vessels
    'vessels': {
        'title': {
            'en': 'Vessels',
            'ko': '선박'
        },
        'add_vessel': {
            'en': 'Add New Vessel',
            'ko': '새 선박 추가'
        },
        'vessel_details': {
            'en': 'Vessel Details',
            'ko': '선박 세부정보'
        },
        'name': {
            'en': 'Name',
            'ko': '이름'
        },
        'imo_number': {
            'en': 'IMO Number',
            'ko': 'IMO 번호'
        },
        'call_sign': {
            'en': 'Call Sign',
            'ko': '호출 부호'
        },
        'vessel_type': {
            'en': 'Vessel Type',
            'ko': '선박 유형'
        },
        'built_date': {
            'en': 'Built Date',
            'ko': '건조일'
        },
        'flag': {
            'en': 'Flag',
            'ko': '국적'
        },
        'description': {
            'en': 'Description',
            'ko': '설명'
        }
    },
    
    # Admin Panel
    'admin': {
        'title': {
            'en': 'Admin Panel',
            'ko': '관리자 패널'
        },
        'user_management': {
            'en': 'User Management',
            'ko': '사용자 관리'
        },
        'system_settings': {
            'en': 'System Settings',
            'ko': '시스템 설정'
        },
        'backup': {
            'en': 'Backup & Restore',
            'ko': '백업 및 복원'
        },
        'add_user': {
            'en': 'Add User',
            'ko': '사용자 추가'
        },
        'username': {
            'en': 'Username',
            'ko': '사용자 이름'
        },
        'email': {
            'en': 'Email',
            'ko': '이메일'
        },
        'role': {
            'en': 'Role',
            'ko': '역할'
        },
        'status': {
            'en': 'Status',
            'ko': '상태'
        },
        'last_login': {
            'en': 'Last Login',
            'ko': '마지막 로그인'
        },
        'roles': {
            'administrator': {
                'en': 'Administrator',
                'ko': '관리자'
            },
            'operator': {
                'en': 'Operator',
                'ko': '운영자'
            },
            'read_only': {
                'en': 'Read Only',
                'ko': '읽기 전용'
            }
        }
    },
    
    # Footer
    'footer': {
        'maritime_nms': {
            'en': 'Maritime Network Management System',
            'ko': '해양 네트워크 관리 시스템'
        },
        'tagline': {
            'en': 'A solution for secure maritime cyber asset management',
            'ko': '안전한 해양 사이버 자산 관리를 위한 솔루션'
        }
    }
}

def get_translation(section, key, lang='en'):
    """
    Get a translation for a specific key in a section
    
    Args:
        section (str): The section in the translations dictionary
        key (str): The key within the section
        lang (str): The language code (en/ko)
        
    Returns:
        str: The translated text or the key itself if translation not found
    """
    try:
        return translations[section][key][lang]
    except KeyError:
        # Fallback to nested keys if needed
        try:
            for main_section in translations:
                for subsection in translations[main_section]:
                    if subsection == key:
                        return translations[main_section][subsection][lang]
        except (KeyError, TypeError):
            pass
        
        # Return the key itself if no translation found
        return key