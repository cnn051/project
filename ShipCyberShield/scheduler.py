# scheduler.py

import time
import threading
from simplified_scanner import scan_network
# from models import db, SecurityLog, EventType # db 직접 임포트 제거
from models import SecurityLog, EventType # 모델 클래스만 임포트

# 자동 네트워크 스캔 설정
AUTO_SCAN_INTERVAL_SECONDS = 60
DEFAULT_SCAN_SUBNET = "192.168.1.0/24"

auto_scan_thread = None
stop_event = threading.Event()
_flask_app = None # Flask app 인스턴스를 저장할 변수

def _perform_automatic_network_scan():
    if _flask_app is None:
        print("Scheduler Error: Flask app instance is not set in _perform_automatic_network_scan.")
        # 로깅을 할 수 없으므로 print 사용, 또는 별도 로거 설정 필요
        return

    with _flask_app.app_context():
        # 이제 app 컨텍스트 내에서 models.py를 통해 db에 접근하거나,
        # _flask_app.extensions['sqlalchemy'].db 를 사용합니다.
        # models.py가 'from app import db'를 사용하고 app.db가 올바르게 초기화되었다면,
        # models 모듈을 통해 db 객체를 사용하는 것이 더 일관적일 수 있습니다.
        from models import db as scheduler_db # models 모듈을 통해 db 가져오기

        _flask_app.logger.info("Automatic network scan - Starting scheduled scan.")
        try:
            subnet_to_scan = _flask_app.config.get('AUTO_SCAN_SUBNET', DEFAULT_SCAN_SUBNET)
            # scan_network 함수가 db 작업을 한다면, 해당 함수도 app 컨텍스트를 인지해야 합니다.
            # 또는 scan_network는 순수 스캔 결과만 반환하고, DB 작업은 여기서 처리합니다.
            discovered_devices, added_or_updated_count = scan_network(subnet_to_scan)

            _flask_app.logger.info(f"Automatic network scan - Scan complete on subnet {subnet_to_scan}. "
                                 f"Processed {len(discovered_devices)} devices. "
                                 f"Added/Updated {added_or_updated_count} assets in inventory.")

            log = SecurityLog(
                event_type=EventType.SYSTEM_INFO,
                description=(f"Automatic network scan on {subnet_to_scan} completed. "
                             f"Processed {len(discovered_devices)} devices, "
                             f"{added_or_updated_count} assets added/updated.")
            )
            scheduler_db.session.add(log)
            scheduler_db.session.commit()

        except Exception as e:
            _flask_app.logger.error(f"Automatic network scan - Error during scan on subnet {subnet_to_scan}: {str(e)}")
            if scheduler_db.session.is_active: # 세션이 활성 상태일 때만 롤백 시도
                scheduler_db.session.rollback()
            # 오류 로그 DB 저장 시도 (별도 세션이나 주의 필요)
            try:
                error_log = SecurityLog(
                    event_type=EventType.SYSTEM_INFO, # 또는 WARNING
                    description=f"Automatic network scan on {subnet_to_scan} failed: {str(e)}"
                )
                scheduler_db.session.add(error_log)
                scheduler_db.session.commit()
            except Exception as log_e:
                _flask_app.logger.error(f"Failed to log scan error to DB: {str(log_e)}")


def _automatic_scan_loop():
    if _flask_app:
        _flask_app.logger.info("Starting automatic network scan loop.")
    else:
        # 앱 인스턴스가 아직 설정되지 않았을 수 있으므로 print 사용
        print("Scheduler Loop: Flask app instance not set at loop start. Will wait.")

    while not stop_event.is_set():
        if _flask_app is None: # 앱 인스턴스가 설정될 때까지 대기
            time.sleep(1)
            continue
        _perform_automatic_network_scan()
        stop_event.wait(AUTO_SCAN_INTERVAL_SECONDS) # 다음 스캔까지 대기

    if _flask_app:
        _flask_app.logger.info("Automatic network scan loop stopped.")
    else:
        print("Scheduler Loop: Stopped.")


def start_automatic_network_scan_scheduler(flask_app_instance):
    global auto_scan_thread, _flask_app
    _flask_app = flask_app_instance # Flask app 인스턴스 저장

    if auto_scan_thread is None or not auto_scan_thread.is_alive():
        stop_event.clear()
        auto_scan_thread = threading.Thread(target=_automatic_scan_loop, daemon=True)
        auto_scan_thread.start()
        if _flask_app:
            _flask_app.logger.info("Automatic network scan scheduler started.")
        else: # 로거 사용 불가 시 print
             print("Automatic network scan scheduler started (Flask logger not available at this point).")
        return True

    if _flask_app:
        _flask_app.logger.info("Automatic network scan scheduler is already running.")
    else:
         print("Automatic network scan scheduler is already running (Flask logger not available at this point).")
    return False

def stop_automatic_network_scan_scheduler(flask_app_instance=None):
    global auto_scan_thread
    # 로깅을 위해 app 인스턴스를 사용하되, 없을 경우 _flask_app (전역) 사용
    app_to_log_with = flask_app_instance if flask_app_instance else _flask_app

    if auto_scan_thread and auto_scan_thread.is_alive():
        stop_event.set()
        auto_scan_thread.join(timeout=10) # 스레드 종료 대기 시간 증가
        if auto_scan_thread.is_alive():
            if app_to_log_with:
                app_to_log_with.logger.warning("Automatic network scan thread did not stop in time.")
            else:
                print("Warning: Automatic network scan thread did not stop in time.")
        auto_scan_thread = None
        if app_to_log_with:
            app_to_log_with.logger.info("Automatic network scan scheduler stopped.")
        else:
            print("Automatic network scan scheduler stopped.")
        return True

    if app_to_log_with:
        app_to_log_with.logger.info("Automatic network scan scheduler is not running.")
    else:
        print("Automatic network scan scheduler is not running.")
    return False