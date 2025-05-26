# app.py
import os
import logging
from flask import Flask, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix
import atexit # 추가

# 1. SQLAlchemy 객체 먼저 생성
class Base(DeclarativeBase):
    pass
db = SQLAlchemy(model_class=Base) # db 객체 생성

# 2. 다른 Flask 확장 객체 생성 (선택적, 필요에 따라 위치 조정 가능)
login_manager = LoginManager()
migrate = Migrate()

# 3. Flask 앱 객체 생성
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# 4. Flask 앱 설정
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///nms.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# 5. 확장들을 앱에 등록 (SQLAlchemy db 객체를 앱과 연결)
db.init_app(app) # 여기가 중요! models.py가 import 되기 전에 app과 연결
migrate.init_app(app, db)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Log configuration
logging.info(f"Using database: {app.config['SQLALCHEMY_DATABASE_URI']}")

# --- 이제 다른 모듈들을 임포트할 수 있습니다 ---
# models.py는 내부적으로 from app import db를 사용하게 됩니다.
# 이 시점에는 app.db가 이미 SQLAlchemy 객체로 정의되어 있고 app과 연결된 상태입니다.
import models # models.py 임포트 (내부적으로 from app import db 사용)
import routes
import auth as auth_module # auth.py 모듈을 auth_module로 가져옴
import api # api.py
from simple_api import bp as simple_api_module_bp # simple_api.py 사용
from api_v1 import api_v1 as api_v1_module_bp # api_v1.py 사용
from routes_snmp_test import snmp_bp as snmp_bp_module_bp # routes_snmp_test.py 사용
from routes import api_bp as routes_api_blueprint # routes.py에서 api_bp 블루프린트 가져오기

# scheduler.py에서 함수 가져오기
from scheduler import start_automatic_network_scan_scheduler, stop_automatic_network_scan_scheduler

# 블루프린트 등록
app.register_blueprint(auth_module.bp)
app.register_blueprint(simple_api_module_bp) # simple_api.py의 블루프린트 등록
app.register_blueprint(api_v1_module_bp)
app.register_blueprint(snmp_bp_module_bp)

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# 앱 컨텍스트 내에서 실행되어야 하는 작업들
with app.app_context():
    # 데이터베이스 테이블 생성 (Flask-Migrate를 사용하면 보통 마이그레이션으로 관리)
    # db.create_all() # 초기 생성 시 또는 개발 중에만 필요할 수 있음

    # 스케줄러 시작 (개발 서버 중복 실행 방지 포함)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        app.logger.info("Attempting to start automatic network scan scheduler from app.py...")
        start_automatic_network_scan_scheduler(app) # app 객체 전달

# 앱 종료 시 스케줄러 중지 등록
atexit.register(lambda: stop_automatic_network_scan_scheduler(app)) # app 객체 전달

# Language selection middleware
@app.before_request
def before_request():
    if 'lang' in request.args:
        session['lang'] = request.args.get('lang')
    if 'lang' not in session:
        session['lang'] = 'en'