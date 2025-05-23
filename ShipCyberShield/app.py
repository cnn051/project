# app.py - Flask application setup with database configuration
import os
import logging
from flask import Flask, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize Flask extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
migrate = Migrate()

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///nms.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)

# Configure login manager
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Log configuration
logging.info(f"Using database: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Import models after db initialization to avoid circular imports
with app.app_context():
    from models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Create all database tables
    db.create_all()
    
    # Register API v1 blueprint
    from api_v1 import api_v1
    app.register_blueprint(api_v1)
    
    # Register SNMP testing blueprint
    from routes_snmp_test import snmp_bp
    app.register_blueprint(snmp_bp)
    
# Language selection middleware
@app.before_request
def before_request():
    # Get language preference from session or query parameter
    if 'lang' in request.args:
        session['lang'] = request.args.get('lang')
    
    # Set default language if not set
    if 'lang' not in session:
        session['lang'] = 'en'  # Default to English
