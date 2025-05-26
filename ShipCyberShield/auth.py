# auth.py - Authentication routes and functions
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse
from app import db
from models import User, SecurityLog, EventType
from utils import generate_password_hash
from datetime import datetime
import logging
from forms import LoginForm, ChangePasswordForm

# Create blueprint
bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Create login form
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data
        
        # Look up user
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            # Log failed login attempt
            logging.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
            
            # Create security log entry
            log = SecurityLog()
            log.event_type = EventType.ACCESS_CONTROL
            log.ip_address = request.remote_addr
            log.description = f"Failed login attempt for username: {username}"
            db.session.add(log)
            db.session.commit()
            
            if session.get('lang') == 'ko':
                flash('사용자 이름 또는 비밀번호가 잘못되었습니다', 'danger')
            else:
                flash('Invalid username or password', 'danger')
            return render_template('simple_login.html', form=form)
        
        # Check if user is active
        if not user.is_active:
            if session.get('lang') == 'ko':
                flash('이 계정은 비활성화되었습니다', 'danger')
            else:
                flash('This account has been deactivated', 'danger')
            return render_template('simple_login.html', form=form)
        
        # Login successful
        login_user(user, remember=remember)
        
        # Update last login time
        user.last_login = datetime.utcnow()
        
        # Create security log entry for successful login
        log = SecurityLog()
        log.event_type = EventType.ACCESS_CONTROL
        log.user_id = user.id
        log.ip_address = request.remote_addr
        log.description = f"Successful login: {user.username}"
        db.session.add(log)
        db.session.commit()
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('dashboard')
        
        return redirect(next_page)
    
    return render_template('simple_login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    """User logout"""
    # Create security log entry before logout
    log = SecurityLog(
        event_type=EventType.ACCESS_CONTROL,
        user_id=current_user.id,
        ip_address=request.remote_addr,
        description=f"User logout: {current_user.username}"
    )
    db.session.add(log)
    db.session.commit()
    
    # Perform logout
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            if session.get('lang') == 'ko':
                flash('현재 비밀번호가 올바르지 않습니다', 'danger')
            else:
                flash('Current password is incorrect', 'danger')
            return render_template('change_password.html', form=form)
        
        # Set new password
        current_user.set_password(form.new_password.data)
        
        # Log password change
        log = SecurityLog()
        log.event_type = EventType.ACCESS_CONTROL
        log.user_id = current_user.id
        log.ip_address = request.remote_addr
        log.description = f"Password changed for user: {current_user.username}"
        db.session.add(log)
        db.session.commit()
        
        if session.get('lang') == 'ko':
            flash('비밀번호가 성공적으로 업데이트되었습니다', 'success')
        else:
            flash('Password has been updated successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html', form=form)
