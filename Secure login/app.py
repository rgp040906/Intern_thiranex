import os
import bcrypt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User, ActivityLog
from forms import RegistrationForm, LoginForm, TwoFactorForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32) # In production use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secure Cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize Extensions
db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"

# Rate Limiter to prevent Brute Force Attacks
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, action, status):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log = ActivityLog(user_id=user_id, action=action, ip_address=ip, status=status)
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash password securely
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        
        # Determine role
        role = 'Admin' if User.query.count() == 0 else 'User'
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password.decode('utf-8'),
            role=role
        )
        db.session.add(user)
        db.session.commit()
        log_activity(user.id, 'Registration', 'Success')
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limiting login attempts
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Check if account is locked
        if user and user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            flash('Account is temporarily locked due to too many failed attempts. Try again later.', 'danger')
            return render_template('login.html', form=form)
        
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Reset failed logins
            user.failed_logins = 0
            user.locked_until = None
            db.session.commit()
            
            if user.two_factor_secret:
                # Require 2FA
                session['pending_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                login_user(user)
                session.permanent = True
                user.last_login = datetime.now(timezone.utc)
                user.last_login_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                db.session.commit()
                log_activity(user.id, 'Login', 'Success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            if user:
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                    log_activity(user.id, 'Account Locked', 'Failed')
                db.session.commit()
                log_activity(user.id, 'Login', 'Failed')
            else:
                log_activity(None, f'Login attempt for {form.email.data}', 'Failed')
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['pending_user_id'])
    if not user:
        return redirect(url_for('login'))
        
    form = TwoFactorForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(form.token.data):
            login_user(user)
            session.permanent = True
            session.pop('pending_user_id', None)
            user.last_login = datetime.now(timezone.utc)
            user.last_login_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            db.session.commit()
            log_activity(user.id, 'Login (2FA)', 'Success')
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_activity(user.id, '2FA Verification', 'Failed')
            flash('Invalid 2FA token. Please try again.', 'danger')
    return render_template('verify_2fa.html', form=form)

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_factor_secret:
        flash('2FA is already set up for your account.', 'info')
        return redirect(url_for('dashboard'))
        
    if 'temp_2fa_secret' not in session:
        session['temp_2fa_secret'] = pyotp.random_base32()
        
    secret = session['temp_2fa_secret']
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="SecureVault")
    
    # Generate QR Code
    img = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        if totp.verify(form.token.data):
            current_user.two_factor_secret = secret
            db.session.commit()
            session.pop('temp_2fa_secret', None)
            log_activity(current_user.id, 'Setup 2FA', 'Success')
            flash('Two-Factor Authentication has been enabled successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid token. Please try again.', 'danger')
            
    return render_template('setup_2fa.html', form=form, qr_code_b64=qr_code_b64, secret=secret)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'Logout', 'Success')
    logout_user()
    flash('You have been logged out safely.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    all_logs = None
    if current_user.role == 'Admin':
        all_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(20).all()
    return render_template('dashboard.html', logs=logs, all_logs=all_logs)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Using HTTPS requires a certificate, for local dev we will run normally but cookies are secure
    app.run(debug=True, port=5000)
