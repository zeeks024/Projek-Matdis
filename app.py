from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from database import db, User, hash_password
from auth import auth
from dotenv import load_dotenv
import os
import pyotp
from security import apply_security_headers, SecureSessionManager, CSRFProtection

load_dotenv()

load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key_change_this_in_production')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfa_users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

    # Initialize extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Blueprints
    app.register_blueprint(auth)

    # Security middleware
    @app.after_request
    def after_request(response):
        return apply_security_headers(response)
    
    @app.before_request
    def before_request():
        # Validate session for authenticated users
        if current_user.is_authenticated:
            if not SecureSessionManager.validate_session():
                logout_user()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('auth.login'))

    # Main routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('auth.login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html', 
                             username=current_user.username,
                             csrf_token=CSRFProtection.generate_csrf_token())

    # Create database
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)