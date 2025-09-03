from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from database import db, User, hash_password
from auth import auth
from dotenv import load_dotenv
import os
import pyotp

load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mfa_users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Blueprints
    app.register_blueprint(auth)

    # Main routes
    @app.route('/')
    def index():
        return render_template('login.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')

            # Generate OTP and save it in the session
            session_otp = generate_otp()
            session['session_otp'] = session_otp

            # Send OTP to user's email
            send_otp(email, session_otp)

            # Redirect to the OTP verification page
            return redirect(url_for('auth.signup_otp', username=username, password=password, email=email))

        return render_template('signup.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                # OTP verification
                session_otp = request.form.get('session_otp')
                user_otp = request.form.get('otp')

                if user_otp != session_otp:
                    flash('Invalid OTP', 'error')
                    return redirect(url_for('auth.login'))

                # TOTP verification
                totp_code = request.form.get('totp')
                if user.verify_totp(totp_code):
                    login_user(user)
                    flash('Login successful', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid TOTP', 'error')
            else:
                flash('Invalid username or password', 'error')
        
        # If GET request, generate OTP
        session_otp = generate_otp()
        return render_template('login.html', session_otp=session_otp)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/loginotp', methods=['GET', 'POST'])
    def loginotp():
        if request.method == 'POST':
            otp = request.form.get('otp')
            # Add logic to verify OTP
            return redirect(url_for('dashboard'))
        return render_template('loginotp.html')

    @app.route('/signup_otp', methods=['GET', 'POST'])
    def signup_otp():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            user_otp = request.form.get('otp')

            # Verify OTP
            session_otp = session.get('session_otp')
            if user_otp != session_otp:
                flash('Invalid OTP', 'error')
                return redirect(url_for('auth.signup_otp', username=username, password=password, email=email))

            # Create new user
            secret_key = pyotp.random_base32()
            private_key, public_key = generate_rsa_key_pair()
            
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            new_user = User(
                username=username, 
                password_hash=hash_password(password), 
                email=email, 
                totp_secret=secret_key,
                public_key=public_key_pem
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            save_private_key(private_key, username)
            qr_path = new_user.generate_totp_qr()
            
            return redirect(url_for('auth.qr_code', qr_path=qr_path))

        username = request.args.get('username')
        password = request.args.get('password')
        email = request.args.get('email')
        return render_template('signup_otp.html', username=username, password=password, email=email)

    @app.route('/signmessage', methods=['GET', 'POST'])
    def signmessage():
        if request.method == 'POST':
            message = request.form.get('message')
            # Add logic to handle message
            return redirect(url_for('dashboard'))
        return render_template('signmessage.html')

    @app.route('/totpverify', methods=['GET', 'POST'])
    def totpverify():
        return render_template('totpverify.html')

    @app.route('/qr_code')
    def qr_code():
        qr_path = request.args.get('qr_path')
        return render_template('qr_code.html', qr_path=qr_path)

    @app.route('/verify_qr', methods=['POST'])
    def verify_qr():
        # Handle the verification logic here
        # For now, we'll just redirect to the dashboard
        return redirect(url_for('dashboard'))

    # Create database
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)