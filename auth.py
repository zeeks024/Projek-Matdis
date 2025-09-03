from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from database import db, User, hash_password
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
import pyotp
import random
import os
import smtplib
import base64
import time
from security import (
    rate_limiter, security_logger, PasswordValidator, InputSanitizer,
    SecureSessionManager, CSRFProtection, require_csrf_token, apply_security_headers
)
from encryption import AESCipher, generate_key, encrypt_file, decrypt_file

auth = Blueprint('auth', __name__)

# Store encryption keys securely
user_encryption_keys = {}

def generate_secure_otp():
    """Generate a more secure OTP using cryptographic random."""
    import secrets
    return str(secrets.randbelow(900000) + 100000)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, username):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    os.makedirs('private_keys', exist_ok=True)
    with open(f'private_keys/{username}_private_key.pem', "wb") as key_file:
        key_file.write(pem)

def load_private_key(username):
    with open(f'private_keys/{username}_private_key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def send_otp(receiver_email, otp_code):
    sender_email = "kelmatdis@gmail.com"
    sender_password = "toux xxen ixrn frnx"  # Use app-specific password

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        subject = "Your OTP Code"
        body = (
            f"Dear Pengguna,\n\n"
            f"Untuk melanjutkan proses verifikasi akun Anda, kami memerlukan konfirmasi melalui kode OTP yang telah kami kirimkan.\n\n"
            f"Kode OTP Anda adalah: {otp_code}\n\n"
            f"Kode ini hanya berlaku selama 10 menit. Jangan bagikan kode ini kepada siapa pun.\n\n"
            f"Salam hangat"
        )
        message = f'Subject: {subject}\n\n{body}'

        server.sendmail(sender_email, receiver_email, message)
        print(f"OTP telah dikirim ke {receiver_email}")
        server.quit()
    except Exception as e:
        print(f"Error saat mengirim email: {e}")

@auth.route('/signup', methods=['GET', 'POST'])
@require_csrf_token
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        
        # Input validation
        is_valid_username, username_error = InputSanitizer.validate_username(username)
        if not is_valid_username:
            flash(username_error, 'error')
            security_logger.log_event('invalid_signup_attempt', details=f'Invalid username: {username_error}')
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        is_valid_email, email_error = InputSanitizer.validate_email(email)
        if not is_valid_email:
            flash(email_error, 'error')
            security_logger.log_event('invalid_signup_attempt', details=f'Invalid email: {email_error}')
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        is_valid_password, password_errors = PasswordValidator.validate_password(password)
        if not is_valid_password:
            for error in password_errors:
                flash(error, 'error')
            security_logger.log_event('invalid_signup_attempt', details='Weak password attempt')
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            security_logger.log_event('duplicate_username_attempt', username)
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered', 'error')
            security_logger.log_event('duplicate_email_attempt', details=email)
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())

        # Check rate limiting for OTP requests
        client_ip = request.remote_addr
        if not rate_limiter.can_request_otp(client_ip):
            flash('Please wait before requesting another OTP', 'error')
            return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        # Generate OTP and save it in the session
        session_otp = generate_secure_otp()
        session['session_otp'] = session_otp
        session['signup_data'] = {
            'username': username,
            'password': password,
            'email': email,
            'timestamp': time.time()
        }
        
        # Record OTP request
        rate_limiter.record_otp_request(client_ip)

        # Send OTP to user's email
        send_otp(email, session_otp)
        security_logger.log_event('otp_sent', details=f'OTP sent to {email}')

        # Redirect to the OTP verification page
        return redirect(url_for('auth.signup_otp'))

    return render_template('signup.html', csrf_token=CSRFProtection.generate_csrf_token())

@auth.route('/signup_otp', methods=['GET', 'POST'])
@require_csrf_token
def signup_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        
        # Verify session has signup data
        if 'signup_data' not in session:
            flash('Session expired. Please start signup process again.', 'error')
            return redirect(url_for('auth.signup'))
        
        signup_data = session['signup_data']
        
        # Check if signup data is too old (10 minutes)
        if time.time() - signup_data['timestamp'] > 600:
            session.pop('signup_data', None)
            session.pop('session_otp', None)
            flash('Signup session expired. Please try again.', 'error')
            return redirect(url_for('auth.signup'))

        # Verify OTP
        session_otp = session.get('session_otp')
        if user_otp != session_otp:
            flash('Invalid OTP', 'error')
            security_logger.log_event('invalid_otp_attempt', signup_data['username'])
            return render_template('signup_otp.html', csrf_token=CSRFProtection.generate_csrf_token())

        username = signup_data['username']
        password = signup_data['password']
        email = signup_data['email']

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
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            save_private_key(private_key, username)
            qr_path = new_user.generate_totp_qr()
            
            # Generate encryption key for user
            encryption_key = generate_key(256)
            user_encryption_keys[username] = base64.b64encode(encryption_key).decode()
            
            # Clear session data
            session.pop('signup_data', None)
            session.pop('session_otp', None)
            
            security_logger.log_event('user_registered', username, success=True)
            
            return redirect(url_for('auth.qr_code', qr_path=qr_path))
            
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            security_logger.log_event('registration_failed', username, details=str(e), success=False)
            return render_template('signup_otp.html', csrf_token=CSRFProtection.generate_csrf_token())

    return render_template('signup_otp.html', csrf_token=CSRFProtection.generate_csrf_token())

@auth.route('/qr_code')
def qr_code():
    qr_path = request.args.get('qr_path')
    return render_template('qr_code.html', qr_path=qr_path)

@auth.route('/verify_qr', methods=['POST'])
def verify_qr():
    # Handle the verification logic here
    # For now, we'll just redirect to the dashboard
    return redirect(url_for('dashboard'))

@auth.route('/login', methods=['GET', 'POST'])
@require_csrf_token
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr
        
        # Check if user is locked out
        if rate_limiter.is_locked_out(username):
            remaining_time = rate_limiter.get_lockout_time_remaining(username)
            flash(f'Account locked due to too many failed attempts. Try again in {remaining_time} seconds.', 'error')
            security_logger.log_login_attempt(username, False, 'Account locked')
            return render_template('login.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        # Input validation
        is_valid_username, username_error = InputSanitizer.validate_username(username)
        if not is_valid_username:
            flash('Invalid username format', 'error')
            return render_template('login.html', csrf_token=CSRFProtection.generate_csrf_token())

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Reset failed attempts on successful password verification
            rate_limiter.reset_attempts(username)
            
            # Check rate limiting for OTP requests
            if not rate_limiter.can_request_otp(client_ip):
                flash('Please wait before requesting another OTP', 'error')
                return render_template('login.html', csrf_token=CSRFProtection.generate_csrf_token())
            
            # Generate OTP and save it in the session
            session_otp = generate_secure_otp()
            session['session_otp'] = session_otp
            session['login_username'] = username
            session['login_timestamp'] = time.time()

            # Record OTP request
            rate_limiter.record_otp_request(client_ip)

            # Send OTP to user's email
            send_otp(user.email, session_otp)
            security_logger.log_event('login_otp_sent', username)

            # Redirect to the OTP verification page
            return redirect(url_for('auth.loginotp'))

        else:
            # Record failed attempt
            locked_out = rate_limiter.record_failed_attempt(username)
            if locked_out:
                security_logger.log_account_lockout(username)
                flash('Too many failed attempts. Account locked temporarily.', 'error')
            else:
                flash('Invalid username or password', 'error')
            
            security_logger.log_login_attempt(username, False, 'Invalid credentials')
    
    return render_template('login.html', csrf_token=CSRFProtection.generate_csrf_token())

@auth.route('/loginotp', methods=['GET', 'POST'])
def loginotp():
    if request.method == 'POST':
        username = request.form.get('username')
        user_otp = request.form.get('otp')

        # Verify OTP
        session_otp = session.get('session_otp')
        if user_otp != session_otp:
            flash('Invalid OTP', 'error')
            return redirect(url_for('auth.loginotp', username=username))

        # Redirect to the TOTP verification page
        return redirect(url_for('auth.totpverify', username=username))

    username = request.args.get('username')
    return render_template('loginotp.html', username=username)

@auth.route('/totpverify', methods=['GET', 'POST'])
def totpverify():
    if request.method == 'POST':
        username = request.form.get('username')
        totp_code = request.form.get('totp')

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('User not found', 'error')
            return redirect(url_for('auth.login'))

        # Verify TOTP
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_code):
            login_user(user)
            flash('TOTP verification successful', 'success')
            return redirect(url_for('auth.signmessage'))  # Redirect to signmessage page
        else:
            flash('Invalid TOTP code', 'error')
            return redirect(url_for('auth.totpverify', username=username))

    username = request.args.get('username')
    return render_template('totpverify.html', username=username)

@auth.route('/signmessage', methods=['GET', 'POST'])
@login_required  # Make sure user is logged in
def signmessage():
    if not current_user.is_authenticated:
        flash('Please login first', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        message = request.form.get('message')
        username = current_user.username

        # Load private key
        private_key = load_private_key(username)

        # Sign the message
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Load public key
        public_key = serialization.load_pem_public_key(current_user.public_key)

        # Verify the signature
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            flash('Message signed and verified successfully', 'success')
            return redirect(url_for('auth.menuencrypt'))  # Redirect to menuencrypt page
        except Exception as e:
            flash('Signature verification failed', 'error')
            return redirect(url_for('auth.signmessage'))

    return render_template('signmessage.html')

@auth.route('/menuencrypt', methods=['GET', 'POST'])
@login_required
@require_csrf_token
def menuencrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        action = request.form.get('action')
        
        if not file or file.filename == '':
            flash('No file selected', 'error')
            return render_template('menuencrypt.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        # Validate file size (max 10MB)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            flash('File size too large. Maximum 10MB allowed.', 'error')
            return render_template('menuencrypt.html', csrf_token=CSRFProtection.generate_csrf_token())
        
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join('uploads', current_user.username)
        os.makedirs(uploads_dir, exist_ok=True)
        
        try:
            if action == 'encrypt':
                # Save uploaded file temporarily
                temp_filename = f"temp_{int(time.time())}_{file.filename}"
                temp_path = os.path.join(uploads_dir, temp_filename)
                file.save(temp_path)
                
                # Get or generate encryption key for user
                if current_user.username not in user_encryption_keys:
                    encryption_key = generate_key(256)
                    user_encryption_keys[current_user.username] = base64.b64encode(encryption_key).decode()
                else:
                    encryption_key = base64.b64decode(user_encryption_keys[current_user.username])
                
                # Encrypt file
                encrypted_filename = f"encrypted_{file.filename}.enc"
                encrypted_path = os.path.join(uploads_dir, encrypted_filename)
                encrypt_file(temp_path, encryption_key, encrypted_path)
                
                # Remove temporary file
                os.remove(temp_path)
                
                flash(f'File encrypted successfully as {encrypted_filename}', 'success')
                security_logger.log_event('file_encrypted', current_user.username, details=file.filename)
                
            elif action == 'decrypt':
                # Check if file is encrypted
                if not file.filename.endswith('.enc'):
                    flash('File does not appear to be encrypted', 'error')
                    return render_template('menuencrypt.html', csrf_token=CSRFProtection.generate_csrf_token())
                
                # Save uploaded encrypted file
                encrypted_filename = f"uploaded_{int(time.time())}_{file.filename}"
                encrypted_path = os.path.join(uploads_dir, encrypted_filename)
                file.save(encrypted_path)
                
                # Get encryption key for user
                if current_user.username not in user_encryption_keys:
                    flash('No encryption key found for your account', 'error')
                    os.remove(encrypted_path)
                    return render_template('menuencrypt.html', csrf_token=CSRFProtection.generate_csrf_token())
                
                encryption_key = base64.b64decode(user_encryption_keys[current_user.username])
                
                # Decrypt file
                decrypted_filename = file.filename.replace('.enc', '_decrypted')
                decrypted_path = os.path.join(uploads_dir, decrypted_filename)
                
                try:
                    decrypt_file(encrypted_path, encryption_key, decrypted_path)
                    flash(f'File decrypted successfully as {decrypted_filename}', 'success')
                    security_logger.log_event('file_decrypted', current_user.username, details=file.filename)
                except Exception as e:
                    flash('Failed to decrypt file. Invalid key or corrupted file.', 'error')
                    security_logger.log_event('file_decrypt_failed', current_user.username, details=str(e))
                
                # Remove uploaded encrypted file
                os.remove(encrypted_path)
            
            else:
                flash('Invalid action', 'error')
                
        except Exception as e:
            flash(f'Operation failed: {str(e)}', 'error')
            security_logger.log_event('file_operation_failed', current_user.username, details=str(e))

    return render_template('menuencrypt.html', csrf_token=CSRFProtection.generate_csrf_token())

@auth.route('/logout')
@login_required
def logout():
    security_logger.log_event('user_logout', current_user.username)
    logout_user()
    SecureSessionManager.destroy_session()
    return redirect(url_for('auth.login'))

@auth.route('/api/check-password-strength', methods=['POST'])
def check_password_strength():
    """API endpoint to check password strength."""
    password = request.json.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    score, description = PasswordValidator.calculate_password_strength(password)
    is_valid, errors = PasswordValidator.validate_password(password)
    
    return jsonify({
        'score': score,
        'description': description,
        'is_valid': is_valid,
        'errors': errors
    })

@auth.route('/api/security-status')
@login_required
def security_status():
    """API endpoint to get user's security status."""
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'totp_enabled': bool(current_user.totp_secret),
        'last_login': session.get('login_timestamp', 0),
        'session_expires': session.get('last_activity', 0) + 1800  # 30 minutes
    })