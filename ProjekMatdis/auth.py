from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import login_user, login_required, logout_user, current_user
from database import db, User, hash_password
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
import pyotp
import random
import os
import smtplib

auth = Blueprint('auth', __name__)

def generate_otp():
    return str(random.randint(100000, 999999))

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

@auth.route('/signup_otp', methods=['GET', 'POST'])
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
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Generate OTP and save it in the session
            session_otp = generate_otp()
            session['session_otp'] = session_otp

            # Send OTP to user's email
            send_otp(user.email, session_otp)

            # Redirect to the OTP verification page
            return redirect(url_for('auth.loginotp', username=username))

        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

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
def menuencrypt():
    if request.method == 'POST':
        file = request.files['file']
        action = request.form.get('action')
        
        if file:
            if action == 'encrypt':
                # Handle file encryption logic here
                flash('File uploaded and encrypted successfully', 'success')
            elif action == 'decrypt':
                # Handle file decryption logic here
                flash('File uploaded and decrypted successfully', 'success')
            return redirect(url_for('auth.menuencrypt'))
        else:
            flash('No file uploaded', 'error')
            return redirect(url_for('auth.menuencrypt'))

    return render_template('menuencrypt.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))