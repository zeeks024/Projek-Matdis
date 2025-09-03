import random
import hashlib
import sqlite3
import smtplib
from contextlib import closing
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pyotp
import qrcode
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import subprocess

# Load environment variables from a .env file
load_dotenv()

# Koneksi ke database SQLite
def create_connection():
    return sqlite3.connect('mfa_users.db')

# Membuat tabel pengguna jika belum ada
def create_table():
    with create_connection() as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                totp_secret TEXT,
                public_key BLOB
            )
            ''')
            conn.commit()

# Meng-hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Menyimpan data pengguna
def save_user(username, password, email, totp_secret, public_key):
    password_hash = hash_password(password)
    with create_connection() as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('''
            INSERT INTO users (username, password_hash, email, totp_secret, public_key)
            VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, email, totp_secret, public_key))
            conn.commit()

# Mengirim OTP melalui email
def send_otp(receiver_email, otp_code):
    sender_email = "kelmatdis@gmail.com"
    sender_password = "toux xxen ixrn frnx"  # Pastikan menggunakan app-specific password

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

# Generate OTP
def generate_otp():
    return random.randint(100000, 999999)

# Generate a secret key for the user
def generate_secret_key():
    return pyotp.random_base32()

# Generate a QR code for the user to scan with Google Authenticator
def generate_qr_code(secret_key, username):
    totp = pyotp.TOTP(secret_key)
    uri = totp.provisioning_uri(name=username, issuer_name="YourAppName")
    qr = qrcode.make(uri)
    qr_filename = f"{username}_qrcode.png"
    qr.save(qr_filename)
    print(f"QR code generated for {username}. Scan it with Google Authenticator.")
    # Display the QR code
    img = Image.open(qr_filename)
    img.show()

# Verify the TOTP entered by the user
def verify_totp(secret_key, otp):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(otp)

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save private key to a file
def save_private_key(private_key, username):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_private_key.pem", "wb") as key_file:
        key_file.write(pem)

# Load private key from a file
def load_private_key(username):
    with open(f"{username}_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

# Sign a message
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify a signature
def verify_signature(public_key, message, signature):
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
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Verifikasi username dan password, dan mengambil email terkait
def verify_user(username, password):
    password_hash = hash_password(password)
    with create_connection() as conn:
        with closing(conn.cursor()) as cursor:
            cursor.execute('SELECT email, totp_secret, public_key FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
            return cursor.fetchone()

# Autentikasi pengguna dengan MFA menggunakan OTP dan TOTP
def authenticate_user(username, password):
    user = verify_user(username, password)
    if user:
        email, totp_secret, public_key_pem = user
        print("Username and password verified.")

        otp = generate_otp()  # Generate OTP
        otp_generation_time = datetime.now()  # Store OTP generation time
        send_otp(email, otp)  # Send OTP via email

        print(f"OTP sent to {email}. Please enter the OTP:")
        user_otp = input()

        current_time = datetime.now()
        if current_time - otp_generation_time <= timedelta(seconds=90):  # Check if OTP is within the time limit
            if user_otp == str(otp):  # Compare OTP as strings
                print("OTP verified. Please enter the TOTP from your authenticator app:")
                user_totp = input()
                if verify_totp(totp_secret, user_totp):
                    print("TOTP verified. Please enter the message to sign:")
                    message = input()
                    # Load private key from file
                    private_key = load_private_key(username)
                    # Load public key from PEM format
                    public_key = serialization.load_pem_public_key(public_key_pem)
                    signature = sign_message(private_key, message)
                    print(f"Signature: {signature.hex()}")
                    if verify_signature(public_key, message, signature):
                        print("Signature verified. Authentication complete.")
                    else:
                        print("Invalid signature.")
                else:
                    print("Invalid TOTP.")
            else:
                print("Invalid OTP.")
        else:
            print("OTP has expired.")
    else:
        print("Username or password is incorrect.")

# Program Utama
if __name__ == "__main__":
    create_table()

    while True:
        print("1. Login")
        print("2. Sign Up")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            # Autentikasi pengguna
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            authenticate_user(username, password)
        elif choice == '2':
            # Mendaftar pengguna baru
            new_username = input("Enter a new username: ")
            new_password = input("Enter a new password: ")
            new_email = input("Enter your email: ")

            otp = generate_otp()
            otp_generation_time = datetime.now()  # Store OTP generation time
            send_otp(new_email, otp)  # Kirim OTP saat registrasi
            
            print(f"OTP sent to {new_email}. Please enter the OTP to complete registration:")
            user_otp = input()
            
            current_time = datetime.now()
            if current_time - otp_generation_time <= timedelta(seconds=90):  # Check if OTP is within the time limit
                if user_otp == str(otp):
                    secret_key = generate_secret_key()
                    generate_qr_code(secret_key, new_username)
                    private_key, public_key = generate_rsa_key_pair()
                    public_key_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    save_user(new_username, new_password, new_email, secret_key, public_key_pem)
                    save_private_key(private_key, new_username)
                    print("User registered successfully!")
                    print("Scan the QR code with Google Authenticator to set up 2FA.")
                else:
                    print("Invalid OTP. Registration failed.")
            else:
                print("OTP has expired. Registration failed.")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")