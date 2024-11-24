import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import hashlib
import pyotp
import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

db = SQLAlchemy()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    totp_secret = db.Column(db.String(32))
    public_key = db.Column(db.LargeBinary)

    def check_password(self, password):
        return self.password_hash == hash_password(password)

    def generate_totp_qr(self):
        totp = pyotp.TOTP(self.totp_secret)
        provisioning_uri = totp.provisioning_uri(self.username, issuer_name="YourAppName")
        
        # Create QR code image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=5,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create the image from the QR code
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Ensure directory exists
        os.makedirs('static/qr_codes', exist_ok=True)
        
        # Save the image
        qr_path = f'qr_codes/{self.username}_qrcode.png'
        full_path = os.path.join('static', qr_path)
        qr_image.save(full_path)
        
        return qr_path

    def verify_totp(self, otp):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(otp)