# MatDis Security Application

A comprehensive security application implementing modern cryptographic techniques and multi-factor authentication for educational purposes.

## 🔐 Features

### Security Implementation
- **Custom AES Encryption**: Full AES-256 implementation from scratch with CBC mode
- **RSA Digital Signatures**: Message signing and verification using RSA cryptography
- **Multi-Factor Authentication (MFA)**:
  - Email OTP verification
  - Time-based One-Time Password (TOTP) using Google Authenticator
- **Advanced Security Measures**:
  - Rate limiting for login attempts
  - CSRF protection on all forms
  - Secure session management
  - Password strength validation
  - Input sanitization and validation
  - Security headers implementation

### Core Functionality
1. **User Registration & Authentication**
   - Secure password policies
   - Email OTP verification
   - TOTP setup with QR codes
   - Account lockout protection

2. **Digital Message Signing**
   - RSA key pair generation
   - Message signing with private keys
   - Signature verification with public keys

3. **File Encryption/Decryption**
   - Custom AES-256-CBC implementation
   - File upload with drag-and-drop interface
   - Secure key management per user
   - Support for files up to 10MB

4. **Security Monitoring**
   - Login attempt logging
   - Security event tracking
   - Real-time password strength checking
   - Session timeout management

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ProjekMatdis
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment**
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set up environment variables**
   Create a `.env` file in the project root:
   ```env
   SECRET_KEY=your-super-secret-key-here
   FLASK_ENV=development
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## 📁 Project Structure

```
ProjekMatdis/
├── app.py                 # Main Flask application
├── auth.py               # Authentication routes and handlers
├── database.py           # Database models and setup
├── encryption.py         # Custom AES implementation
├── security.py           # Security utilities and middleware
├── matdis.py            # Original CLI implementation
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── .env                 # Environment variables (create this)
├── static/
│   ├── css/
│   │   └── styles.css   # CSS styles
│   └── images/
│       └── a.png        # Background image
├── templates/
│   ├── base.html        # Base template
│   ├── dashboard.html   # Main dashboard
│   ├── login.html       # Login page
│   ├── signup.html      # Registration page
│   ├── loginotp.html    # OTP verification
│   ├── signup_otp.html  # Registration OTP
│   ├── totpverify.html  # TOTP verification
│   ├── signmessage.html # Message signing
│   ├── menuencrypt.html # File encryption
│   └── qr_code.html     # TOTP QR code display
├── uploads/             # User file uploads (created automatically)
├── private_keys/        # RSA private keys (created automatically)
└── static/qr_codes/     # TOTP QR codes (created automatically)
```

## 🔧 Configuration

### Email Configuration
Update the email settings in `auth.py`:
```python
sender_email = "your-email@gmail.com"
sender_password = "your-app-specific-password"
```

### Security Settings
Modify security parameters in `security.py`:
- Password policies
- Rate limiting settings
- Session timeout duration
- CSRF protection settings

## 🚀 Usage

### 1. User Registration
1. Navigate to the signup page
2. Enter username, email, and password
3. Verify email with OTP
4. Scan QR code with Google Authenticator
5. Complete registration

### 2. User Login
1. Enter username and password
2. Verify email OTP
3. Enter TOTP code from authenticator app
4. Access dashboard

### 3. Digital Signature
1. Navigate to "Sign Message"
2. Enter your message
3. System signs with your private key
4. Verification is performed automatically

### 4. File Encryption
1. Go to "File Encryption"
2. Upload or drag-drop a file
3. Choose encrypt or decrypt
4. Download the processed file

## 🔒 Security Features Explained

### Custom AES Implementation
- **Algorithm**: AES-256 with CBC mode
- **Key Size**: 256-bit keys for maximum security
- **Initialization Vector**: Random IV for each encryption
- **Padding**: PKCS7 padding for data integrity

### Password Security
- Minimum 8 characters
- Requires uppercase, lowercase, digits, and special characters
- Real-time strength checking
- Protection against common passwords

### Rate Limiting
- Maximum 5 failed login attempts
- 5-minute lockout period
- OTP request cooldown (1 minute)
- Automatic attempt reset on successful login

### Session Security
- 30-minute session timeout
- Secure session tokens
- CSRF token validation
- Session regeneration on login

## 📊 API Endpoints

### Authentication
- `POST /auth/signup` - User registration
- `POST /auth/login` - User login
- `POST /auth/loginotp` - OTP verification
- `POST /auth/totpverify` - TOTP verification
- `GET /auth/logout` - User logout

### Security Features
- `POST /auth/signmessage` - Message signing
- `POST /auth/menuencrypt` - File encryption/decryption
- `POST /auth/api/check-password-strength` - Password validation
- `GET /auth/api/security-status` - Security status

## 🔧 Development

### Adding New Features
1. Create new routes in `auth.py`
2. Add corresponding templates in `templates/`
3. Update security policies in `security.py` if needed
4. Test thoroughly with various inputs

### Security Considerations
- Always validate and sanitize user inputs
- Use CSRF tokens on all forms
- Implement proper error handling
- Log security events for monitoring
- Regular security audits

## 📝 Educational Purpose

This application is designed for educational purposes to demonstrate:
- Modern cryptographic implementations
- Secure web application development
- Multi-factor authentication systems
- Security best practices
- Threat mitigation techniques

**Note**: While this implementation follows security best practices, it's intended for learning and should undergo professional security audit before production use.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add appropriate tests
5. Submit a pull request

## 📄 License

This project is for educational purposes. Please respect cryptographic regulations in your jurisdiction.

## 🔗 Dependencies

- **Flask**: Web framework
- **Flask-SQLAlchemy**: Database ORM
- **Flask-Login**: User session management
- **cryptography**: RSA cryptographic operations
- **pyotp**: TOTP implementation
- **qrcode**: QR code generation
- **Pillow**: Image processing
- **email-validator**: Email validation

## 🚨 Security Notice

This implementation includes:
- Custom cryptographic code for educational purposes
- Security measures designed for demonstration
- Logging and monitoring capabilities

Always consult security professionals for production deployments.
