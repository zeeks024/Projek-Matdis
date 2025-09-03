"""
Enhanced Security Module for the MFA Application
This module provides additional security features including:
- Rate limiting for login attempts
- Session management improvements
- Input validation and sanitization
- Secure password policies
- Activity logging
"""

import hashlib
import re
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from flask import request, session
import secrets
import string


class SecurityConfig:
    """Security configuration constants."""
    
    # Password policy
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes in seconds
    MAX_OTP_ATTEMPTS = 3
    OTP_COOLDOWN = 60  # 1 minute between OTP requests
    
    # Session security
    SESSION_TIMEOUT = 1800  # 30 minutes
    MAX_CONCURRENT_SESSIONS = 3
    
    # Input validation
    MAX_USERNAME_LENGTH = 50
    MAX_EMAIL_LENGTH = 254
    USERNAME_PATTERN = r'^[a-zA-Z0-9_.-]+$'
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    }


class RateLimiter:
    """Rate limiting functionality to prevent brute force attacks."""
    
    def __init__(self):
        self.attempts = {}
        self.lockouts = {}
        self.otp_requests = {}
    
    def is_locked_out(self, identifier: str) -> bool:
        """Check if an identifier is currently locked out."""
        if identifier in self.lockouts:
            if time.time() < self.lockouts[identifier]:
                return True
            else:
                # Lockout expired, remove it
                del self.lockouts[identifier]
                if identifier in self.attempts:
                    del self.attempts[identifier]
        return False
    
    def record_failed_attempt(self, identifier: str) -> bool:
        """Record a failed login attempt. Returns True if lockout triggered."""
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        # Clean old attempts (older than 1 hour)
        current_time = time.time()
        self.attempts[identifier] = [
            attempt for attempt in self.attempts[identifier]
            if current_time - attempt < 3600
        ]
        
        self.attempts[identifier].append(current_time)
        
        if len(self.attempts[identifier]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
            self.lockouts[identifier] = current_time + SecurityConfig.LOCKOUT_DURATION
            return True
        
        return False
    
    def reset_attempts(self, identifier: str):
        """Reset failed attempts for an identifier."""
        if identifier in self.attempts:
            del self.attempts[identifier]
        if identifier in self.lockouts:
            del self.lockouts[identifier]
    
    def can_request_otp(self, identifier: str) -> bool:
        """Check if an identifier can request a new OTP."""
        if identifier in self.otp_requests:
            last_request = self.otp_requests[identifier]
            if time.time() - last_request < SecurityConfig.OTP_COOLDOWN:
                return False
        return True
    
    def record_otp_request(self, identifier: str):
        """Record an OTP request timestamp."""
        self.otp_requests[identifier] = time.time()
    
    def get_lockout_time_remaining(self, identifier: str) -> int:
        """Get remaining lockout time in seconds."""
        if identifier in self.lockouts:
            remaining = self.lockouts[identifier] - time.time()
            return max(0, int(remaining))
        return 0


class PasswordValidator:
    """Password validation and strength checking."""
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy.
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long")
        
        if len(password) > SecurityConfig.MAX_PASSWORD_LENGTH:
            errors.append(f"Password must be no more than {SecurityConfig.MAX_PASSWORD_LENGTH} characters long")
        
        if SecurityConfig.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if SecurityConfig.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if SecurityConfig.REQUIRE_DIGITS and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if SecurityConfig.REQUIRE_SPECIAL_CHARS:
            if not re.search(f'[{re.escape(SecurityConfig.SPECIAL_CHARS)}]', password):
                errors.append(f"Password must contain at least one special character: {SecurityConfig.SPECIAL_CHARS}")
        
        # Check for common weak patterns
        if password.lower() in ['password', '123456', 'qwerty', 'admin', 'login']:
            errors.append("Password is too common and easily guessable")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def calculate_password_strength(password: str) -> Tuple[int, str]:
        """
        Calculate password strength score (0-100) and description.
        Returns (score, description)
        """
        score = 0
        
        # Length score (max 25 points)
        score += min(25, len(password) * 2)
        
        # Character variety (max 40 points)
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(f'[{re.escape(SecurityConfig.SPECIAL_CHARS)}]', password):
            score += 10
        
        # Pattern complexity (max 35 points)
        unique_chars = len(set(password))
        score += min(15, unique_chars)
        
        # Check for patterns that reduce strength
        if re.search(r'(.)\1{2,}', password):  # Repeating characters
            score -= 10
        if re.search(r'012|123|234|345|456|567|678|789|890', password):  # Sequential numbers
            score -= 10
        if re.search(r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz', password.lower()):  # Sequential letters
            score -= 10
        
        score = max(0, min(100, score))
        
        if score < 30:
            description = "Very Weak"
        elif score < 50:
            description = "Weak"
        elif score < 70:
            description = "Fair"
        elif score < 90:
            description = "Strong"
        else:
            description = "Very Strong"
        
        return score, description


class InputSanitizer:
    """Input validation and sanitization."""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username format and content."""
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) > SecurityConfig.MAX_USERNAME_LENGTH:
            return False, f"Username must be no more than {SecurityConfig.MAX_USERNAME_LENGTH} characters"
        
        if not re.match(SecurityConfig.USERNAME_PATTERN, username):
            return False, "Username can only contain letters, numbers, dots, hyphens, and underscores"
        
        if username.startswith('.') or username.endswith('.'):
            return False, "Username cannot start or end with a dot"
        
        return True, ""
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Validate email format."""
        if not email:
            return False, "Email cannot be empty"
        
        if len(email) > SecurityConfig.MAX_EMAIL_LENGTH:
            return False, f"Email must be no more than {SecurityConfig.MAX_EMAIL_LENGTH} characters"
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        return True, ""
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """Sanitize string input to prevent injection attacks."""
        if not input_str:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        sanitized = sanitized[:max_length]
        
        return sanitized.strip()


class SecurityLogger:
    """Security event logging."""
    
    def __init__(self, log_file: str = 'security.log'):
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else '.', exist_ok=True)
    
    def log_event(self, event_type: str, user_id: str = None, ip_address: str = None, 
                  details: str = None, success: bool = True):
        """Log a security event."""
        timestamp = datetime.utcnow().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address or self._get_client_ip(),
            'user_agent': request.headers.get('User-Agent', '') if request else '',
            'details': details,
            'success': success
        }
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            # Fallback logging if file write fails
            print(f"Failed to write security log: {e}")
    
    def _get_client_ip(self) -> str:
        """Get client IP address from request."""
        if not request:
            return 'unknown'
        
        # Check for forwarded IP first
        if 'X-Forwarded-For' in request.headers:
            return request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif 'X-Real-IP' in request.headers:
            return request.headers['X-Real-IP']
        else:
            return request.remote_addr or 'unknown'
    
    def log_login_attempt(self, username: str, success: bool, details: str = None):
        """Log login attempt."""
        self.log_event('login_attempt', username, details=details, success=success)
    
    def log_password_change(self, user_id: str, success: bool = True):
        """Log password change."""
        self.log_event('password_change', user_id, success=success)
    
    def log_account_lockout(self, identifier: str):
        """Log account lockout."""
        self.log_event('account_lockout', identifier, success=False)
    
    def log_suspicious_activity(self, details: str, user_id: str = None):
        """Log suspicious activity."""
        self.log_event('suspicious_activity', user_id, details=details, success=False)


class SecureSessionManager:
    """Enhanced session management with security features."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def create_session(user_id: str) -> str:
        """Create a new secure session."""
        session_token = SecureSessionManager.generate_secure_token()
        session['user_id'] = user_id
        session['session_token'] = session_token
        session['created_at'] = time.time()
        session['last_activity'] = time.time()
        session['ip_address'] = request.remote_addr if request else 'unknown'
        
        return session_token
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session."""
        if 'user_id' not in session:
            return False
        
        # Check session timeout
        if 'last_activity' in session:
            if time.time() - session['last_activity'] > SecurityConfig.SESSION_TIMEOUT:
                SecureSessionManager.destroy_session()
                return False
        
        # Update last activity
        session['last_activity'] = time.time()
        
        return True
    
    @staticmethod
    def destroy_session():
        """Destroy current session."""
        session.clear()
    
    @staticmethod
    def regenerate_session_id():
        """Regenerate session ID for security."""
        if 'user_id' in session:
            user_id = session['user_id']
            SecureSessionManager.destroy_session()
            SecureSessionManager.create_session(user_id)


class CSRFProtection:
    """CSRF protection utilities."""
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF token."""
        if 'csrf_token' not in session:
            session['csrf_token'] = SecureSessionManager.generate_secure_token()
        return session['csrf_token']
    
    @staticmethod
    def validate_csrf_token(token: str) -> bool:
        """Validate CSRF token."""
        return session.get('csrf_token') == token


# Global instances
rate_limiter = RateLimiter()
security_logger = SecurityLogger()


def apply_security_headers(response):
    """Apply security headers to response."""
    for header, value in SecurityConfig.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


def require_csrf_token(f):
    """Decorator to require CSRF token for POST requests."""
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not CSRFProtection.validate_csrf_token(token):
                from flask import abort
                abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function
