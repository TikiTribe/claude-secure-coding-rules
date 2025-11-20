# OWASP Top 10 2025 - Core Security Rules

This file provides foundational security rules based on OWASP Top 10:2025.

## Overview

**Standard**: OWASP Top 10:2025 (Release Candidate, November 2025)
**Scope**: Web application security risks
**Data Source**: 589 CWEs across 248 categories

---

## A01:2025 - Broken Access Control

**Risk Level**: Critical (3.73% of applications affected)
**CWE Coverage**: 40 CWEs including SSRF

### Rule: Enforce Server-Side Access Control

**Level**: `strict`

**When**: Any endpoint accessing protected resources, user data, or administrative functions.

**Do**:
```python
from functools import wraps
from flask import g, abort

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.user.has_permission(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users/<int:user_id>')
@require_permission('admin:read')
def get_user(user_id):
    # Server validates ownership/permission before returning data
    return User.query.get_or_404(user_id)
```

**Don't**:
```python
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    # VULNERABLE: No authorization check - any authenticated user can access any profile
    return User.query.get_or_404(user_id)
```

**Why**: Broken access control allows attackers to access unauthorized data, modify other users' data, or elevate privileges. Server-side enforcement is required because client-side controls can be bypassed.

**Refs**: OWASP A01:2025, CWE-284, CWE-862, CWE-863, NIST SSDF PW.1.1

---

### Rule: Prevent SSRF Attacks

**Level**: `strict`

**When**: Application makes HTTP requests based on user-supplied URLs or parameters.

**Do**:
```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

def validate_url(url):
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid scheme")

    # Check against allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

    # Block internal IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            raise ValueError("Internal addresses blocked")
    except ValueError:
        pass  # hostname, not IP

    return url

def fetch_external_resource(user_url):
    validated_url = validate_url(user_url)
    return requests.get(validated_url, timeout=5)
```

**Don't**:
```python
def fetch_resource(url):
    # VULNERABLE: Direct fetch allows SSRF to internal services
    return requests.get(url)
```

**Why**: SSRF allows attackers to make requests to internal services, cloud metadata endpoints, or other protected resources.

**Refs**: OWASP A01:2025, CWE-918, MITRE ATLAS AML.T0024

---

## A02:2025 - Security Misconfiguration

**Risk Level**: High (3.00% of applications affected)
**CWE Coverage**: 16 CWEs

### Rule: Use Secure Default Configurations

**Level**: `strict`

**When**: Configuring web servers, frameworks, databases, or cloud services.

**Do**:
```python
# Flask production configuration
app.config.update(
    DEBUG=False,
    TESTING=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# Disable verbose errors in production
@app.errorhandler(Exception)
def handle_error(error):
    app.logger.error(f"Error: {error}")
    return {"error": "Internal server error"}, 500
```

**Don't**:
```python
app.config['DEBUG'] = True  # VULNERABLE in production
app.config['SECRET_KEY'] = 'dev'  # VULNERABLE: weak secret

@app.errorhandler(Exception)
def handle_error(error):
    # VULNERABLE: Exposes stack traces and internal paths
    return {"error": str(error), "traceback": traceback.format_exc()}, 500
```

**Why**: Misconfigured servers expose sensitive information, enable debug features, or use default credentials that attackers exploit.

**Refs**: OWASP A02:2025, CWE-16, CWE-209, NIST SSDF PW.9.1

---

## A03:2025 - Software Supply Chain Failures

**Risk Level**: Critical (highest exploit/impact scores)
**CWE Coverage**: Expanded from "Vulnerable and Outdated Components"

### Rule: Verify Dependency Integrity

**Level**: `strict`

**When**: Installing, updating, or building with third-party dependencies.

**Do**:
```bash
# Use lockfiles with integrity hashes
npm ci --ignore-scripts  # Install from lockfile only

# Verify package signatures
pip install --require-hashes -r requirements.txt

# Pin exact versions with hashes
# requirements.txt
requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
```

```python
# Verify downloaded artifacts
import hashlib

def verify_checksum(filepath, expected_hash):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    if sha256.hexdigest() != expected_hash:
        raise SecurityError("Checksum mismatch - possible tampering")
```

**Don't**:
```bash
# VULNERABLE: Unpinned versions
pip install requests

# VULNERABLE: No integrity verification
npm install some-package
```

**Why**: Supply chain attacks compromise build systems, inject malicious code into dependencies, or distribute tampered packages.

**Refs**: OWASP A03:2025, CWE-829, NIST SSDF PS.3.1, OSSF Scorecard

---

## A04:2025 - Cryptographic Failures

**Risk Level**: High
**Movement**: Down from #2 in 2021

### Rule: Use Strong Cryptographic Algorithms

**Level**: `strict`

**When**: Encrypting data, hashing passwords, or establishing secure connections.

**Do**:
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt
import os

# Password hashing with bcrypt
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Symmetric encryption with AES-256
def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext)

# Key derivation
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())
```

**Don't**:
```python
import hashlib
import base64

# VULNERABLE: MD5/SHA1 for passwords
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: Weak encryption
from Crypto.Cipher import DES  # DES is broken

# VULNERABLE: Hardcoded keys
SECRET_KEY = "mysecretkey123"
```

**Why**: Weak cryptography allows attackers to decrypt sensitive data, forge signatures, or crack password hashes.

**Refs**: OWASP A04:2025, CWE-327, CWE-328, NIST SP 800-131A

---

## A05:2025 - Injection

**Risk Level**: High
**Movement**: Down from #3 in 2021

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Constructing database queries, LDAP queries, OS commands, or XML parsers with user input.

**Do**:
```python
# SQL - Parameterized queries
def get_user(username):
    cursor.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )
    return cursor.fetchone()

# ORM usage
user = User.query.filter_by(username=username).first()

# Command execution with explicit arguments
import subprocess
def list_files(directory):
    # shlex.quote or explicit args list
    result = subprocess.run(
        ['ls', '-la', directory],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout
```

**Don't**:
```python
# VULNERABLE: SQL injection
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# VULNERABLE: Command injection
import os
os.system(f"ls -la {user_input}")
```

**Why**: Injection flaws allow attackers to execute arbitrary queries or commands, leading to data theft, modification, or system compromise.

**Refs**: OWASP A05:2025, CWE-89, CWE-78, CWE-79, NIST SSDF PW.5.1

---

## A06:2025 - Insecure Design

**Risk Level**: High
**Movement**: Down from #4 in 2021

### Rule: Implement Threat Modeling

**Level**: `advisory`

**When**: Designing new features, APIs, or system architectures.

**Do**:
- Identify trust boundaries and data flows
- Document threat actors and attack vectors
- Apply security controls at design phase
- Use abuse case scenarios alongside use cases

```python
# Design with rate limiting built-in
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Designed-in protection
def login():
    # Rate limiting prevents brute force by design
    pass
```

**Don't**:
- Add security as an afterthought
- Assume trusted inputs from any source
- Design without considering abuse scenarios

**Why**: Security flaws in design are expensive to fix later. Building security in from the start is more effective than patching vulnerabilities.

**Refs**: OWASP A06:2025, CWE-840, ISO/IEC 27001, NIST SSDF PW.1.1

---

## A07:2025 - Authentication Failures

**Risk Level**: High

### Rule: Implement Secure Session Management

**Level**: `strict`

**When**: Handling user authentication, sessions, or tokens.

**Do**:
```python
from flask import session
import secrets

# Secure session configuration
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
)

# Regenerate session on login
@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form['username'], request.form['password']):
        session.clear()  # Prevent session fixation
        session['user_id'] = user.id
        session.regenerate()  # New session ID
        return redirect('/dashboard')
    return "Invalid credentials", 401
```

**Don't**:
```python
# VULNERABLE: Weak session secret
app.secret_key = 'secret'

# VULNERABLE: No session regeneration on login
@app.route('/login', methods=['POST'])
def login():
    if check_password(username, password):
        session['logged_in'] = True  # Session fixation risk
```

**Why**: Weak authentication allows account takeover, credential stuffing, and session hijacking attacks.

**Refs**: OWASP A07:2025, CWE-287, CWE-384, NIST SP 800-63B

---

## A08:2025 - Software and Data Integrity Failures

**Risk Level**: High

### Rule: Verify Code and Data Integrity

**Level**: `strict`

**When**: Loading code, deserializing data, or updating software.

**Do**:
```python
import hmac
import hashlib
import json

# Verify data integrity with HMAC
def verify_payload(payload, signature, secret_key):
    expected = hmac.new(
        secret_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise SecurityError("Invalid signature")
    return json.loads(payload)

# Safe deserialization
import json
data = json.loads(user_input)  # Safe: JSON only
```

**Don't**:
```python
import pickle

# VULNERABLE: Arbitrary code execution
data = pickle.loads(user_input)

# VULNERABLE: No integrity verification
def process_update(payload):
    return json.loads(payload)  # No signature check
```

**Why**: Integrity failures allow attackers to inject malicious code through deserialization, tampered updates, or CI/CD pipeline compromises.

**Refs**: OWASP A08:2025, CWE-502, CWE-829, NIST SSDF PW.4.1

---

## A09:2025 - Logging & Alerting Failures

**Risk Level**: Medium

### Rule: Log Security Events Comprehensively

**Level**: `warning`

**When**: Authentication attempts, access control decisions, data access, or security-relevant operations.

**Do**:
```python
import logging
from datetime import datetime

security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

def log_security_event(event_type, user_id, details, severity='INFO'):
    security_logger.log(
        getattr(logging, severity),
        json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'details': details
        })
    )

@app.route('/login', methods=['POST'])
def login():
    if authenticate(username, password):
        log_security_event('LOGIN_SUCCESS', user.id, {'method': '2fa'})
        return redirect('/dashboard')
    else:
        log_security_event('LOGIN_FAILURE', None,
                          {'username': username}, severity='WARNING')
        return "Invalid credentials", 401
```

**Don't**:
```python
# VULNERABLE: No logging
@app.route('/login', methods=['POST'])
def login():
    if authenticate(username, password):
        return redirect('/dashboard')
    return "Invalid", 401

# VULNERABLE: Logging sensitive data
logger.info(f"Login attempt: {username}:{password}")
```

**Why**: Without proper logging, breaches go undetected, forensics are impossible, and compliance requirements are violated.

**Refs**: OWASP A09:2025, CWE-778, CWE-223, NIST SP 800-92

---

## A10:2025 - Mishandling of Exceptional Conditions

**Risk Level**: Medium
**Status**: New category for 2025

### Rule: Handle Errors Securely

**Level**: `warning`

**When**: Exception handling, error responses, or failure modes.

**Do**:
```python
from flask import jsonify
import logging

@app.errorhandler(Exception)
def handle_exception(e):
    # Log full details internally
    app.logger.error(f"Unhandled exception: {e}", exc_info=True)

    # Return safe message to client
    if isinstance(e, ValidationError):
        return jsonify({"error": "Invalid input"}), 400
    elif isinstance(e, AuthenticationError):
        return jsonify({"error": "Authentication failed"}), 401
    else:
        return jsonify({"error": "Internal server error"}), 500

# Fail closed
def check_permission(user, resource):
    try:
        return permission_service.check(user, resource)
    except Exception as e:
        logger.error(f"Permission check failed: {e}")
        return False  # Fail closed - deny access on error
```

**Don't**:
```python
# VULNERABLE: Fail open
def check_permission(user, resource):
    try:
        return permission_service.check(user, resource)
    except:
        return True  # DANGEROUS: Grants access on error

# VULNERABLE: Information disclosure
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500  # Exposes internal details
```

**Why**: Poor error handling can leak sensitive information, bypass security controls when failing open, or create denial of service conditions.

**Refs**: OWASP A10:2025, CWE-755, CWE-754, CWE-391

---

## Quick Reference

| Category | Level | Primary CWEs | Key Control |
|----------|-------|--------------|-------------|
| A01 Broken Access Control | strict | CWE-284, CWE-862 | Server-side authorization |
| A02 Security Misconfiguration | strict | CWE-16, CWE-209 | Secure defaults |
| A03 Supply Chain Failures | strict | CWE-829 | Integrity verification |
| A04 Cryptographic Failures | strict | CWE-327, CWE-328 | Strong algorithms |
| A05 Injection | strict | CWE-89, CWE-78, CWE-79 | Parameterized queries |
| A06 Insecure Design | advisory | CWE-840 | Threat modeling |
| A07 Authentication Failures | strict | CWE-287, CWE-384 | Secure sessions |
| A08 Integrity Failures | strict | CWE-502 | Signature verification |
| A09 Logging Failures | warning | CWE-778 | Comprehensive logging |
| A10 Error Handling | warning | CWE-755 | Fail closed |

---

## Version History

- **v1.0.0** - Initial release based on OWASP Top 10:2025 RC1 (November 2025)
