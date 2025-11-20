# Python Security Rules

Security rules for Python development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/_core/ai-security.md` - AI/ML security (if applicable)

---

## Input Handling

### Rule: Avoid Dangerous Deserialization

**Level**: `strict`

**When**: Loading data from untrusted sources.

**Do**:
```python
import json
import yaml

# JSON is safe for untrusted data
data = json.loads(user_input)

# YAML with safe loader
data = yaml.safe_load(user_input)
```

**Don't**:
```python
import pickle
import yaml

# VULNERABLE: Arbitrary code execution
data = pickle.loads(user_input)

# VULNERABLE: yaml.load executes arbitrary Python
data = yaml.load(user_input, Loader=yaml.Loader)
```

**Why**: Pickle and unsafe YAML loaders execute arbitrary code during deserialization, enabling RCE attacks.

**Refs**: CWE-502, OWASP A08:2025

---

### Rule: Use Subprocess Safely

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```python
import subprocess
import shlex

# Pass arguments as list (no shell)
result = subprocess.run(
    ['ls', '-la', user_provided_dir],
    capture_output=True,
    text=True,
    check=True
)

# If shell=True is required, validate strictly
if re.match(r'^[a-zA-Z0-9_-]+$', filename):
    subprocess.run(f'process {shlex.quote(filename)}', shell=True)
```

**Don't**:
```python
import os
import subprocess

# VULNERABLE: Command injection
os.system(f'ls {user_input}')

# VULNERABLE: Shell injection
subprocess.run(f'grep {pattern} {filename}', shell=True)
```

**Why**: Shell injection allows attackers to execute arbitrary commands on the system.

**Refs**: CWE-78, OWASP A03:2025

---

## File Operations

### Rule: Prevent Path Traversal

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```python
import os
from pathlib import Path

UPLOAD_DIR = Path('/app/uploads').resolve()

def safe_file_access(filename: str) -> Path:
    # Resolve to absolute path
    requested = (UPLOAD_DIR / filename).resolve()

    # Verify it's within allowed directory
    if not requested.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal attempt detected")

    return requested
```

**Don't**:
```python
def get_file(filename):
    # VULNERABLE: Path traversal
    return open(f'/app/uploads/{filename}').read()

# VULNERABLE: No validation
path = os.path.join(base_dir, user_filename)
```

**Why**: Path traversal (../) allows reading arbitrary files like /etc/passwd or application secrets.

**Refs**: CWE-22, OWASP A01:2025

---

### Rule: Secure Temporary Files

**Level**: `warning`

**When**: Creating temporary files.

**Do**:
```python
import tempfile

# Secure temporary file with automatic cleanup
with tempfile.NamedTemporaryFile(delete=True) as tmp:
    tmp.write(data)
    tmp.flush()
    process_file(tmp.name)

# Secure temporary directory
with tempfile.TemporaryDirectory() as tmpdir:
    filepath = os.path.join(tmpdir, 'data.txt')
```

**Don't**:
```python
# VULNERABLE: Predictable filename, race condition
tmp_file = f'/tmp/myapp_{user_id}.txt'
with open(tmp_file, 'w') as f:
    f.write(data)
```

**Why**: Predictable temp file names enable symlink attacks and race conditions.

**Refs**: CWE-377, CWE-379

---

## Cryptography

### Rule: Use Secure Random Numbers

**Level**: `strict`

**When**: Generating tokens, keys, or security-sensitive random values.

**Do**:
```python
import secrets

# Secure token generation
token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)

# Secure random choice
otp = ''.join(secrets.choice('0123456789') for _ in range(6))
```

**Don't**:
```python
import random

# VULNERABLE: Predictable random
token = ''.join(random.choices('abcdef0123456789', k=32))
session_id = random.randint(0, 999999)
```

**Why**: `random` module uses predictable PRNG. Attackers can predict tokens and session IDs.

**Refs**: CWE-330, CWE-338

---

### Rule: Hash Passwords Correctly

**Level**: `strict`

**When**: Storing user passwords.

**Do**:
```python
import bcrypt
# Or: from argon2 import PasswordHasher

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)
```

**Don't**:
```python
import hashlib

# VULNERABLE: No salt, fast hash
password_hash = hashlib.sha256(password.encode()).hexdigest()

# VULNERABLE: MD5 is broken
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Why**: Unsalted fast hashes are vulnerable to rainbow tables and GPU cracking.

**Refs**: CWE-916, CWE-328, OWASP A02:2025

---

## SQL Security

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries with user input.

**Do**:
```python
import sqlite3

# Parameterized query
cursor.execute(
    "SELECT * FROM users WHERE email = ? AND status = ?",
    (email, status)
)

# With named parameters
cursor.execute(
    "SELECT * FROM users WHERE email = :email",
    {"email": email}
)

# SQLAlchemy ORM
user = session.query(User).filter(User.email == email).first()
```

**Don't**:
```python
# VULNERABLE: SQL injection
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)

# VULNERABLE: String formatting
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Web Security

### Rule: Validate URL Schemes

**Level**: `strict`

**When**: Processing user-provided URLs.

**Do**:
```python
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}

def validate_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Invalid scheme: {parsed.scheme}")

    if not parsed.netloc:
        raise ValueError("Missing hostname")

    return url
```

**Don't**:
```python
# VULNERABLE: Allows file://, javascript:, etc.
def fetch_url(url):
    return requests.get(url)
```

**Why**: Malicious schemes like `file://` or `javascript:` can read local files or execute code.

**Refs**: CWE-918, OWASP A10:2025

---

### Rule: Set Secure Cookie Attributes

**Level**: `strict`

**When**: Setting cookies in web applications.

**Do**:
```python
from flask import make_response

response = make_response(data)
response.set_cookie(
    'session_id',
    value=session_id,
    httponly=True,      # Prevents XSS access
    secure=True,        # HTTPS only
    samesite='Lax',     # CSRF protection
    max_age=3600        # 1 hour expiry
)
```

**Don't**:
```python
# VULNERABLE: Missing security attributes
response.set_cookie('session_id', session_id)
```

**Why**: Missing attributes expose cookies to XSS theft and CSRF attacks.

**Refs**: CWE-614, CWE-1004, OWASP A07:2025

---

## Error Handling

### Rule: Don't Expose Stack Traces

**Level**: `warning`

**When**: Handling exceptions in production.

**Do**:
```python
import logging

logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # Log full details internally
    logger.exception("Unhandled exception")

    # Return safe message to client
    return {"error": "Internal server error"}, 500
```

**Don't**:
```python
@app.errorhandler(Exception)
def handle_error(error):
    # VULNERABLE: Exposes internals
    return {
        "error": str(error),
        "traceback": traceback.format_exc()
    }, 500
```

**Why**: Stack traces reveal file paths, library versions, and code structure to attackers.

**Refs**: CWE-209, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Avoid pickle/unsafe YAML | strict | CWE-502 |
| Safe subprocess | strict | CWE-78 |
| Path traversal prevention | strict | CWE-22 |
| Secure temp files | warning | CWE-377 |
| Cryptographic randomness | strict | CWE-330 |
| Password hashing | strict | CWE-916 |
| Parameterized queries | strict | CWE-89 |
| URL scheme validation | strict | CWE-918 |
| Secure cookies | strict | CWE-614 |
| No stack traces | warning | CWE-209 |

---

## Version History

- **v1.0.0** - Initial Python security rules
