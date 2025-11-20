# Django Security Rules

Security rules for Django development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/python/CLAUDE.md` - Python security

---

## Configuration

### Rule: Use Secure Production Settings

**Level**: `strict`

**When**: Deploying Django to production.

**Do**:
```python
# settings/production.py
import os

DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

ALLOWED_HOSTS = ['myapp.com', 'www.myapp.com']

# Security middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware
]

# HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Security headers
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
```

**Don't**:
```python
# VULNERABLE: Production misconfigurations
DEBUG = True
SECRET_KEY = 'django-insecure-hardcoded-key'
ALLOWED_HOSTS = ['*']
```

**Why**: Debug mode exposes sensitive information, weak secrets enable session forgery.

**Refs**: CWE-215, OWASP A05:2025

---

## CSRF Protection

### Rule: Use CSRF Protection Correctly

**Level**: `strict`

**When**: Handling form submissions and state-changing requests.

**Do**:
```python
# views.py
from django.views.decorators.csrf import csrf_protect
from django.middleware.csrf import get_token

@csrf_protect
def update_profile(request):
    if request.method == 'POST':
        # CSRF token validated automatically
        form = ProfileForm(request.POST)
        if form.is_valid():
            form.save()
    return render(request, 'profile.html')

# For AJAX, include token in headers
# template.html
<script>
const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
fetch('/api/update', {
    method: 'POST',
    headers: {'X-CSRFToken': csrftoken},
    body: JSON.stringify(data)
});
</script>
```

**Don't**:
```python
from django.views.decorators.csrf import csrf_exempt

# VULNERABLE: Disables CSRF protection
@csrf_exempt
def update_profile(request):
    # No CSRF validation
    pass
```

**Why**: CSRF allows attackers to perform actions on behalf of authenticated users.

**Refs**: CWE-352, OWASP A01:2025

---

## SQL Security

### Rule: Use ORM and Avoid Raw SQL

**Level**: `strict`

**When**: Querying the database.

**Do**:
```python
from django.db.models import Q

# ORM queries are safe
users = User.objects.filter(email=email, is_active=True)

# Complex queries with Q objects
users = User.objects.filter(
    Q(email__icontains=search) | Q(name__icontains=search)
)

# If raw SQL is needed, use parameterized queries
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute(
        "SELECT * FROM users WHERE email = %s",
        [email]
    )
```

**Don't**:
```python
# VULNERABLE: SQL injection
User.objects.raw(f"SELECT * FROM users WHERE email = '{email}'")

# VULNERABLE: extra() with user input
User.objects.extra(where=[f"email = '{email}'"])
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## XSS Prevention

### Rule: Use Django Template Auto-Escaping

**Level**: `strict`

**When**: Rendering user content in templates.

**Do**:
```html
<!-- Django auto-escapes by default -->
<p>{{ user_input }}</p>

<!-- For trusted HTML, use |safe only after sanitization -->
{% load bleach_tags %}
<div>{{ user_html|bleach }}</div>
```

```python
# views.py
import bleach

def render_content(request):
    allowed_tags = ['p', 'b', 'i', 'a']
    clean_html = bleach.clean(user_html, tags=allowed_tags)
    return render(request, 'content.html', {'content': clean_html})
```

**Don't**:
```html
<!-- VULNERABLE: Disables escaping -->
<p>{{ user_input|safe }}</p>

<!-- VULNERABLE: autoescape off -->
{% autoescape off %}
{{ user_content }}
{% endautoescape %}
```

**Why**: Unescaped output enables XSS attacks that steal cookies or perform actions as users.

**Refs**: CWE-79, OWASP A03:2025

---

## Authentication

### Rule: Use Django's Authentication System

**Level**: `strict`

**When**: Implementing user authentication.

**Do**:
```python
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password

def login_view(request):
    if request.method == 'POST':
        user = authenticate(
            request,
            username=request.POST['username'],
            password=request.POST['password']
        )
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')
```

**Don't**:
```python
# VULNERABLE: Custom auth without proper hashing
def login_view(request):
    user = User.objects.get(username=request.POST['username'])
    if user.password == request.POST['password']:  # Plain comparison!
        request.session['user_id'] = user.id
```

**Why**: Django's auth system handles password hashing, session management, and timing attacks.

**Refs**: CWE-916, OWASP A07:2025

---

## Authorization

### Rule: Implement Object-Level Permissions

**Level**: `strict`

**When**: Accessing user-owned resources.

**Do**:
```python
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied

def edit_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)

    # Check ownership
    if document.owner != request.user:
        raise PermissionDenied

    # Process edit
    return render(request, 'edit.html', {'document': document})

# Or use django-guardian for object permissions
from guardian.shortcuts import get_objects_for_user

def list_documents(request):
    documents = get_objects_for_user(request.user, 'view_document')
    return render(request, 'list.html', {'documents': documents})
```

**Don't**:
```python
# VULNERABLE: No ownership check (IDOR)
def edit_document(request, doc_id):
    document = Document.objects.get(id=doc_id)
    return render(request, 'edit.html', {'document': document})
```

**Why**: Missing authorization checks allow users to access other users' data.

**Refs**: CWE-862, OWASP A01:2025

---

## File Uploads

### Rule: Validate File Uploads

**Level**: `strict`

**When**: Accepting file uploads from users.

**Do**:
```python
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
import magic

def validate_image(file):
    # Check extension
    allowed_extensions = ['jpg', 'jpeg', 'png']
    ext = file.name.split('.')[-1].lower()
    if ext not in allowed_extensions:
        raise ValidationError('Invalid file extension')

    # Check MIME type
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ['image/jpeg', 'image/png']:
        raise ValidationError('Invalid file type')

    # Check size
    if file.size > 5 * 1024 * 1024:  # 5MB
        raise ValidationError('File too large')

class Document(models.Model):
    file = models.FileField(
        upload_to='documents/',
        validators=[FileExtensionValidator(['pdf', 'doc', 'docx'])]
    )
```

**Don't**:
```python
# VULNERABLE: No validation
class Document(models.Model):
    file = models.FileField(upload_to='documents/')
```

**Why**: Unrestricted uploads enable web shells, path traversal, and storage exhaustion.

**Refs**: CWE-434, OWASP A04:2025

---

## Session Security

### Rule: Configure Secure Sessions

**Level**: `strict`

**When**: Managing user sessions.

**Do**:
```python
# settings.py
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JS access
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
SESSION_COOKIE_AGE = 1800  # 30 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Use database or cache backend
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

# Rotate session on login
from django.contrib.auth import login
def login_view(request):
    # ... authenticate
    login(request, user)
    request.session.cycle_key()  # Prevent session fixation
```

**Don't**:
```python
# VULNERABLE: Insecure session settings
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_AGE = 86400 * 30  # 30 days
```

**Why**: Insecure sessions enable hijacking and fixation attacks.

**Refs**: CWE-384, OWASP A07:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Secure production settings | strict | CWE-215 |
| CSRF protection | strict | CWE-352 |
| ORM queries | strict | CWE-89 |
| Template auto-escaping | strict | CWE-79 |
| Django auth system | strict | CWE-916 |
| Object-level permissions | strict | CWE-862 |
| File upload validation | strict | CWE-434 |
| Secure sessions | strict | CWE-384 |

---

## Version History

- **v1.0.0** - Initial Django security rules
