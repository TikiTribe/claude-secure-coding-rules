# Flask Security Rules

Security rules for Flask development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/python/CLAUDE.md` - Python security

---

## Configuration

### Rule: Use Secure Configuration

**Level**: `strict`

**When**: Configuring Flask for production.

**Do**:
```python
import os

class ProductionConfig:
    SECRET_KEY = os.environ['SECRET_KEY']
    DEBUG = False
    TESTING = False

    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app.config.from_object(ProductionConfig)
```

**Don't**:
```python
# VULNERABLE: Insecure configuration
app.config['SECRET_KEY'] = 'dev'
app.config['DEBUG'] = True
app.config['SESSION_COOKIE_SECURE'] = False
```

**Why**: Debug mode exposes sensitive information, weak secrets enable session forgery.

**Refs**: CWE-215, OWASP A05:2025

---

## Input Validation

### Rule: Validate Request Data

**Level**: `strict`

**When**: Processing user input.

**Do**:
```python
from flask import request, jsonify
from marshmallow import Schema, fields, validate, ValidationError

class UserSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128)
    )
    age = fields.Int(validate=validate.Range(min=0, max=150))

@app.route('/users', methods=['POST'])
def create_user():
    schema = UserSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    # data is validated
    return jsonify(create_user_service(data)), 201
```

**Don't**:
```python
# VULNERABLE: No validation
@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    return jsonify(create_user_service(data)), 201
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## XSS Prevention

### Rule: Use Jinja2 Auto-Escaping

**Level**: `strict`

**When**: Rendering user content in templates.

**Do**:
```html
<!-- Jinja2 auto-escapes by default -->
<p>{{ user_input }}</p>

<!-- For trusted HTML, sanitize first -->
<div>{{ sanitized_html | safe }}</div>
```

```python
import bleach

@app.route('/content')
def show_content():
    allowed_tags = ['p', 'b', 'i', 'a']
    clean_html = bleach.clean(user_html, tags=allowed_tags)
    return render_template('content.html', content=clean_html)
```

**Don't**:
```html
<!-- VULNERABLE: Disables escaping -->
<p>{{ user_input | safe }}</p>

{% autoescape false %}
{{ user_content }}
{% endautoescape %}
```

**Why**: Unescaped output enables XSS attacks that steal cookies or perform actions as users.

**Refs**: CWE-79, OWASP A03:2025

---

## Authentication

### Rule: Implement Secure Sessions

**Level**: `strict`

**When**: Managing user authentication.

**Do**:
```python
from flask import session
from flask_login import LoginManager, login_user, login_required
import secrets

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        login_user(user)
        session.regenerate()  # Prevent session fixation
        return redirect(url_for('dashboard'))
    return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
```

**Don't**:
```python
# VULNERABLE: Manual session without security
@app.route('/login', methods=['POST'])
def login():
    if check_password(request.form['password']):
        session['user_id'] = user.id  # No regeneration
        return redirect('/dashboard')
```

**Why**: Flask-Login handles session regeneration, remember-me tokens, and session protection.

**Refs**: CWE-384, OWASP A07:2025

---

## CSRF Protection

### Rule: Use Flask-WTF for CSRF Protection

**Level**: `strict`

**When**: Handling form submissions.

**Do**:
```python
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email

csrf = CSRFProtect(app)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # CSRF validated automatically
        user = authenticate(form.email.data, form.password.data)
        if user:
            login_user(user)
            return redirect('/dashboard')
    return render_template('login.html', form=form)
```

```html
<form method="POST">
    {{ form.hidden_tag() }}  <!-- Includes CSRF token -->
    {{ form.email() }}
    {{ form.password() }}
    <button type="submit">Login</button>
</form>
```

**Don't**:
```python
# VULNERABLE: No CSRF protection
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    # Process without CSRF check
```

**Why**: CSRF allows attackers to perform actions on behalf of authenticated users.

**Refs**: CWE-352, OWASP A01:2025

---

## Database Security

### Rule: Use SQLAlchemy ORM

**Level**: `strict`

**When**: Querying databases.

**Do**:
```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)

# ORM queries are safe
user = User.query.filter_by(email=email).first()

# If raw SQL needed, use parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)
```

**Don't**:
```python
# VULNERABLE: SQL injection
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.session.execute(query)
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Error Handling

### Rule: Implement Custom Error Handlers

**Level**: `warning`

**When**: Handling errors in production.

**Do**:
```python
import logging

logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400
```

**Don't**:
```python
# VULNERABLE: Debug mode in production
app.run(debug=True)

# VULNERABLE: Exposing exceptions
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500
```

**Why**: Stack traces reveal internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

---

## File Uploads

### Rule: Validate Uploaded Files

**Level**: `strict`

**When**: Accepting file uploads.

**Do**:
```python
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['file']

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))

    return jsonify({'filename': filename}), 201
```

**Don't**:
```python
# VULNERABLE: No validation
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # Path traversal!
```

**Why**: Unrestricted uploads enable web shells, path traversal, and storage exhaustion.

**Refs**: CWE-434, OWASP A04:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Secure configuration | strict | CWE-215 |
| Input validation | strict | CWE-20 |
| Jinja2 auto-escaping | strict | CWE-79 |
| Secure sessions | strict | CWE-384 |
| CSRF protection | strict | CWE-352 |
| SQLAlchemy ORM | strict | CWE-89 |
| Error handling | warning | CWE-209 |
| File upload validation | strict | CWE-434 |

---

## Version History

- **v1.0.0** - Initial Flask security rules
