# FastAPI Security Rules

Security rules for FastAPI development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/python/CLAUDE.md` - Python security

---

## Input Validation

### Rule: Use Pydantic for Request Validation

**Level**: `strict`

**When**: Accepting request data from users.

**Do**:
```python
from pydantic import BaseModel, EmailStr, Field, validator
from fastapi import FastAPI

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    age: int = Field(..., ge=0, le=150)

    @validator('password')
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v

@app.post("/users")
async def create_user(user: UserCreate):
    # user is already validated
    return {"email": user.email}
```

**Don't**:
```python
@app.post("/users")
async def create_user(request: Request):
    # VULNERABLE: No validation
    data = await request.json()
    email = data.get('email')
    password = data.get('password')
```

**Why**: Unvalidated input enables injection attacks, type confusion, and business logic bypass.

**Refs**: OWASP A03:2025, CWE-20

---

### Rule: Validate Path Parameters

**Level**: `strict`

**When**: Using path parameters for resource access.

**Do**:
```python
from fastapi import Path
from uuid import UUID

@app.get("/users/{user_id}")
async def get_user(
    user_id: UUID = Path(..., description="User UUID")
):
    return {"user_id": user_id}

@app.get("/files/{filename}")
async def get_file(
    filename: str = Path(..., regex=r'^[a-zA-Z0-9_-]+\.[a-z]+$')
):
    # Filename validated against pattern
    return {"filename": filename}
```

**Don't**:
```python
@app.get("/files/{filename}")
async def get_file(filename: str):
    # VULNERABLE: Path traversal possible
    return FileResponse(f"uploads/{filename}")
```

**Why**: Unvalidated path parameters enable path traversal and injection attacks.

**Refs**: CWE-22, OWASP A01:2025

---

## Authentication

### Rule: Implement Secure JWT Handling

**Level**: `strict`

**When**: Using JWT for authentication.

**Do**:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta

SECRET_KEY = os.environ["JWT_SECRET"]  # From environment
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return await get_user(user_id)
```

**Don't**:
```python
# VULNERABLE: Hardcoded secret
SECRET_KEY = "mysecretkey123"

# VULNERABLE: Algorithm confusion
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])

# VULNERABLE: No expiration
token = jwt.encode({"sub": user_id}, SECRET_KEY)
```

**Why**: Weak JWT implementation allows token forgery and unauthorized access.

**Refs**: CWE-347, OWASP A07:2025

---

### Rule: Implement Rate Limiting

**Level**: `warning`

**When**: Exposing authentication or resource-intensive endpoints.

**Do**:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest):
    # Rate limited to prevent brute force
    return authenticate(credentials)

@app.post("/api/expensive")
@limiter.limit("10/minute")
async def expensive_operation(request: Request):
    return process()
```

**Don't**:
```python
@app.post("/login")
async def login(credentials: LoginRequest):
    # VULNERABLE: No rate limiting enables brute force
    return authenticate(credentials)
```

**Why**: Missing rate limits enable brute force attacks, credential stuffing, and DoS.

**Refs**: CWE-307, OWASP A07:2025

---

## Authorization

### Rule: Implement Resource-Level Authorization

**Level**: `strict`

**When**: Accessing user-owned or permission-restricted resources.

**Do**:
```python
from fastapi import Depends, HTTPException, status

async def get_user_document(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    document = db.query(Document).filter(Document.id == doc_id).first()

    if not document:
        raise HTTPException(status_code=404, detail="Not found")

    # Check ownership or permission
    if document.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")

    return document

@app.get("/documents/{doc_id}")
async def read_document(document: Document = Depends(get_user_document)):
    return document
```

**Don't**:
```python
@app.get("/documents/{doc_id}")
async def read_document(doc_id: int, db: Session = Depends(get_db)):
    # VULNERABLE: No authorization check (IDOR)
    return db.query(Document).filter(Document.id == doc_id).first()
```

**Why**: Missing authorization checks enable IDOR attacks where users access others' data.

**Refs**: CWE-862, OWASP A01:2025

---

## Database Security

### Rule: Use ORM with Parameterized Queries

**Level**: `strict`

**When**: Querying databases.

**Do**:
```python
from sqlalchemy.orm import Session
from sqlalchemy import text

# ORM queries are safe
users = db.query(User).filter(User.email == email).all()

# Raw SQL with parameters
result = db.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)
```

**Don't**:
```python
# VULNERABLE: SQL injection
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.execute(query)

# VULNERABLE: String formatting
db.execute(f"DELETE FROM users WHERE id = {user_id}")
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Response Security

### Rule: Don't Expose Sensitive Data in Responses

**Level**: `strict`

**When**: Returning user or system data.

**Do**:
```python
from pydantic import BaseModel

class UserResponse(BaseModel):
    id: int
    email: str
    name: str

    class Config:
        orm_mode = True

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    user = get_user_from_db(user_id)
    return user  # password_hash automatically excluded
```

**Don't**:
```python
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    # VULNERABLE: Exposes password hash
    user = db.query(User).filter(User.id == user_id).first()
    return user.__dict__
```

**Why**: Exposing internal fields leaks sensitive data like password hashes or internal IDs.

**Refs**: CWE-200, OWASP A01:2025

---

## Error Handling

### Rule: Use Custom Exception Handlers

**Level**: `warning`

**When**: Handling errors in production.

**Do**:
```python
from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception: {exc}")

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"detail": "Invalid input"}
    )
```

**Don't**:
```python
# Default FastAPI behavior exposes stack traces in debug mode
app = FastAPI(debug=True)  # VULNERABLE in production
```

**Why**: Stack traces expose internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

---

## CORS Configuration

### Rule: Configure CORS Restrictively

**Level**: `strict`

**When**: Enabling cross-origin requests.

**Do**:
```python
from fastapi.middleware.cors import CORSMiddleware

origins = [
    "https://myapp.com",
    "https://admin.myapp.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

**Don't**:
```python
# VULNERABLE: Allows any origin with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
```

**Why**: Permissive CORS allows malicious sites to make authenticated API requests.

**Refs**: CWE-942, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Pydantic validation | strict | CWE-20 |
| Path parameter validation | strict | CWE-22 |
| Secure JWT | strict | CWE-347 |
| Rate limiting | warning | CWE-307 |
| Resource authorization | strict | CWE-862 |
| ORM/parameterized queries | strict | CWE-89 |
| Response filtering | strict | CWE-200 |
| Error handling | warning | CWE-209 |
| CORS configuration | strict | CWE-942 |

---

## Version History

- **v1.0.0** - Initial FastAPI security rules
