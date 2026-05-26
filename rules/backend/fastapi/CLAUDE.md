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
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from fastapi import FastAPI

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    age: int = Field(..., ge=0, le=150)

    @field_validator('password', mode='before')
    @classmethod
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
    filename: str = Path(..., pattern=r'^[a-zA-Z0-9_-]+\.[a-z]+$')
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
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ["JWT_SECRET"]  # From environment
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
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
from pydantic import BaseModel, ConfigDict

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    name: str

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

## AI/ML API Security

### Rule: Secure LLM API Endpoints

**Level**: `strict`

**When**: Building APIs that serve LLM or ML model inference.

**Do**:
```python
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
import os
import re

app = FastAPI()

# Safe: Strict input schema for LLM inputs. User content stays in the user
# message role at inference time; it is never concatenated into the system
# prompt. This role separation is the primary OWASP LLM01:2025 control.
# Substring denylists are trivially bypassed (encoding, paraphrase, Unicode
# substitution) and must not be the sole or primary defense.
class LLMRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)
    max_tokens: int = Field(default=256, ge=1, le=4096)
    temperature: float = Field(default=0.7, ge=0, le=2)

class LLMResponse(BaseModel):
    text: str
    tokens_used: int
    finish_reason: str

# Safe: Validate model outputs against a typed Pydantic schema before
# returning to callers. Structured output validation catches malformed,
# truncated, or policy-violating responses at the API boundary.
async def validate_output(text: str) -> str:
    # Redact known sensitive data patterns as a defense-in-depth layer.
    sensitive_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{16}\b',  # Credit card
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, text):
            return "[Content filtered]"
    return text

@app.post("/generate", response_model=LLMResponse)
async def generate(
    request: LLMRequest,
    api_key: str = Depends(verify_api_key)
):
    # Pass user content in the user role, not by string concatenation into
    # the system prompt. The system prompt is a static constant defined in
    # server configuration, not derived from user input.
    result = await model.generate(
        system_prompt=STATIC_SYSTEM_PROMPT,   # constant, not user-derived
        user_message=request.prompt,           # user role, segregated
        max_tokens=request.max_tokens,
        temperature=request.temperature
    )

    # Validate output before returning
    filtered_text = await validate_output(result.text)

    return LLMResponse(
        text=filtered_text,
        tokens_used=result.tokens,
        finish_reason=result.finish_reason
    )

# Safe: Streaming with output validation
from fastapi.responses import StreamingResponse

@app.post("/stream")
async def stream_generate(
    request: LLMRequest,
    api_key: str = Depends(verify_api_key)
):
    async def generate_stream():
        buffer = ""
        async for chunk in model.stream(
            system_prompt=STATIC_SYSTEM_PROMPT,
            user_message=request.prompt
        ):
            buffer += chunk
            # Validate accumulated output
            if len(buffer) > 100:
                filtered = await validate_output(buffer)
                yield filtered
                buffer = ""
        if buffer:
            yield await validate_output(buffer)

    return StreamingResponse(
        generate_stream(),
        media_type="text/plain"
    )
```

**Don't**:
```python
# VULNERABLE: No input validation
@app.post("/generate")
async def generate(prompt: str, max_tokens: int):
    return await model.generate(prompt, max_tokens)

# VULNERABLE: No output validation
@app.post("/generate")
async def generate(request: LLMRequest):
    result = await model.generate(request.prompt)
    return {"text": result}  # Could contain sensitive data

# VULNERABLE: User input concatenated into system prompt (prompt injection)
@app.post("/chat")
async def chat(message: str):
    full_prompt = f"System: You are helpful.\nUser: {message}\nAssistant:"
    return await model.generate(full_prompt)  # Injection possible

# VULNERABLE: Substring denylist as sole injection defense
# Trivially bypassed by encoding, paraphrase, or multilingual injection.
if "ignore previous instructions" in message.lower():
    raise ValueError("Blocked")
```

**Why**: LLM APIs are vulnerable to prompt injection when user content reaches the system prompt role. Structural role isolation (user content in the user message role, never concatenated into the system prompt) is the primary OWASP LLM01:2025 control. Output must be validated against typed schemas before returning to callers.

**Refs**: OWASP LLM01:2025, OWASP LLM05:2025 (Improper Output Handling), CWE-20

---

### Rule: Secure Model Loading in FastAPI

**Level**: `strict`

**When**: Loading ML models in FastAPI applications.

**Do**:
```python
from fastapi import FastAPI
from contextlib import asynccontextmanager
import torch
import os

# Safe: Load model at startup with validation
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Load model securely
    model_path = os.environ.get("MODEL_PATH")
    if not model_path:
        raise ValueError("MODEL_PATH not configured")

    # Use safe serialization (TorchScript)
    app.state.model = torch.jit.load(model_path)
    app.state.model.eval()

    # If using transformers
    from transformers import AutoModel
    app.state.transformer = AutoModel.from_pretrained(
        os.environ.get("MODEL_NAME"),
        trust_remote_code=False,  # CRITICAL
        use_safetensors=True
    )

    yield

    # Cleanup
    del app.state.model
    del app.state.transformer

app = FastAPI(lifespan=lifespan)

@app.post("/predict")
async def predict(data: PredictRequest):
    model = app.state.model
    with torch.no_grad():
        result = model(data.to_tensor())
    return {"prediction": result.tolist()}
```

**Don't**:
```python
# VULNERABLE: Trust remote code
model = AutoModel.from_pretrained(
    model_name,
    trust_remote_code=True  # Arbitrary code execution
)

# VULNERABLE: Load pickle files
import pickle
model = pickle.load(open("model.pkl", "rb"))  # RCE

# VULNERABLE: Load at request time
@app.post("/predict")
async def predict(data: dict):
    model = torch.load("model.pt")  # Slow and unsafe
    return model(data)
```

**Why**: Unsafe model loading enables remote code execution through malicious model files or compromised model repositories.

**Refs**: OWASP LLM03:2025 (Supply Chain), OWASP LLM04:2025 (Data and Model Poisoning), CWE-502, MITRE ATLAS AML.T0010

---

### Rule: Implement AI-Specific Rate Limiting

**Level**: `strict`

**When**: Serving compute-intensive AI endpoints.

**Do**:
```python
from fastapi import FastAPI, HTTPException, Depends, Request
from collections import defaultdict
from time import time
import asyncio

# Safe: Token-based rate limiting for AI APIs
class TokenBucketLimiter:
    def __init__(
        self,
        tokens_per_minute: int = 10000,
        requests_per_minute: int = 60
    ):
        self.tokens_per_minute = tokens_per_minute
        self.requests_per_minute = requests_per_minute
        self.user_tokens = defaultdict(lambda: {"tokens": 0, "requests": [], "last_reset": time()})

    async def check_limit(self, user_id: str, requested_tokens: int) -> bool:
        now = time()
        user = self.user_tokens[user_id]

        # Reset if minute passed
        if now - user["last_reset"] > 60:
            user["tokens"] = 0
            user["requests"] = []
            user["last_reset"] = now

        # Check token limit
        if user["tokens"] + requested_tokens > self.tokens_per_minute:
            return False

        # Check request limit
        user["requests"] = [t for t in user["requests"] if now - t < 60]
        if len(user["requests"]) >= self.requests_per_minute:
            return False

        # Update usage
        user["tokens"] += requested_tokens
        user["requests"].append(now)
        return True

limiter = TokenBucketLimiter()

async def check_ai_rate_limit(
    request: Request,
    user_id: str = Depends(get_current_user)
):
    # Estimate tokens from request
    body = await request.json()
    estimated_tokens = len(body.get("prompt", "")) // 4 + body.get("max_tokens", 256)

    if not await limiter.check_limit(user_id, estimated_tokens):
        raise HTTPException(
            status_code=429,
            detail="Token rate limit exceeded"
        )

@app.post("/generate")
async def generate(
    request: LLMRequest,
    _: None = Depends(check_ai_rate_limit)
):
    return await model.generate(request)
```

**Don't**:
```python
# VULNERABLE: No rate limiting on expensive endpoints
@app.post("/generate")
async def generate(request: LLMRequest):
    return await model.generate(request)  # DoS vector

# VULNERABLE: Request-based only (ignores token usage)
@app.post("/generate")
@limiter.limit("60/minute")  # User can request max tokens each time
async def generate(request: LLMRequest):
    return await model.generate(request)
```

**Why**: AI endpoints are compute-intensive. Without token-based rate limiting, users can exhaust GPU resources and rack up costs.

**Refs**: OWASP LLM10:2025 (Unbounded Consumption), CWE-400, CWE-770

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
| Secure LLM API endpoints | strict | OWASP LLM01:2025, CWE-20 |
| Secure model loading | strict | OWASP LLM03:2025, CWE-502 |
| AI-specific rate limiting | strict | OWASP LLM10:2025, CWE-400 |

---

## Version History

- **v2.0.0** - Pydantic v2 API, OWASP LLM Top 10 2025 refs, structural prompt injection defense
- **v1.1.0** - Added AI/ML API security rules
- **v1.0.0** - Initial FastAPI security rules
