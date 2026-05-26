# BentoML Security Rules

Security rules for BentoML model serving in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Model Packaging Security

### Rule: Secure Bento Building and Signing

**Level**: `strict`

**When**: Packaging models with BentoML.

**Do**:
```python
import bentoml
import hashlib
from pathlib import Path

# Safe: Save model with metadata for verification
def save_secure_model(model, name: str, version: str):
    # Save with explicit framework
    saved_model = bentoml.pytorch.save_model(
        name,
        model,
        signatures={
            "predict": {
                "batchable": True,
                "batch_dim": 0,
            }
        },
        metadata={
            "version": version,
            "framework": "pytorch",
            "safe_serialization": True
        },
        # Do not include arbitrary modules
        external_modules=[]
    )

    return saved_model

# Safe: Build bento with locked dependencies
"""
# bentofile.yaml
service: "service:svc"
include:
  - "*.py"
  - "requirements.txt"
exclude:
  - "__pycache__"
  - "*.pyc"
  - ".env"
  - "secrets/*"
python:
  packages:
    - torch==2.0.1
    - numpy==1.24.0
  lock_packages: true  # Pin all transitive dependencies
docker:
  base_image: python:3.11-slim
  # Don't run as root
  user: "bentoml"
"""

# Safe: Verify bento before deployment
def verify_bento(bento_tag: str, expected_hash: str) -> bool:
    bento = bentoml.get(bento_tag)
    bento_path = bento.path

    # Calculate hash of key files
    service_file = Path(bento_path) / "src" / "service.py"
    actual_hash = hashlib.sha256(
        service_file.read_bytes()
    ).hexdigest()

    if actual_hash != expected_hash:
        raise ValueError("Bento integrity check failed")

    # Check for suspicious patterns
    content = service_file.read_text()
    DANGEROUS_PATTERNS = [
        "subprocess", "os.system", "eval(", "exec(",
        "__import__", "pickle.loads"
    ]
    for pattern in DANGEROUS_PATTERNS:
        if pattern in content:
            raise ValueError(f"Suspicious pattern: {pattern}")

    return True

# Safe: Import bento with verification
def import_verified_bento(bento_path: str, expected_hash: str):
    # Verify before import
    verify_bento(bento_path, expected_hash)

    return bentoml.import_bento(bento_path)
```

**Don't**:
```python
# VULNERABLE: No dependency locking
"""
# bentofile.yaml
python:
  packages:
    - torch  # Unpinned - supply chain risk
    - numpy
"""

# VULNERABLE: Include secrets
"""
include:
  - "*"  # Includes .env, secrets, etc.
"""

# VULNERABLE: Run as root
"""
docker:
  base_image: python:3.11
  # No user specified - runs as root
"""

# VULNERABLE: Import without verification
bento = bentoml.import_bento(untrusted_path)
```

**Why**: Unverified bentos can contain malicious code, compromised dependencies, or exposed secrets that enable supply chain attacks.

**Refs**: OWASP LLM03:2025 (Supply Chain Vulnerabilities), CWE-502, CWE-200

---

## Service Security

### Rule: Implement Secure BentoML Services

**Level**: `strict`

**When**: Defining BentoML services and APIs.

**Do**:
```python
import bentoml
import numpy as np
from pydantic import BaseModel, Field, field_validator

# Safe: Input validation with Pydantic v2
class PredictionInput(BaseModel):
    data: list[float] = Field(..., max_length=10000)
    options: dict = Field(default_factory=dict)

    @field_validator("data", mode="before")
    @classmethod
    def validate_data(cls, v):
        if len(v) == 0:
            raise ValueError("Empty data")
        if any(not isinstance(x, (int, float)) for x in v):
            raise ValueError("Invalid data type")
        return v

    @field_validator("options", mode="before")
    @classmethod
    def validate_options(cls, v):
        allowed_keys = {"threshold", "top_k"}
        if not set(v.keys()).issubset(allowed_keys):
            raise ValueError("Invalid options")
        return v

class PredictionOutput(BaseModel):
    result: list[float]
    confidence: float

# Safe: Service with validation and resource limits (BentoML v1.x API)
runner = bentoml.pytorch.get("secure_model:latest").to_runner()

svc = bentoml.Service("secure_service", runners=[runner])

@svc.api(
    input=bentoml.io.JSON.from_sample(PredictionInput(data=[0.0])),
    output=bentoml.io.JSON.from_sample(PredictionOutput(result=[0.0], confidence=0.0)),
    route="/predict"
)
async def predict(input_data: PredictionInput) -> PredictionOutput:
    # Convert to numpy with validation
    arr = np.array(input_data.data, dtype=np.float32)

    # Size check
    if arr.nbytes > 10_000_000:  # 10MB limit
        raise ValueError("Input too large")

    # Run inference
    result = await runner.predict.async_run(arr)

    return PredictionOutput(
        result=result.tolist(),
        confidence=float(result.max())
    )

# Safe: Health check endpoint
@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON(), route="/health")
async def health():
    return {"status": "healthy"}

# Safe: Rate limiting configuration
"""
# configuration.yaml
api_server:
  max_request_size: 10485760  # 10MB
  timeout: 60
  metrics:
    enabled: true
    namespace: "bentoml"
runners:
  secure_model:
    max_batch_size: 32
    max_latency_ms: 1000
"""
```

**Don't**:
```python
# VULNERABLE: No input validation
@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON())
async def predict(input_data: dict):
    # Accept any structure
    return await runner.predict.async_run(input_data)

# VULNERABLE: Arbitrary code execution via user-controlled input
# LLM01:2025 — prompt/input injection leads to eval/exec
@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON())
async def execute(input_data: dict):
    code = input_data.get("code")
    return eval(code)  # Never do this

# VULNERABLE: File access
@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON())
async def read_file(input_data: dict):
    path = input_data.get("path")
    return open(path).read()  # Path traversal

# VULNERABLE: No size limits
@svc.api(
    input=bentoml.io.NumpyNdarray(),  # Any size array
    output=bentoml.io.NumpyNdarray()
)
async def process(arr):
    return runner.run(arr)  # Could be huge
```

**Why**: Services without input validation enable injection attacks, denial of service, and unauthorized data access. Accepting unsanitized text that reaches model inference or downstream code paths is an LLM01:2025 (Prompt Injection) risk.

**Refs**: CWE-20, CWE-94, OWASP LLM01:2025 (Prompt Injection)

---

## Runner Security

### Rule: Configure Secure Runner Execution

**Level**: `strict`

**When**: Setting up BentoML runners.

**Do**:
```python
import bentoml
import numpy as np

# Safe: Runner with resource limits
model_ref = bentoml.pytorch.get("model:latest")

runner = model_ref.to_runner(
    name="secure_runner",
    max_batch_size=32,
    max_latency_ms=1000,
    # Resource configuration
    runnable_init_params={
        "max_concurrent": 4
    }
)

# Safe: Runner configuration in yaml
"""
# configuration.yaml
runners:
  secure_runner:
    resources:
      nvidia.com/gpu: 1
      cpu: 2
      memory: 4Gi
    batching:
      enabled: true
      max_batch_size: 32
      max_latency_ms: 1000
    timeout: 60
"""

# Safe: Custom runner with validation
import torch

class SecureRunnable(bentoml.Runnable):
    SUPPORTED_RESOURCES = ("nvidia.com/gpu", "cpu")
    SUPPORTS_CPU_MULTI_THREADING = True

    def __init__(self):
        self.model = torch.jit.load("model.pt")  # Safe format
        self.max_input_size = 10_000_000

    @bentoml.Runnable.method(batchable=True, batch_dim=0)
    def predict(self, input_arr: np.ndarray) -> np.ndarray:
        # Validate input
        if input_arr.nbytes > self.max_input_size:
            raise ValueError("Input too large")

        if len(input_arr.shape) != 2:
            raise ValueError("Invalid input shape")

        # Safe inference
        with torch.no_grad():
            tensor = torch.from_numpy(input_arr)
            output = self.model(tensor)

        return output.numpy()

# Safe: Create runner from custom runnable
secure_runner = bentoml.Runner(
    SecureRunnable,
    name="secure_custom_runner",
    max_batch_size=32
)

svc = bentoml.Service("service", runners=[secure_runner])
```

**Don't**:
```python
# VULNERABLE: No resource limits
runner = model.to_runner()  # Unlimited resources

# VULNERABLE: Pickle loading in runner
class UnsafeRunnable(bentoml.Runnable):
    def __init__(self):
        import pickle
        self.model = pickle.load(open("model.pkl", "rb"))  # RCE

# VULNERABLE: Shell execution in runner
class CommandRunnable(bentoml.Runnable):
    @bentoml.Runnable.method
    def run(self, cmd: str):
        import subprocess
        return subprocess.check_output(cmd, shell=True)  # Command injection

# VULNERABLE: No input validation
class NoValidation(bentoml.Runnable):
    @bentoml.Runnable.method(batchable=True)
    def predict(self, data):
        return self.model(data)  # Any size/type
```

**Why**: Runners execute inference code with server privileges. Unsafe runners enable code execution or resource exhaustion.

**Refs**: CWE-94, CWE-400, CWE-502

---

## Deployment Security

### Rule: Secure BentoML Deployment Configuration

**Level**: `strict`

**When**: Deploying BentoML services to production.

**Do**:
```python
# Safe: Docker deployment with security
"""
# bentofile.yaml
docker:
  base_image: python:3.11-slim
  dockerfile_template: ./Dockerfile.template
  # Run as non-root
  user: bentoml
  system_packages:
    - libgomp1  # Only needed packages
  env:
    - PYTHONDONTWRITEBYTECODE=1
    - PYTHONUNBUFFERED=1
"""

# Safe: Dockerfile template with security hardening
"""
# Dockerfile.template
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r bentoml && useradd -r -g bentoml bentoml

# Set working directory
WORKDIR /home/bentoml

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=bentoml:bentoml . .

# Security hardening
RUN chmod -R 755 /home/bentoml && \
    chown -R bentoml:bentoml /home/bentoml

# Switch to non-root user
USER bentoml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["bentoml", "serve", "service:svc", "--port", "3000"]
"""

# Safe: Kubernetes deployment with security context
"""
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: bentoml
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            memory: "4Gi"
            cpu: "2"
            nvidia.com/gpu: 1
          requests:
            memory: "2Gi"
            cpu: "1"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /readyz
            port: 3000
"""

# Safe: Environment configuration
import os

# Load secrets from environment, not files
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY not configured")

# Use secrets manager for production
from google.cloud import secretmanager

def get_secret(secret_id: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/my-project/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")
```

**Don't**:
```python
# VULNERABLE: Run as root
"""
docker:
  base_image: python:3.11
  # No user specified
"""

# VULNERABLE: Privileged container
"""
securityContext:
  privileged: true
"""

# VULNERABLE: No resource limits
"""
containers:
- name: bentoml
  # No resource limits
"""

# VULNERABLE: Hardcoded secrets
"""
docker:
  env:
    - API_KEY=secret123  # Exposed in image
"""

# VULNERABLE: Mount sensitive paths
"""
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # Docker escape
"""
```

**Why**: Insecure deployments expose services to container escapes, resource exhaustion, and privilege escalation attacks.

**Refs**: CWE-269, CWE-250, OWASP A05:2025

---

## API Security

### Rule: Implement API Authentication and Rate Limiting

**Level**: `strict`

**When**: Exposing BentoML services as APIs.

**Do**:
```python
import bentoml
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import os
from collections import defaultdict
from time import time

# Safe: Custom authentication middleware
class AuthMiddleware:
    def __init__(self, app):
        self.app = app
        self.valid_keys = set(
            os.environ.get("API_KEYS", "").split(",")
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            api_key = headers.get(b"x-api-key", b"").decode()

            if api_key not in self.valid_keys:
                response = JSONResponse(
                    {"error": "Unauthorized"},
                    status_code=401
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)

# Safe: Rate limiting middleware
class RateLimitMiddleware:
    def __init__(self, app, requests_per_minute: int = 60):
        self.app = app
        self.rpm = requests_per_minute
        self.requests = defaultdict(list)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            client = scope.get("client", ("unknown", 0))[0]
            now = time()

            # Clean old requests
            self.requests[client] = [
                t for t in self.requests[client] if now - t < 60
            ]

            if len(self.requests[client]) >= self.rpm:
                response = JSONResponse(
                    {"error": "Rate limit exceeded"},
                    status_code=429
                )
                await response(scope, receive, send)
                return

            self.requests[client].append(now)

        await self.app(scope, receive, send)

# Safe: Service with security middleware
runner = bentoml.pytorch.get("secure_model:latest").to_runner()
svc = bentoml.Service(
    "secure_api",
    runners=[runner]
)

# Add security middleware
svc.add_asgi_middleware(AuthMiddleware)
svc.add_asgi_middleware(RateLimitMiddleware, requests_per_minute=100)
svc.add_asgi_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],
    allow_methods=["POST"],
    allow_headers=["X-API-Key"]
)

# Safe: Audit logging
import logging

logger = logging.getLogger("bentoml.security")

@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON())
async def predict(input_data: dict, ctx: bentoml.Context) -> dict:
    # Log request for audit
    logger.info(
        "Prediction request",
        extra={
            "client_ip": ctx.request.client.host,
            "input_size": len(str(input_data)),
            "timestamp": time()
        }
    )

    result = await runner.predict.async_run(input_data)
    return {"result": result}
```

**Don't**:
```python
# VULNERABLE: No authentication
@svc.api(input=bentoml.io.JSON(), output=bentoml.io.JSON())
async def predict(data: dict):
    return await runner.run(data)  # Public access

# VULNERABLE: CORS allows all
svc.add_asgi_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Any origin
    allow_methods=["*"],
    allow_headers=["*"]
)

# VULNERABLE: No rate limiting
# Allows unlimited requests

# VULNERABLE: No audit logging
# Can't track abuse or debug issues
```

**Why**: Unprotected APIs enable unauthorized access, denial of service attacks, and make security incidents difficult to investigate.

**Refs**: OWASP A01:2025, CWE-306, CWE-770

---

## OpenAPI Docs Exposure

### Rule: Gate or Disable the /docs Swagger UI in Production

**Level**: `strict`

**When**: Deploying any BentoML service accessible outside a trusted network.

**Do**:
```python
# Safe option 1: Disable docs at serve time (BentoML 1.2+)
# bentoml serve service:svc --port 3000 --no-docs

# Safe option 2: Block /docs at the reverse proxy before the request
# reaches the BentoML process. Nginx example:
"""
# nginx.conf
server {
    listen 443 ssl;

    # Require a shared secret header to reach /docs
    location /docs {
        # Deny public access entirely in production
        deny all;
        # Or restrict to internal CIDR
        # allow 10.0.0.0/8;
        # deny all;
    }

    location / {
        proxy_pass http://bentoml:3000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
"""

# Safe option 3: Traefik middleware to strip /docs
"""
# traefik labels (docker-compose)
labels:
  - "traefik.http.middlewares.strip-docs.redirectregex.regex=^.*/docs.*"
  - "traefik.http.middlewares.strip-docs.redirectregex.replacement=/"
  - "traefik.http.routers.bentoml.middlewares=strip-docs"
"""
```

**Don't**:
```python
# VULNERABLE: Default BentoML serve exposes /docs publicly
# bentoml serve service:svc --port 3000
# Any caller can reach http://host:3000/docs and inspect all routes,
# schemas, and parameter names without authentication.

# VULNERABLE: ASGI auth middleware does NOT protect /docs
# BentoML registers the OpenAPI/Swagger UI routes directly on the
# Starlette app before add_asgi_middleware runs, so middleware
# added via svc.add_asgi_middleware() is bypassed for /docs requests.
svc.add_asgi_middleware(AuthMiddleware)  # Does NOT cover /docs
```

**Why**: BentoML registers `/docs` (Swagger UI) and `/openapi.json` directly on the internal Starlette app before ASGI middleware is applied. Middleware added via `add_asgi_middleware` wraps the outer app and does not intercept these routes. An attacker with network access to the service port can enumerate every endpoint, schema, and example without credentials, aiding targeted injection or denial-of-service attacks. Gate access at the reverse proxy layer or disable docs at serve time.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-306, CWE-200

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure bento building and signing | strict | OWASP LLM03:2025, CWE-502 |
| Implement secure BentoML services | strict | CWE-20, CWE-94, OWASP LLM01:2025 |
| Configure secure runner execution | strict | CWE-94, CWE-400 |
| Secure BentoML deployment configuration | strict | CWE-269, CWE-250 |
| Implement API authentication and rate limiting | strict | OWASP A01:2025, CWE-306 |
| Gate or disable /docs Swagger UI in production | strict | OWASP A01:2025, CWE-306, CWE-200 |

---

## Version History

- **v1.1.0** - Fix OWASP LLM refs to 2025 edition; migrate validators to Pydantic v2; add /docs exposure rule; replace deprecated JSON shim
- **v1.0.0** - Initial BentoML security rules
