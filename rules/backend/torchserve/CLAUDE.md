# TorchServe Security Rules

> **ARCHIVED / END OF LIFE — DO NOT USE FOR NEW DEPLOYMENTS**
>
> TorchServe was archived by AWS and the PyTorch project in 2024. The repository
> is no longer maintained, security patches are not being issued, and a CVE backlog
> remains unresolved. See the archival announcement at
> https://github.com/pytorch/serve/discussions/3168.
>
> **For new projects, use a maintained alternative:**
> - [Triton Inference Server](https://github.com/triton-inference-server/server) (NVIDIA, actively maintained)
> - [vLLM](https://github.com/vllm-project/vllm) (LLM-focused, high-throughput)
> - [Ray Serve](https://docs.ray.io/en/latest/serve/index.html) (general-purpose, production-grade)
> - [BentoML](https://github.com/bentoml/BentoML) (framework-agnostic, cloud-native)
>
> The rules below are retained as **legacy support guidance only** for teams that
> cannot migrate existing TorchServe deployments immediately.

Security rules for PyTorch TorchServe model serving in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Model Archive Security

### Rule: Validate MAR File Integrity

**Level**: `strict`

**When**: Creating or loading Model Archive (MAR) files.

**Do**:
```python
import hashlib
import os
from pathlib import Path

# Safe: Create MAR with integrity check
def create_secure_mar(
    model_name: str,
    serialized_file: str,
    handler: str,
    output_path: str
) -> str:
    """Create MAR file with security validations"""

    # Validate handler is from trusted source
    TRUSTED_HANDLERS = [
        "image_classifier",
        "text_classifier",
        "object_detector"
    ]

    if handler not in TRUSTED_HANDLERS and not handler.endswith(".py"):
        raise ValueError(f"Unknown handler: {handler}")

    if handler.endswith(".py"):
        # Verify the handler file exists before packaging.
        # Do NOT use substring denylist checks as a security control — they are
        # trivially bypassed via string concatenation, importlib, or getattr().
        # Real protection comes from MAR signing (below) and OS sandboxing.
        handler_path = Path(handler)
        if not handler_path.exists():
            raise ValueError("Handler file not found")

    # Create MAR
    import subprocess
    result = subprocess.run([
        "torch-model-archiver",
        "--model-name", model_name,
        "--version", "1.0",
        "--serialized-file", serialized_file,
        "--handler", handler,
        "--export-path", output_path
    ], capture_output=True, check=True)

    # Generate checksum AND sign the archive with cosign or GPG.
    # Signature verification at load time proves the archive was reviewed and
    # packaged by a trusted party — substring denylist checks do not.
    mar_path = Path(output_path) / f"{model_name}.mar"
    checksum = hashlib.sha256(mar_path.read_bytes()).hexdigest()

    # Save checksum for transport integrity
    checksum_file = mar_path.with_suffix(".sha256")
    checksum_file.write_text(checksum)

    # Sign with cosign (keyless OIDC) or GPG — choose one and enforce at load time:
    #   cosign sign-blob --yes --bundle model.mar.bundle model.mar
    #   gpg --detach-sign --armor model.mar

    return str(mar_path)

# Safe: Verify MAR signature and checksum before loading.
# Cryptographic verification is the primary control; checksum covers transport
# integrity only and does not replace signing.
def verify_mar(mar_path: str, expected_hash: str) -> bool:
    path = Path(mar_path)
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        return False
    # Also verify cosign bundle or GPG signature before returning True:
    #   cosign verify-blob --bundle model.mar.bundle model.mar
    #   gpg --verify model.mar.asc model.mar
    return True

# Safe: Model store configuration
"""
# config.properties
model_store=/models
load_models=verified_model.mar
# Don't allow runtime model loading from arbitrary sources
enable_model_api=false
"""
```

**Don't**:
```python
# VULNERABLE: Load MAR without verification
def load_any_mar(mar_path: str):
    subprocess.run(["torchserve", "--models", f"model={mar_path}"])

# VULNERABLE: Custom handler with shell access
"""
# handler.py
import subprocess

class UnsafeHandler:
    def handle(self, data, context):
        cmd = data[0].get("command")
        return subprocess.check_output(cmd, shell=True)
"""

# VULNERABLE: Pickle-based model loading in handler
"""
class Handler:
    def initialize(self, context):
        import pickle
        self.model = pickle.load(open("model.pkl", "rb"))  # RCE risk
"""
```

**Why**: MAR files can contain malicious code in custom handlers or poisoned model weights. Cryptographic signing of the archive proves it was reviewed by a trusted party before loading. Static substring checks on handler source are trivially bypassed (string concatenation, importlib, getattr) and must not be used as a primary control. Handler code executes with full server process privileges; OS-level sandboxing (gVisor, Docker with `--security-opt=no-new-privileges`, seccomp profile) is required to contain a compromised handler. Static analysis of handler source is defense-in-depth only.

**Refs**: OWASP LLM03:2025 (Supply Chain Vulnerabilities), CWE-502, MITRE ATLAS AML.T0010

---

## Custom Handler Security

### Rule: Implement Secure Custom Handlers

**Level**: `strict`

**When**: Writing custom inference handlers.

**Do**:
```python
# handler.py - Secure custom handler
from ts.torch_handler.base_handler import BaseHandler
import torch
import json
import numpy as np

class SecureImageClassifier(BaseHandler):
    def __init__(self):
        super().__init__()
        self.max_image_size = 10 * 1024 * 1024  # 10MB
        self.max_batch_size = 32

    def initialize(self, context):
        """Secure initialization"""
        properties = context.system_properties
        model_dir = properties.get("model_dir")

        # Load model safely (use TorchScript, not pickle)
        model_path = f"{model_dir}/model.pt"
        self.model = torch.jit.load(model_path)
        self.model.eval()

        # Validate model is on expected device
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.model.to(self.device)

    def preprocess(self, data):
        """Validate and preprocess inputs"""
        images = []

        for row in data:
            # Get image data
            image = row.get("data") or row.get("body")

            if image is None:
                raise ValueError("No image data provided")

            # Validate size
            if len(image) > self.max_image_size:
                raise ValueError(f"Image too large: {len(image)} bytes")

            # Safely decode image
            try:
                if isinstance(image, (bytes, bytearray)):
                    image = self._decode_image(image)
                else:
                    raise ValueError("Invalid image format")
            except Exception as e:
                raise ValueError(f"Failed to decode image: {e}")

            images.append(image)

        # Validate batch size
        if len(images) > self.max_batch_size:
            raise ValueError(f"Batch too large: {len(images)}")

        return torch.stack(images).to(self.device)

    def _decode_image(self, image_bytes: bytes) -> torch.Tensor:
        """Safely decode image bytes"""
        from PIL import Image
        import io

        # Validate image header
        if not (image_bytes[:8] == b'\x89PNG\r\n\x1a\n' or
                image_bytes[:2] == b'\xff\xd8'):
            raise ValueError("Invalid image format")

        img = Image.open(io.BytesIO(image_bytes))

        # Validate dimensions
        if img.width > 4096 or img.height > 4096:
            raise ValueError("Image dimensions too large")

        # Convert to tensor
        img = img.convert("RGB").resize((224, 224))
        tensor = torch.tensor(np.array(img)).permute(2, 0, 1).float() / 255
        return tensor

    def inference(self, data):
        """Run inference with resource limits"""
        with torch.no_grad():
            return self.model(data)

    def postprocess(self, inference_output):
        """Sanitize outputs"""
        results = []
        for output in inference_output:
            # Convert to list, limit precision
            probs = torch.softmax(output, dim=0)
            top5 = torch.topk(probs, 5)

            results.append({
                "predictions": [
                    {"class": idx.item(), "probability": round(prob.item(), 4)}
                    for idx, prob in zip(top5.indices, top5.values)
                ]
            })

        return results
```

**Don't**:
```python
# VULNERABLE: No input validation
class UnsafeHandler(BaseHandler):
    def preprocess(self, data):
        return torch.tensor(data[0]["body"])  # No validation

    def inference(self, data):
        return self.model(data)  # Could be huge tensor

# VULNERABLE: Shell command in handler
class CommandHandler(BaseHandler):
    def handle(self, data, context):
        import subprocess
        cmd = data[0].get("cmd")
        return subprocess.run(cmd, shell=True)  # RCE

# VULNERABLE: Arbitrary file access
class FileHandler(BaseHandler):
    def handle(self, data, context):
        path = data[0].get("path")
        return open(path).read()  # Path traversal

# VULNERABLE: Pickle in handler
class PickleHandler(BaseHandler):
    def handle(self, data, context):
        import pickle
        return pickle.loads(data[0]["body"])  # Arbitrary code
```

**Why**: Custom handlers execute with server privileges. Unsafe handlers enable RCE, data exfiltration, or denial of service.

**Refs**: CWE-94, CWE-78, CWE-22

---

## Management API Security

### Rule: Secure Management API Access

**Level**: `strict`

**When**: Configuring TorchServe management endpoints.

**Do**:
```python
# config.properties - Secure configuration
"""
# Bind management to localhost only
management_address=http://127.0.0.1:8081

# Or disable entirely in production
enable_model_api=false

# Require authentication (custom middleware)
# Use reverse proxy for auth

# Limit concurrent requests
job_queue_size=100
number_of_netty_threads=4
max_request_size=10485760

# Disable metrics endpoint if not needed
enable_metrics_api=false

# Model snapshot for controlled loading
model_snapshot={"name":"startup.cfg","modelCount":1,"models":{"model":{"1.0":{"defaultVersion":true}}}}
"""

# Safe: Proxy management API with authentication
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader
import httpx
import os

app = FastAPI()
api_key_header = APIKeyHeader(name="X-API-Key")

TORCHSERVE_MGMT = "http://127.0.0.1:8081"
VALID_KEYS = set(os.environ.get("API_KEYS", "").split(","))

async def verify_key(api_key: str = Depends(api_key_header)):
    if api_key not in VALID_KEYS:
        raise HTTPException(status_code=401)
    return api_key

# Safe: Controlled model registration
ALLOWED_MODELS = {"classifier", "detector"}

@app.post("/models/{model_name}")
async def register_model(
    model_name: str,
    api_key: str = Depends(verify_key)
):
    if model_name not in ALLOWED_MODELS:
        raise HTTPException(403, "Model not allowed")

    # Only load from verified store
    url = f"model_{model_name}.mar"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{TORCHSERVE_MGMT}/models",
            params={"url": url, "model_name": model_name}
        )

    return response.json()

# Safe: Model unloading with audit
@app.delete("/models/{model_name}")
async def unload_model(
    model_name: str,
    api_key: str = Depends(verify_key)
):
    # Log the action
    import logging
    logging.info(f"Model unload: {model_name} by {api_key}")

    async with httpx.AsyncClient() as client:
        response = await client.delete(
            f"{TORCHSERVE_MGMT}/models/{model_name}"
        )

    return response.json()
```

**Don't**:
```python
# VULNERABLE: Management API exposed publicly
"""
management_address=http://0.0.0.0:8081
"""

# VULNERABLE: No authentication
@app.post("/models")
async def register_model(url: str):
    # Anyone can register models
    return httpx.post(f"{MGMT}/models", params={"url": url})

# VULNERABLE: Allow arbitrary model URLs
@app.post("/models")
async def register_any(url: str):
    # Load from any URL - SSRF and supply chain attack
    return httpx.post(f"{MGMT}/models", params={"url": url})

# VULNERABLE: No audit logging
@app.delete("/models/{name}")
async def delete(name: str):
    return httpx.delete(f"{MGMT}/models/{name}")  # No logging
```

**Why**: Exposed management API allows attackers to load malicious models, unload production models, or exfiltrate model data.

**Refs**: OWASP A01:2025, CWE-306, CWE-918

---

## Inference API Security

### Rule: Validate Inference Requests

**Level**: `strict`

**When**: Serving inference requests.

**Do**:
```python
# config.properties - Request limits
"""
# Size limits
max_request_size=10485760
max_response_size=10485760

# Timeout limits
default_response_timeout=120

# Queue limits
job_queue_size=100

# Worker configuration
default_workers_per_model=1
"""

# Safe: Client with validation
import httpx
from pydantic import BaseModel, validator

class InferenceRequest(BaseModel):
    data: bytes
    content_type: str = "application/octet-stream"

    @validator("data")
    def validate_size(cls, v):
        if len(v) > 10_000_000:
            raise ValueError("Data too large")
        return v

    @validator("content_type")
    def validate_type(cls, v):
        allowed = ["application/octet-stream", "application/json"]
        if v not in allowed:
            raise ValueError(f"Invalid content type: {v}")
        return v

class SecureTorchServeClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.client = httpx.Client(timeout=30)

    def predict(self, model_name: str, data: bytes) -> dict:
        # Validate model name
        if not model_name.isalnum():
            raise ValueError("Invalid model name")

        # Validate request
        request = InferenceRequest(data=data)

        response = self.client.post(
            f"{self.base_url}/predictions/{model_name}",
            content=request.data,
            headers={"Content-Type": request.content_type}
        )

        if response.status_code != 200:
            raise RuntimeError(f"Inference failed: {response.text}")

        return response.json()

    def health_check(self) -> bool:
        response = self.client.get(f"{self.base_url}/ping")
        return response.status_code == 200

# Safe: Rate limiting middleware
from fastapi import FastAPI, Request
from collections import defaultdict
from time import time

app = FastAPI()
request_counts = defaultdict(list)

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    client_ip = request.client.host
    now = time()

    # Clean old requests
    request_counts[client_ip] = [
        t for t in request_counts[client_ip] if now - t < 60
    ]

    if len(request_counts[client_ip]) >= 100:
        return JSONResponse(status_code=429, content={"error": "Rate limit"})

    request_counts[client_ip].append(now)
    return await call_next(request)
```

**Don't**:
```python
# VULNERABLE: No request validation
def predict(model_name: str, data: bytes):
    return httpx.post(
        f"http://localhost:8080/predictions/{model_name}",
        content=data  # No size/type validation
    )

# VULNERABLE: User-controlled model name
@app.post("/predict/{model}")
async def predict(model: str, data: bytes):
    return httpx.post(f"{SERVE}/predictions/{model}", content=data)
    # Allows accessing any model

# VULNERABLE: No timeout
client = httpx.Client()  # Default timeout might be too long
```

**Why**: Unvalidated inference requests enable denial of service through oversized payloads, unbounded batch sizes, or resource exhaustion on GPU/CPU workers.

**Refs**: OWASP LLM10:2025 (Unbounded Consumption), CWE-400, CWE-770

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Validate MAR file integrity | strict | OWASP LLM03:2025 (Supply Chain), CWE-502 |
| Implement secure custom handlers | strict | CWE-94, CWE-78 |
| Secure management API access | strict | OWASP A01:2025, CWE-306 |
| Validate inference requests | strict | OWASP LLM10:2025 (Unbounded Consumption), CWE-400 |

---

## Version History

- **v1.0.0** - Initial TorchServe security rules
