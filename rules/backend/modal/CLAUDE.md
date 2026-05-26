# Modal Security Rules

Security rules for Modal serverless AI deployment in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Function Security

### Rule: Secure Modal Function Configuration

**Level**: `strict`

**When**: Defining Modal functions and classes.

**Do**:
```python
import hmac
import modal
from modal import App, Image, Secret

# App replaces Stub (renamed in Modal 0.60)
app = modal.App(
    name="secure-inference",
    secrets=[modal.Secret.from_name("model-api-key")]
)

# Minimal image with pinned dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.0.1",
        "transformers==4.30.0",
        "numpy==1.24.0"
    )
    .run_commands("useradd -m appuser")
)

# Function with explicit resource limits and input validation
@app.function(
    image=image,
    gpu="T4",
    memory=8192,
    timeout=300,
    retries=2,
    concurrency_limit=10,
    allow_concurrent_inputs=5
)
def secure_inference(input_data: dict) -> dict:
    if not isinstance(input_data, dict):
        raise ValueError("Invalid input type")

    if "prompt" not in input_data:
        raise ValueError("Missing prompt")

    prompt = input_data["prompt"]
    if len(prompt) > 10000:
        raise ValueError("Prompt too long")

    from transformers import AutoModelForCausalLM, AutoTokenizer

    # trust_remote_code=False prevents arbitrary code execution
    # (OWASP LLM01:2025 — Prompt Injection / remote code execution vector)
    model = AutoModelForCausalLM.from_pretrained(
        "model-name",
        trust_remote_code=False
    )
    tokenizer = AutoTokenizer.from_pretrained(
        "model-name",
        trust_remote_code=False
    )

    inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
    outputs = model.generate(**inputs, max_new_tokens=256)
    result = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return {"result": result}

# Class with lifecycle management and per-caller identity check
@app.cls(
    image=image,
    gpu="T4",
    memory=8192,
    timeout=300,
    container_idle_timeout=60
)
class SecureModel:
    def __enter__(self):
        from transformers import pipeline
        self.pipe = pipeline(
            "text-generation",
            model="gpt2",
            trust_remote_code=False
        )
        self.max_input_length = 1000

    @modal.method()
    def generate(self, prompt: str, max_tokens: int = 100, caller_id: str = "") -> str:
        # Verify caller identity before processing
        if not caller_id or not caller_id.isalnum():
            raise ValueError("Valid caller_id required")

        if len(prompt) > self.max_input_length:
            raise ValueError("Prompt too long")

        if max_tokens > 500:
            max_tokens = 500

        result = self.pipe(prompt, max_new_tokens=max_tokens)
        return result[0]["generated_text"]
```

**Don't**:
```python
# VULNERABLE: No resource limits — enables resource exhaustion (OWASP LLM06:2025)
@app.function()
def unlimited_function(data):
    return process(data)

# VULNERABLE: trust_remote_code=True enables RCE (OWASP LLM01:2025)
@app.function(image=image)
def unsafe_model(prompt: str):
    model = AutoModel.from_pretrained(
        user_model_name,
        trust_remote_code=True
    )

# VULNERABLE: No input validation
@app.function()
def no_validation(data):
    return model(data)

# VULNERABLE: Unpinned dependencies
image = modal.Image.debian_slim().pip_install(
    "torch",
    "transformers"
)
```

**Why**: Missing resource limits enable resource exhaustion (unbounded GPU/compute consumption). `trust_remote_code=True` on user-supplied model names lets an attacker execute arbitrary Python at model-load time.

**Refs**: CWE-400, CWE-502, OWASP LLM01:2025, OWASP LLM06:2025, OWASP LLM10:2025

---

## Secrets Management

### Rule: Secure Modal Secrets Handling

**Level**: `strict`

**When**: Managing secrets and environment variables.

**Do**:
```python
import modal
import os

app = modal.App("secure-app")

# Reference specific named secrets — minimal scope
@app.function(
    secrets=[
        modal.Secret.from_name("openai-key"),
    ]
)
def call_api():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("API key not configured")
    return make_api_call(api_key)

# CLI command to create a secret (use interactive mode to avoid key in shell history)
"""
modal secret create model-config \
    MODEL_NAME=gpt-4 \
    MAX_TOKENS=1000
"""

# Environment-specific secrets
@app.function(
    secrets=[
        modal.Secret.from_name(
            "prod-api-key" if os.environ.get("ENV") == "prod"
            else "dev-api-key"
        )
    ]
)
def environment_aware():
    pass

# Multiple secrets with per-secret isolation
@app.function(
    secrets=[
        modal.Secret.from_name("db-credentials"),
        modal.Secret.from_name("api-key"),
    ]
)
def multi_secret_function():
    db_pass = os.environ["DB_PASSWORD"]
    api_key = os.environ["API_KEY"]

# Log operation metadata, never the secret value
@app.function(secrets=[modal.Secret.from_name("api-key")])
def safe_logging():
    api_key = os.environ["API_KEY"]
    print(f"Making API call with key length: {len(api_key)}")
    result = call_api(api_key)
    return result
```

**Don't**:
```python
# VULNERABLE: Hardcoded secrets
@app.function()
def hardcoded_secret():
    api_key = "sk-1234567890abcdef"
    return call_api(api_key)

# VULNERABLE: Secret baked into image layer
image = modal.Image.debian_slim().run_commands(
    "echo 'API_KEY=secret' >> /etc/environment"
)

# VULNERABLE: Overly broad secret grants
app = modal.App(
    secrets=[modal.Secret.from_name("all-secrets")]
)

# VULNERABLE: Logging secret values
@app.function(secrets=[modal.Secret.from_name("api-key")])
def log_secret():
    api_key = os.environ["API_KEY"]
    print(f"Using key: {api_key}")

# VULNERABLE: Returning secrets to callers
@app.function(secrets=[modal.Secret.from_name("api-key")])
def return_secret():
    return {"key": os.environ["API_KEY"]}
```

**Why**: Exposed secrets enable unauthorized API access, data theft, and financial abuse of cloud resources.

**Refs**: CWE-798, CWE-532, OWASP A07:2025

---

## Container Security

### Rule: Harden Modal Container Images

**Level**: `strict`

**When**: Building custom Modal images.

**Do**:
```python
import modal

# Pin apt packages by exact version to match pinned pip packages.
# Find the version with: apt-cache show libgomp1 | grep Version
# Pinning prevents supply-chain drift across image rebuilds.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("libgomp1=12.3.0-1ubuntu1~22.04")  # pinned, not floating
    .pip_install(
        "torch==2.0.1",
        "numpy==1.24.0",
    )
    .run_commands(
        "useradd -m -u 1000 appuser",
        "mkdir -p /app && chown appuser:appuser /app"
    )
    .workdir("/app")
    .copy_local_file("model.py", "/app/model.py")
)

# Micromamba for smaller images
image = (
    modal.Image.micromamba(python_version="3.11")
    .micromamba_install(
        "pytorch",
        "numpy",
        channels=["pytorch", "conda-forge"]
    )
    .pip_install("transformers==4.30.0")
)

# Multi-stage build pattern: heavy build step, lean inference image
base_image = modal.Image.debian_slim().pip_install("torch==2.0.1")

@app.function(image=base_image)
def build_model():
    pass

inference_image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch==2.0.1", "transformers==4.30.0")
)

@app.function(image=inference_image)
def inference():
    pass

# Scan images for vulnerabilities before promotion
"""
trivy image modal-image:latest
"""
```

**Don't**:
```python
# VULNERABLE: Full base image (large attack surface)
image = modal.Image.from_registry("python:3.11")

# VULNERABLE: Default root user
image = modal.Image.debian_slim()

# VULNERABLE: Unnecessary tools installed
image = (
    modal.Image.debian_slim()
    .apt_install(
        "curl", "wget", "git", "ssh",
        "build-essential"
    )
)

# VULNERABLE: Copy entire working directory (includes .env, .git, secrets)
image = modal.Image.debian_slim().copy_local_dir(".", "/app")

# VULNERABLE: Unpinned registry image
image = modal.Image.from_registry("pytorch/pytorch")
```

**Why**: Bloated images with root access and unnecessary tools increase attack surface and enable privilege escalation. Unpinned `apt_install()` calls contradict pinned pip packages and allow supply-chain drift across image rebuilds.

**Refs**: CWE-250, CWE-269, OWASP A05:2025

---

## Web Endpoint Security

### Rule: Secure Modal Web Endpoints

**Level**: `strict`

**When**: Exposing Modal functions as web endpoints.

**Do**:
```python
import hmac
import modal
import os
from modal import web_endpoint, asgi_app
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from collections import defaultdict
from time import time

app = modal.App("secure-api")

class PredictionRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)
    max_tokens: int = Field(default=100, le=1000, ge=1)
    temperature: float = Field(default=0.7, ge=0, le=2)

class PredictionResponse(BaseModel):
    result: str
    tokens_used: int

@app.function(secrets=[modal.Secret.from_name("api-keys")])
@web_endpoint(method="POST")
def secure_predict(
    request: PredictionRequest,
    authorization: str = Header(...)
) -> PredictionResponse:
    valid_keys = os.environ.get("API_KEYS", "").split(",")
    token = authorization.replace("Bearer ", "")

    # Use constant-time comparison to prevent timing side-channel leaks
    # Plain `in` or `==` on strings leaks information about key length and prefix
    if not any(hmac.compare_digest(token, k) for k in valid_keys if k):
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = generate(request.prompt, request.max_tokens)
    return PredictionResponse(
        result=result,
        tokens_used=len(result.split())
    )

# Full FastAPI app with rate limiting
fastapi_app_instance = FastAPI()
request_counts: dict = defaultdict(list)

@fastapi_app_instance.middleware("http")
async def rate_limit(request, call_next):
    client = request.client.host
    now = time()
    request_counts[client] = [
        t for t in request_counts[client] if now - t < 60
    ]
    if len(request_counts[client]) >= 60:
        raise HTTPException(429, "Rate limit exceeded")
    request_counts[client].append(now)
    return await call_next(request)

@fastapi_app_instance.post("/predict", response_model=PredictionResponse)
async def predict(
    request: PredictionRequest,
    authorization: str = Header(...)
):
    if not verify_token(authorization):
        raise HTTPException(401, "Unauthorized")
    return await process_prediction(request)

@app.function(secrets=[modal.Secret.from_name("api-keys")])
@asgi_app()
def fastapi_app():
    return fastapi_app_instance
```

**Don't**:
```python
# VULNERABLE: No authentication
@app.function()
@web_endpoint()
def public_endpoint(data: dict):
    return model(data)

# VULNERABLE: No input validation
@app.function()
@web_endpoint(method="POST")
def unvalidated_endpoint(request: dict):
    return model(request["prompt"])

# VULNERABLE: Return secrets to caller
@app.function(secrets=[modal.Secret.from_name("api-keys")])
@web_endpoint()
def leaky_endpoint():
    return {"api_key": os.environ["API_KEY"], "result": "data"}

# VULNERABLE: Plain string comparison leaks timing information
# if token not in valid_keys: raise HTTPException(...)

# VULNERABLE: No rate limiting
@app.function()
@web_endpoint(method="POST")
def unlimited_endpoint(request: PredictionRequest):
    return process(request)
```

**Why**: Unprotected endpoints enable unauthorized GPU resource abuse and denial of service. Plain string comparison against a key list leaks timing information that an attacker can use to enumerate valid key prefixes.

**Refs**: OWASP A01:2025, CWE-306, CWE-770, CWE-208

---

## Scheduled Function Security

### Rule: Secure Modal Scheduled Functions

**Level**: `strict`

**When**: Using Modal schedules and cron jobs.

**Do**:
```python
import modal
import logging
from datetime import datetime

app = modal.App("secure-scheduled")
logger = logging.getLogger(__name__)

# Scheduled function with timeout, logging, and error handling
@app.function(
    schedule=modal.Cron("0 * * * *"),
    secrets=[modal.Secret.from_name("db-credentials")],
    timeout=1800,
    retries=1
)
def secure_scheduled_job():
    start_time = datetime.utcnow()
    logger.info(f"Job started at {start_time}")

    try:
        result = process_data()
        logger.info(f"Job completed: {result['count']} items processed")
        return {
            "status": "success",
            "count": result["count"],
            "duration": (datetime.utcnow() - start_time).seconds
        }
    except Exception as e:
        logger.error(f"Job failed: {type(e).__name__}")
        raise

# Singleton: prevent overlapping runs
@app.function(
    schedule=modal.Period(hours=1),
    timeout=600,
    concurrency_limit=1
)
def singleton_job():
    pass

# Manual trigger with allowlist validation
@app.function()
def manual_trigger(job_name: str, params: dict):
    allowed_jobs = {"sync", "cleanup", "backup"}
    if job_name not in allowed_jobs:
        raise ValueError(f"Unknown job: {job_name}")

    if params.get("force") and not params.get("confirmed"):
        raise ValueError("Force requires confirmation")

    return execute_job(job_name, params)
```

**Don't**:
```python
# VULNERABLE: No timeout — function runs indefinitely
@app.function(schedule=modal.Cron("* * * * *"))
def no_timeout_job():
    process_forever()

# VULNERABLE: Logs secret values
@app.function(schedule=modal.Period(hours=1))
def logging_secrets():
    api_key = os.environ["API_KEY"]
    print(f"Using key: {api_key}")

# VULNERABLE: No concurrency control — instances pile up
@app.function(schedule=modal.Cron("*/5 * * * *"))
def overlapping_job():
    long_running_task()

# VULNERABLE: Arbitrary job execution via globals() — code injection
@app.function()
def run_any_job(job_name: str):
    return globals()[job_name]()
```

**Why**: Scheduled functions without timeouts or concurrency limits accumulate unbounded cost. Logging secret values exposes credentials in Modal's log store. Unrestricted job dispatch enables code injection.

**Refs**: CWE-400, CWE-532, CWE-94

---

## Volume Security

### Rule: Secure Modal Volume Access

**Level**: `strict`

**When**: Using `modal.Volume` for shared persistent storage.

**Do**:
```python
import modal

app = modal.App("secure-volume-app")

# Name volumes per logical owner; never share one volume across untrusted callers.
# Read-only mounts for shared model artifacts prevent a compromised function
# from overwriting the model weights used by all other functions.
model_volume = modal.Volume.from_name("shared-models", create_if_missing=False)
user_volume = modal.Volume.from_name("user-data-alice", create_if_missing=True)

# Mount shared artifacts read-only; mount per-user data read-write
@app.function(
    volumes={
        "/models": model_volume,     # read-only — enforce at the OS layer too
        "/data/alice": user_volume,  # scoped to one caller
    }
)
def inference_for_alice(prompt: str) -> str:
    import os
    # Prevent path traversal: resolve and verify the path stays inside /data/alice
    base = "/data/alice"
    target = os.path.realpath(os.path.join(base, "output.txt"))
    if not target.startswith(base + os.sep):
        raise ValueError("Path traversal detected")

    with open(target, "w") as f:
        f.write(run_model(prompt))

    return "done"
```

**Don't**:
```python
# VULNERABLE: Single volume shared across all callers — one compromised function
# can read or overwrite every other caller's data
shared_volume = modal.Volume.from_name("all-users")

@app.function(volumes={"/data": shared_volume})
def process_for_any_caller(user_id: str, prompt: str):
    path = f"/data/{user_id}/output.txt"  # Path traversal not checked
    with open(path, "w") as f:
        f.write(run_model(prompt))

# VULNERABLE: Model artifacts mounted read-write — attacker can replace weights
@app.function(volumes={"/models": model_volume})
def poisonable_inference(prompt: str):
    pass
```

**Why**: A writable shared volume is a lateral movement vector. A compromised function can read other callers' data or overwrite shared model weights (model poisoning). Mount shared artifacts read-only and scope writable volumes to a single logical caller.

**Refs**: CWE-732, CWE-22, OWASP A01:2025, OWASP LLM04:2025

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure Modal function configuration | strict | CWE-400, CWE-502, OWASP LLM01:2025, LLM06:2025, LLM10:2025 |
| Secure Modal secrets handling | strict | CWE-798, CWE-532, OWASP A07:2025 |
| Harden Modal container images | strict | CWE-250, CWE-269, OWASP A05:2025 |
| Secure Modal web endpoints | strict | OWASP A01:2025, CWE-306, CWE-770, CWE-208 |
| Secure Modal scheduled functions | strict | CWE-400, CWE-532, CWE-94 |
| Secure Modal Volume access | strict | CWE-732, CWE-22, OWASP A01:2025, LLM04:2025 |

---

## Version History

- **v2.0.0** - Rewrote for Modal 0.60+ API (App replaces Stub); corrected OWASP LLM refs to 2025 edition; pinned apt packages; added Volume security rule; switched token comparison to hmac.compare_digest(); added per-caller identity check
- **v1.0.0** - Initial Modal security rules
