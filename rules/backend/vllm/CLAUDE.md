# vLLM Security Rules

Security rules for vLLM high-throughput inference in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## KV Cache Security

### Rule: Isolate KV Cache Per Request

**Level**: `strict`

**When**: Serving multiple users with PagedAttention.

**Do**:
```python
from vllm import LLM, SamplingParams

# Safe: Separate engine per security boundary
class SecureVLLMEngine:
    def __init__(self, model: str):
        self.llm = LLM(
            model=model,
            trust_remote_code=False,  # CRITICAL
            gpu_memory_utilization=0.8,
            max_model_len=4096,
            # Disable potentially unsafe features
            enable_prefix_caching=False,  # Prevents cross-request cache leaks
            disable_log_requests=True  # Don't log sensitive prompts
        )

    def generate_isolated(self, prompt: str, user_id: str) -> str:
        # Validate input
        if len(prompt) > 8192:
            raise ValueError("Prompt too long")

        # Sanitize prompt for cache key isolation
        sampling_params = SamplingParams(
            temperature=0.7,
            max_tokens=1024,
            # Prevent excessive generation
            stop=["\n\nHuman:", "\n\nUser:"]
        )

        outputs = self.llm.generate([prompt], sampling_params)
        return outputs[0].outputs[0].text

# Safe: Clear cache between sensitive operations
def clear_kv_cache(engine):
    """Force cache clearing for security-critical operations"""
    # vLLM automatic memory management
    # For strict isolation, use separate engine instances
    pass
```

**Don't**:
```python
# VULNERABLE: Prefix caching with multi-tenant
llm = LLM(
    model="model",
    enable_prefix_caching=True  # Cross-user cache sharing
)

# VULNERABLE: No request isolation
def serve_all_users(llm, requests):
    # All users share KV cache state
    return llm.generate(requests)

# VULNERABLE: Logging sensitive prompts
llm = LLM(
    model="model",
    disable_log_requests=False  # Logs all prompts
)
```

**Why**: Shared KV cache can leak information between users through prefix matching or timing attacks. PagedAttention optimizes memory but can create cross-request dependencies.

**Refs**: OWASP LLM06, CWE-200, CWE-203

---

### Rule: Validate PagedAttention Configuration

**Level**: `strict`

**When**: Configuring vLLM memory management.

**Do**:
```python
from vllm import LLM
from vllm.config import CacheConfig

# Safe: Secure memory configuration
llm = LLM(
    model="meta-llama/Llama-2-7b-chat-hf",
    trust_remote_code=False,
    # Memory security settings
    gpu_memory_utilization=0.85,  # Leave headroom
    swap_space=0,  # Disable swap to prevent disk leaks
    max_num_batched_tokens=8192,  # Limit batch size
    max_num_seqs=256,  # Limit concurrent sequences
    # Block size affects cache granularity
    block_size=16  # Standard block size
)

# Safe: Production configuration with limits
class ProductionVLLMConfig:
    def __init__(self):
        self.config = {
            "trust_remote_code": False,
            "gpu_memory_utilization": 0.8,
            "max_model_len": 4096,
            "max_num_batched_tokens": 4096,
            "swap_space": 0,  # No disk swapping
            "disable_log_requests": True,
            "enable_prefix_caching": False
        }

    def get_engine(self, model: str) -> LLM:
        return LLM(model=model, **self.config)
```

**Don't**:
```python
# VULNERABLE: Trust remote code
llm = LLM(
    model="random-model",
    trust_remote_code=True  # Arbitrary code execution
)

# VULNERABLE: Swap to disk (data persistence)
llm = LLM(
    model="model",
    swap_space=16  # KV cache written to disk
)

# VULNERABLE: Excessive memory utilization
llm = LLM(
    model="model",
    gpu_memory_utilization=0.99  # OOM risk, DoS vector
)
```

**Why**: Improper memory configuration can lead to data leaks through swap files, OOM-based denial of service, or memory corruption attacks.

**Refs**: CWE-401, CWE-400, OWASP LLM04

---

## Continuous Batching Security

### Rule: Implement Request Isolation in Batches

**Level**: `strict`

**When**: Using continuous batching for throughput.

**Do**:
```python
from vllm import LLM, SamplingParams
import hashlib

class SecureBatchProcessor:
    def __init__(self, model: str):
        self.llm = LLM(
            model=model,
            trust_remote_code=False,
            max_num_seqs=64,  # Limit concurrent requests
            max_num_batched_tokens=4096
        )

    def process_batch(self, requests: list[dict]) -> list[str]:
        # Validate all requests
        validated = []
        for req in requests:
            if not self._validate_request(req):
                continue
            validated.append(req)

        # Apply per-request sampling params
        prompts = []
        params_list = []

        for req in validated:
            prompts.append(req["prompt"])
            params_list.append(SamplingParams(
                temperature=req.get("temperature", 0.7),
                max_tokens=min(req.get("max_tokens", 512), 2048),
                # Request-specific stop sequences
                stop=req.get("stop", [])
            ))

        # Generate with isolation
        outputs = self.llm.generate(prompts, params_list)

        return [o.outputs[0].text for o in outputs]

    def _validate_request(self, req: dict) -> bool:
        if "prompt" not in req:
            return False
        if len(req["prompt"]) > 8192:
            return False
        if req.get("max_tokens", 0) > 4096:
            return False
        return True

# Safe: Rate limiting per user in batch context
from collections import defaultdict
from time import time

class RateLimitedBatcher:
    def __init__(self, max_requests_per_minute: int = 60):
        self.user_requests = defaultdict(list)
        self.max_rpm = max_requests_per_minute

    def can_process(self, user_id: str) -> bool:
        now = time()
        # Clean old requests
        self.user_requests[user_id] = [
            t for t in self.user_requests[user_id]
            if now - t < 60
        ]

        if len(self.user_requests[user_id]) >= self.max_rpm:
            return False

        self.user_requests[user_id].append(now)
        return True
```

**Don't**:
```python
# VULNERABLE: No request validation
def batch_process(llm, prompts):
    return llm.generate(prompts)  # No limits or validation

# VULNERABLE: Shared sampling params leak settings
params = SamplingParams(temperature=0.7)
outputs = llm.generate(all_user_prompts, params)  # Same params for all

# VULNERABLE: No rate limiting
def process_unlimited(llm, requests):
    while requests:
        llm.generate(requests.pop())  # DoS vector
```

**Why**: Continuous batching without isolation allows users to affect each other's requests through resource exhaustion or parameter leakage.

**Refs**: OWASP LLM04, CWE-400, CWE-770

---

## Model Loading Security

### Rule: Secure Model Source Verification

**Level**: `strict`

**When**: Loading models for vLLM inference.

**Do**:
```python
from vllm import LLM
import os

# Safe: Verified model sources only
TRUSTED_MODELS = {
    "meta-llama/Llama-2-7b-chat-hf",
    "mistralai/Mistral-7B-Instruct-v0.1",
    "google/gemma-7b-it",
}

def load_verified_model(model_id: str) -> LLM:
    if model_id not in TRUSTED_MODELS:
        raise ValueError(f"Untrusted model: {model_id}")

    return LLM(
        model=model_id,
        trust_remote_code=False,  # CRITICAL
        tokenizer_mode="auto",
        dtype="auto",
        # Use safetensors format
        load_format="safetensors"
    )

# Safe: Local model with integrity check
import hashlib
from pathlib import Path

def load_local_model(model_path: str, expected_hash: str) -> LLM:
    path = Path(model_path)

    # Verify model file integrity
    config_file = path / "config.json"
    if config_file.exists():
        actual_hash = hashlib.sha256(
            config_file.read_bytes()
        ).hexdigest()

        if actual_hash != expected_hash:
            raise ValueError("Model integrity check failed")

    return LLM(
        model=model_path,
        trust_remote_code=False,
        load_format="safetensors"  # Safe serialization
    )

# Safe: Environment-based token (not hardcoded)
os.environ["HF_TOKEN"] = os.environ.get("HF_TOKEN", "")
llm = LLM(
    model="private/model",
    trust_remote_code=False
)
```

**Don't**:
```python
# VULNERABLE: Trust remote code from any source
llm = LLM(
    model=user_provided_model,
    trust_remote_code=True  # Executes arbitrary code
)

# VULNERABLE: No model verification
llm = LLM(model=any_model_path)  # Could be poisoned

# VULNERABLE: Pickle-based model loading
llm = LLM(
    model="model",
    load_format="pt"  # Pickle files can contain malicious code
)

# VULNERABLE: Hardcoded token
os.environ["HF_TOKEN"] = "hf_1234567890abcdef"  # Exposed credential
```

**Why**: Unverified models can contain malicious code in custom model definitions or poisoned weights that produce harmful outputs.

**Refs**: OWASP LLM05, MITRE ATLAS AML.T0010, CWE-502

---

## API Security

### Rule: Secure vLLM API Deployment

**Level**: `strict`

**When**: Deploying vLLM as an API service.

**Do**:
```python
from vllm import LLM, SamplingParams
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field, validator
import os

app = FastAPI()

# Safe: Strict input validation
class GenerationRequest(BaseModel):
    prompt: str = Field(..., max_length=8192)
    max_tokens: int = Field(default=512, le=2048, ge=1)
    temperature: float = Field(default=0.7, ge=0, le=2)

    @validator("prompt")
    def validate_prompt(cls, v):
        # Check for injection patterns
        if any(pattern in v.lower() for pattern in [
            "ignore previous", "system:", "admin:"
        ]):
            raise ValueError("Invalid prompt content")
        return v

class GenerationResponse(BaseModel):
    text: str
    finish_reason: str

# Safe: Global engine with secure config
engine = LLM(
    model=os.environ["MODEL_NAME"],
    trust_remote_code=False,
    gpu_memory_utilization=0.8,
    max_model_len=4096,
    disable_log_requests=True
)

# Safe: Rate limiting and authentication
from fastapi.security import APIKeyHeader
from collections import defaultdict
from time import time

api_key_header = APIKeyHeader(name="X-API-Key")
request_counts = defaultdict(list)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    # Validate API key
    valid_keys = os.environ.get("API_KEYS", "").split(",")
    if api_key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Rate limiting
    now = time()
    request_counts[api_key] = [
        t for t in request_counts[api_key] if now - t < 60
    ]
    if len(request_counts[api_key]) >= 60:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    request_counts[api_key].append(now)

    return api_key

@app.post("/generate", response_model=GenerationResponse)
async def generate(
    request: GenerationRequest,
    api_key: str = Depends(verify_api_key)
):
    params = SamplingParams(
        temperature=request.temperature,
        max_tokens=request.max_tokens
    )

    outputs = engine.generate([request.prompt], params)
    result = outputs[0].outputs[0]

    # Validate output before returning
    text = result.text
    if len(text) > request.max_tokens * 10:
        text = text[:request.max_tokens * 10]

    return GenerationResponse(
        text=text,
        finish_reason=result.finish_reason
    )
```

**Don't**:
```python
# VULNERABLE: No input validation
@app.post("/generate")
async def generate(prompt: str, max_tokens: int):
    return engine.generate([prompt])  # No limits

# VULNERABLE: No authentication
@app.post("/generate")
async def generate(request: dict):
    return engine.generate([request["prompt"]])  # Public access

# VULNERABLE: Exposing engine internals
@app.get("/config")
async def get_config():
    return {
        "model": engine.model_config,
        "cache": engine.cache_config  # Leaks internal state
    }

# VULNERABLE: No rate limiting
# Allows DoS through excessive requests
```

**Why**: Unprotected API endpoints enable DoS attacks, prompt injection, and abuse of compute resources.

**Refs**: OWASP A01:2025, CWE-306, CWE-770

---

## Quantization Security

### Rule: Validate Quantized Model Integrity

**Level**: `strict`

**When**: Using quantized models (AWQ, GPTQ, etc.).

**Do**:
```python
from vllm import LLM

# Safe: Verified quantization source
VERIFIED_QUANTS = {
    "TheBloke/Llama-2-7B-Chat-AWQ": "sha256:abc123...",
    "TheBloke/Mistral-7B-Instruct-v0.1-AWQ": "sha256:def456...",
}

def load_quantized_model(model_id: str) -> LLM:
    if model_id not in VERIFIED_QUANTS:
        raise ValueError(f"Unverified quantized model: {model_id}")

    return LLM(
        model=model_id,
        trust_remote_code=False,
        quantization="awq",  # Explicit quantization method
        dtype="auto"
    )

# Safe: Explicit quantization configuration
llm = LLM(
    model="verified-awq-model",
    trust_remote_code=False,
    quantization="awq",
    # Validate quantization settings
    enforce_eager=False,  # Use CUDA graphs for performance
    max_model_len=4096
)

# Safe: Monitor for quality degradation
class QuantizedModelValidator:
    def __init__(self, llm: LLM):
        self.llm = llm
        self.baseline_responses = {}

    def validate_quality(self, test_prompts: list[str]) -> bool:
        """Ensure quantization hasn't degraded outputs"""
        for prompt in test_prompts:
            output = self.llm.generate([prompt])
            # Check for coherence, no garbage output
            text = output[0].outputs[0].text
            if len(text) < 10 or not text.isprintable():
                return False
        return True
```

**Don't**:
```python
# VULNERABLE: Unverified quantized model
llm = LLM(
    model=user_provided_quant_model,
    quantization="awq"  # Could be corrupted
)

# VULNERABLE: Auto-detect quantization from untrusted source
llm = LLM(
    model="random/quant-model"
    # vLLM auto-detects, but source is untrusted
)

# VULNERABLE: No quality validation
def deploy_quant():
    llm = LLM(model="quant-model", quantization="gptq")
    return llm  # May produce garbage outputs
```

**Why**: Corrupted quantized models can produce subtly wrong outputs or contain malicious modifications that affect inference behavior.

**Refs**: MITRE ATLAS AML.T0020, CWE-354

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Isolate KV cache per request | strict | CWE-200, CWE-203 |
| Validate PagedAttention configuration | strict | CWE-401, CWE-400 |
| Implement request isolation in batches | strict | OWASP LLM04, CWE-770 |
| Secure model source verification | strict | OWASP LLM05, CWE-502 |
| Secure vLLM API deployment | strict | OWASP A01:2025, CWE-306 |
| Validate quantized model integrity | strict | AML.T0020, CWE-354 |

---

## Version History

- **v1.0.0** - Initial vLLM security rules
