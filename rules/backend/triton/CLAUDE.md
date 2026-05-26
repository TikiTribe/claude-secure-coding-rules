# Triton Inference Server Security Rules

Security rules for NVIDIA Triton Inference Server in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Model Repository Security

### Rule: Secure Model Repository Configuration

**Level**: `strict`

**When**: Configuring Triton model repositories.

**Do**:
```python
# config.pbtxt - Safe model configuration
"""
name: "secure_model"
platform: "onnxruntime_onnx"
max_batch_size: 32

# Explicit versioning
version_policy: { specific: { versions: [1, 2] } }

# Resource limits
instance_group [
  {
    count: 2
    kind: KIND_GPU
    gpus: [0]
  }
]

# Input validation
input [
  {
    name: "input"
    data_type: TYPE_FP32
    dims: [1, 224, 224, 3]
    # Strict shape enforcement
    reshape: { shape: [1, 224, 224, 3] }
  }
]

output [
  {
    name: "output"
    data_type: TYPE_FP32
    dims: [1, 1000]
  }
]

# Rate limiting
dynamic_batching {
  preferred_batch_size: [8, 16]
  max_queue_delay_microseconds: 100000
}
"""

# Safe: Repository structure with validation
import os
from pathlib import Path

def validate_model_repository(repo_path: str) -> bool:
    repo = Path(repo_path)

    for model_dir in repo.iterdir():
        if not model_dir.is_dir():
            continue

        config = model_dir / "config.pbtxt"
        if not config.exists():
            raise ValueError(f"Missing config: {model_dir}")

        # Check for unsafe patterns
        config_text = config.read_text()
        if "backend: \"python\"" in config_text:
            # Python backend requires extra scrutiny
            if "trust_remote_code" in config_text:
                raise ValueError(f"Unsafe Python backend: {model_dir}")

        # Verify model files are safe formats
        for version_dir in model_dir.iterdir():
            if version_dir.is_dir() and version_dir.name.isdigit():
                model_files = list(version_dir.glob("*"))
                for f in model_files:
                    if f.suffix in [".pkl", ".pickle"]:
                        raise ValueError(f"Unsafe pickle format: {f}")

    return True
```

**Don't**:
```python
# VULNERABLE: No version control
"""
version_policy: { all: {} }  # Loads all versions including untested
"""

# VULNERABLE: Unrestricted Python backend
"""
backend: "python"
# No restrictions on what Python code can do
"""

# VULNERABLE: No resource limits
"""
instance_group [
  {
    count: 100  # Excessive GPU allocation
    kind: KIND_GPU
  }
]
"""

# VULNERABLE: Accepting pickle models
def load_any_model(path):
    # Triton can load pickle-based models (TorchScript, etc.)
    # which can execute arbitrary code
    pass
```

**Why**: Unrestricted model repositories allow loading malicious models, excessive resource consumption, or arbitrary code execution through unsafe serialization formats.

**Refs**: OWASP LLM03:2025, CWE-502, CWE-400

---

## GPU Isolation Security

### Rule: Enforce GPU and Memory Isolation

**Level**: `strict`

**When**: Deploying multi-tenant Triton instances.

**Do**:
```python
# config.pbtxt - GPU isolation
"""
name: "isolated_model"
platform: "tensorrt_plan"

instance_group [
  {
    count: 1
    kind: KIND_GPU
    gpus: [0]  # Pin to specific GPU
    # Rate limiting per instance
    rate_limiter {
      resources [
        {
          name: "compute"
          count: 1
        }
      ]
    }
  }
]

# Memory limits
optimization {
  cuda {
    graphs: true
    busy_wait_events: false
  }
}
"""

# Safe: Docker deployment with GPU isolation
"""
# docker-compose.yml
services:
  triton:
    image: nvcr.io/nvidia/tritonserver:24.05-py3
    deploy:
      resources:
        limits:
          memory: 16G
        reservations:
          devices:
            - driver: nvidia
              device_ids: ['0']  # Specific GPU only
              capabilities: [gpu]
    # Read-only model repository
    volumes:
      - ./models:/models:ro
    # Network isolation
    networks:
      - internal
    # No host privileges
    security_opt:
      - no-new-privileges:true
"""

# Safe: Kubernetes deployment with resource quotas
"""
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: triton
        resources:
          limits:
            nvidia.com/gpu: 1
            memory: "16Gi"
            cpu: "4"
          requests:
            nvidia.com/gpu: 1
            memory: "8Gi"
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
"""
```

**Don't**:
```python
# VULNERABLE: No GPU pinning
"""
instance_group [
  {
    kind: KIND_GPU
    # No gpus specified - uses any available
  }
]
"""

# VULNERABLE: Unrestricted memory
"""
# Docker without limits
docker run --gpus all tritonserver  # Full GPU access
"""

# VULNERABLE: Privileged container
"""
docker run --privileged tritonserver  # Host access
"""

# VULNERABLE: No resource quotas
"""
# Kubernetes without limits
containers:
- name: triton
  # No resource limits - can consume cluster
"""
```

**Why**: Without GPU isolation, one model or tenant can affect others through resource exhaustion, memory corruption, or side-channel attacks.

**Refs**: CWE-400, CWE-770, CWE-269

---

## Ensemble Security

### Rule: Validate Ensemble Pipeline Security

**Level**: `strict`

**When**: Creating model ensemble pipelines.

**Do**:
```python
# config.pbtxt - Secure ensemble
"""
name: "secure_ensemble"
platform: "ensemble"
max_batch_size: 16

ensemble_scheduling {
  step [
    {
      model_name: "preprocessor"
      model_version: 1  # Pin version
      input_map {
        key: "raw_input"
        value: "INPUT"
      }
      output_map {
        key: "processed"
        value: "PROCESSED"
      }
    },
    {
      model_name: "classifier"
      model_version: 1  # Pin version
      input_map {
        key: "PROCESSED"
        value: "features"
      }
      output_map {
        key: "predictions"
        value: "OUTPUT"
      }
    }
  ]
}

# Validate all inputs
input [
  {
    name: "INPUT"
    data_type: TYPE_UINT8
    dims: [-1, 224, 224, 3]
  }
]

output [
  {
    name: "OUTPUT"
    data_type: TYPE_FP32
    dims: [-1, 1000]
  }
]
"""

# Safe: Python BLS (Business Logic Scripting) with validation
"""
# model.py for Python backend
import triton_python_backend_utils as pb_utils
import numpy as np

class TritonPythonModel:
    def initialize(self, args):
        # Validate model configuration
        self.max_input_size = 1000000  # 1MB limit

    def execute(self, requests):
        responses = []
        for request in requests:
            # Validate input size
            input_tensor = pb_utils.get_input_tensor_by_name(
                request, "INPUT"
            )
            if input_tensor.as_numpy().nbytes > self.max_input_size:
                error = pb_utils.TritonError("Input too large")
                responses.append(pb_utils.InferenceResponse(error=error))
                continue

            # Process safely
            result = self.process(input_tensor)
            responses.append(pb_utils.InferenceResponse(
                output_tensors=[result]
            ))

        return responses
"""
```

**Don't**:
```python
# VULNERABLE: Unpinned versions in ensemble
"""
ensemble_scheduling {
  step [
    {
      model_name: "model"
      model_version: -1  # Latest version - unstable
    }
  ]
}
"""

# VULNERABLE: Python backend without validation
"""
class TritonPythonModel:
    def execute(self, requests):
        for request in requests:
            # No input validation
            data = pb_utils.get_input_tensor_by_name(request, "INPUT")
            result = process_any_data(data)  # Could be huge/malicious
"""

# VULNERABLE: Circular ensemble dependencies
"""
ensemble_scheduling {
  step [
    { model_name: "A", input_map: { key: "B_out" } },
    { model_name: "B", input_map: { key: "A_out" } }
  ]
}
"""
```

**Why**: Ensemble pipelines can have unvalidated data flow between models, creating injection points or enabling resource exhaustion through cascading effects.

**Refs**: OWASP LLM03:2025, CWE-20, CWE-400

---

## API Security

### Rule: Secure gRPC and HTTP Endpoints

**Level**: `strict`

**When**: Exposing Triton API endpoints.

**Do**:
```python
# Safe: Triton server with security options
"""
# Start with authentication and TLS
tritonserver \\
    --model-repository=/models \\
    --grpc-port=8001 \\
    --http-port=8000 \\
    --metrics-port=8002 \\
    # TLS configuration
    --grpc-use-ssl=true \\
    --grpc-server-cert=/certs/server.crt \\
    --grpc-server-key=/certs/server.key \\
    --grpc-root-cert=/certs/ca.crt \\
    # Rate limiting
    --rate-limit="execution_count:10" \\
    # Disable unnecessary features
    --allow-gpu-metrics=false \\
    --allow-cpu-metrics=false
"""

# Safe: Python client with mTLS — pass cert paths directly to InferenceServerClient
import tritonclient.grpc as grpcclient

def create_secure_client(url: str, cert_path: str):
    # InferenceServerClient accepts PEM-encoded bytes for mTLS directly;
    # no separate ssl context object is needed.
    client = grpcclient.InferenceServerClient(
        url=url,
        ssl=True,
        root_certificates=cert_path + "/ca.crt",
        private_key=cert_path + "/client.key",
        certificate_chain=cert_path + "/client.crt"
    )

    return client

# Safe: Request validation
from pydantic import BaseModel, field_validator
import numpy as np

class InferenceRequest(BaseModel):
    model_name: str
    inputs: dict
    request_id: str

    @field_validator("model_name")
    @classmethod
    def validate_model(cls, v):
        allowed = ["classifier", "detector", "embedder"]
        if v not in allowed:
            raise ValueError(f"Model not allowed: {v}")
        return v

    @field_validator("inputs")
    @classmethod
    def validate_inputs(cls, v):
        for name, data in v.items():
            arr = np.array(data)
            if arr.nbytes > 10_000_000:  # 10MB limit
                raise ValueError(f"Input {name} too large")
        return v
```

**Don't**:
```python
# VULNERABLE: No TLS
"""
tritonserver --model-repository=/models
# All traffic unencrypted
"""

# VULNERABLE: Exposed metrics with sensitive data
"""
tritonserver \\
    --metrics-port=8002 \\
    --allow-gpu-metrics=true \\
    --allow-metrics=true
# Metrics exposed without auth
"""

# VULNERABLE: No request validation
def infer(client, model_name, data):
    # Direct inference without validation
    return client.infer(model_name, data)

# VULNERABLE: Accepting any model name
def route_inference(model_name: str, data):
    return client.infer(model_name, data)  # User controls model
```

**Why**: Unprotected endpoints enable unauthorized model access, data interception, or denial of service through unvalidated requests.

**Refs**: OWASP A01:2025, CWE-306, CWE-319

---

## Custom Backend Security

### Rule: Sandbox Custom Backend Code

**Level**: `strict`

**When**: Using Python or custom backends.

**Do**:
```python
# model.py - Safe Python backend
import triton_python_backend_utils as pb_utils
import numpy as np
import os

class TritonPythonModel:
    def initialize(self, args):
        # Validate environment
        if os.getenv("TRITON_SANDBOX") != "true":
            raise RuntimeError("Must run in sandbox")

        # Load model with restrictions
        model_path = os.path.join(
            args["model_repository"],
            args["model_name"]
        )

        # Verify model path is within allowed directory
        allowed_base = "/models"
        if not os.path.realpath(model_path).startswith(allowed_base):
            raise RuntimeError("Invalid model path")

        # Set resource limits
        self.max_batch_size = 32
        self.max_sequence_length = 512

    def execute(self, requests):
        responses = []

        for request in requests:
            try:
                # Validate request
                input_tensor = pb_utils.get_input_tensor_by_name(
                    request, "INPUT"
                )
                data = input_tensor.as_numpy()

                # Check batch size
                if data.shape[0] > self.max_batch_size:
                    raise ValueError("Batch too large")

                # Check sequence length
                if len(data.shape) > 1 and data.shape[1] > self.max_sequence_length:
                    raise ValueError("Sequence too long")

                # Safe processing
                result = self.process_safe(data)

                output = pb_utils.Tensor(
                    "OUTPUT",
                    result.astype(np.float32)
                )
                responses.append(pb_utils.InferenceResponse([output]))

            except Exception as e:
                error = pb_utils.TritonError(str(e))
                responses.append(pb_utils.InferenceResponse(error=error))

        return responses

    def process_safe(self, data: np.ndarray) -> np.ndarray:
        # Implement safe processing logic
        # No shell commands, file writes, network access
        return data * 2  # Example safe operation
```

**Don't**:
```python
# VULNERABLE: Unrestricted Python backend
class TritonPythonModel:
    def execute(self, requests):
        for request in requests:
            # No validation
            data = pb_utils.get_input_tensor_by_name(request, "INPUT")

            # Dangerous operations
            import subprocess
            subprocess.run(data.decode())  # Shell injection

            import pickle
            obj = pickle.loads(data)  # Arbitrary code execution

            open("/etc/passwd", "r")  # File access

# VULNERABLE: Dynamic code execution
class UnsafeModel:
    def execute(self, requests):
        code = requests[0].get_input("code")
        exec(code)  # Never do this
```

**Why**: Custom backends run with server privileges and can access system resources, making input validation and sandboxing critical.

**Refs**: CWE-94, CWE-78, OWASP LLM05:2025

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure model repository configuration | strict | OWASP LLM03:2025, CWE-502 |
| Enforce GPU and memory isolation | strict | CWE-400, CWE-770 |
| Validate ensemble pipeline security | strict | OWASP LLM03:2025, CWE-20 |
| Secure gRPC and HTTP endpoints | strict | OWASP A01:2025, CWE-306 |
| Sandbox custom backend code | strict | CWE-94, CWE-78 |

---

## Version History

- **v2.0.0** - Updated OWASP LLM references to 2025 numbering; fixed gRPC client API; updated Docker image tag to 24.x; migrated to Pydantic v2 field_validator
- **v1.0.0** - Initial Triton Inference Server security rules
