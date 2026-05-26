# Ray Serve Security Rules

Security rules for Ray Serve distributed model serving in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Deployment Security

### Rule: Secure Deployment Configuration

**Level**: `strict`

**When**: Deploying Ray Serve applications.

**Do**:
```python
from ray import serve
from ray.serve import Application
from ray.serve.config import HTTPOptions
import os

# Safe: Secure deployment with resource limits
@serve.deployment(
    name="secure_model",
    num_replicas=2,
    max_concurrent_queries=100,
    # Resource limits per replica
    ray_actor_options={
        "num_cpus": 1,
        "num_gpus": 0.5,
        "memory": 2 * 1024 * 1024 * 1024,  # 2GB
    },
    # Health check configuration
    health_check_period_s=10,
    health_check_timeout_s=30,
)
class SecureModelDeployment:
    def __init__(self):
        # Load model securely
        import torch
        model_path = os.environ.get("MODEL_PATH")
        if not model_path:
            raise ValueError("MODEL_PATH not set")

        # Use TorchScript (safe) instead of pickle
        self.model = torch.jit.load(model_path)
        self.model.eval()

        # Set limits
        self.max_input_size = 10_000_000  # 10MB
        self.max_batch_size = 32

    async def __call__(self, request):
        # Validate request
        data = await request.body()

        if len(data) > self.max_input_size:
            return {"error": "Input too large"}, 400

        # Process safely
        result = self._predict(data)
        return {"result": result}

    def _predict(self, data: bytes):
        import torch
        import numpy as np

        # Safe deserialization
        arr = np.frombuffer(data, dtype=np.float32)
        tensor = torch.from_numpy(arr)

        with torch.no_grad():
            output = self.model(tensor)

        return output.numpy().tolist()

# Safe: Secure serve configuration
serve_config = {
    "http_options": HTTPOptions(
        host="127.0.0.1",  # Localhost only
        port=8000,
        # Request limits
        request_timeout_s=30,
    ),
    "logging_config": {
        "encoding": "JSON",
        "enable_access_log": True,
    }
}

# Safe: Deploy with authentication proxy
app = SecureModelDeployment.bind()
serve.run(app, **serve_config)
```

**Don't**:
```python
# VULNERABLE: No resource limits
@serve.deployment
class UnlimitedDeployment:
    pass  # Can consume all resources

# VULNERABLE: Public binding
serve_config = {
    "http_options": HTTPOptions(
        host="0.0.0.0",  # Exposed to all
        port=8000
    )
}

# VULNERABLE: Pickle-based model loading
@serve.deployment
class UnsafeModel:
    def __init__(self):
        import pickle
        self.model = pickle.load(open("model.pkl", "rb"))  # RCE

# VULNERABLE: No request validation
@serve.deployment
class NoValidation:
    async def __call__(self, request):
        data = await request.json()
        return self.model(data)  # Could be huge
```

**Why**: Unrestricted deployments enable resource exhaustion, denial of service, or code execution through unsafe deserialization.

**Refs**: CWE-400, CWE-502, OWASP LLM10:2025 (Unbounded Consumption)

---

## Autoscaling Security

### Rule: Implement Secure Autoscaling Policies

**Level**: `strict`

**When**: Configuring autoscaling for Ray Serve deployments.

**Do**:
```python
from ray import serve
from ray.serve.config import AutoscalingConfig

# Safe: Bounded autoscaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=10,  # Hard limit
        target_num_ongoing_requests_per_replica=10,
        # Gradual scaling
        upscale_delay_s=30,
        downscale_delay_s=60,
        # Metrics window
        metrics_interval_s=10,
        look_back_period_s=30,
    ),
    # Per-replica limits
    ray_actor_options={
        "num_cpus": 1,
        "memory": 2 * 1024 * 1024 * 1024,
    },
    max_concurrent_queries=50,
)
class SecureAutoscaledModel:
    def __init__(self):
        self.model = self._load_model()

    async def __call__(self, request):
        # Implementation with validation
        pass

# Safe: Resource-aware autoscaling
def get_cluster_resources():
    import ray
    resources = ray.cluster_resources()
    return {
        "cpu": resources.get("CPU", 0),
        "memory": resources.get("memory", 0),
        "gpu": resources.get("GPU", 0)
    }

def calculate_safe_max_replicas(
    cpu_per_replica: float,
    memory_per_replica: float,
    safety_margin: float = 0.8
) -> int:
    resources = get_cluster_resources()

    max_by_cpu = int(
        (resources["cpu"] * safety_margin) / cpu_per_replica
    )
    max_by_memory = int(
        (resources["memory"] * safety_margin) / memory_per_replica
    )

    return min(max_by_cpu, max_by_memory, 100)  # Hard cap at 100

# Safe: Deployment with calculated limits
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=calculate_safe_max_replicas(1, 2 * 1024**3),
    )
)
class ResourceAwareModel:
    pass
```

**Don't**:
```python
# VULNERABLE: Unbounded autoscaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=1000,  # Can exhaust cluster
    )
)
class UnboundedModel:
    pass

# VULNERABLE: No per-replica limits
@serve.deployment(
    autoscaling_config=AutoscalingConfig(max_replicas=100)
    # No ray_actor_options - unlimited resources per replica
)
class UnlimitedReplicas:
    pass

# VULNERABLE: Aggressive scaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        upscale_delay_s=1,  # Too fast
        downscale_delay_s=1,
        max_replicas=100
    )
)
class AggressiveScaling:
    pass
```

**Why**: Unbounded autoscaling can exhaust cluster resources, causing cascading failures and enabling resource-based DoS attacks.

**Refs**: CWE-400, CWE-770

---

## Serialization Security

### Rule: Use Safe Serialization for Ray Objects

**Level**: `strict`

**When**: Passing objects between Ray actors and deployments.

**Do**:
```python
from ray import serve
import ray
import numpy as np

# Safe: Use supported serialization types
@serve.deployment
class SafeSerializer:
    async def __call__(self, request):
        data = await request.json()

        # Safe types for Ray serialization
        # numpy arrays, torch tensors, basic Python types
        arr = np.array(data["input"], dtype=np.float32)

        # Process in actor
        result = await self._process_remote(arr)
        return {"result": result.tolist()}

    async def _process_remote(self, arr: np.ndarray):
        # Ray handles numpy serialization safely
        return self.model.predict(arr)

# Safe: Custom serialization with validation
import msgpack

@serve.deployment
class SecureCustomSerializer:
    def __init__(self):
        self.allowed_types = {np.ndarray, list, dict, str, int, float}

    async def __call__(self, request):
        data = await request.body()

        # Use msgpack instead of pickle
        try:
            unpacked = msgpack.unpackb(data, raw=False)
        except Exception:
            return {"error": "Invalid serialization"}, 400

        # Validate types
        if not self._validate_types(unpacked):
            return {"error": "Invalid data types"}, 400

        return {"result": self._process(unpacked)}

    def _validate_types(self, obj, depth=0):
        if depth > 10:  # Prevent deep nesting attacks
            return False

        if isinstance(obj, dict):
            return all(
                self._validate_types(v, depth + 1)
                for v in obj.values()
            )
        elif isinstance(obj, list):
            return all(
                self._validate_types(v, depth + 1)
                for v in obj
            )
        else:
            return type(obj) in {str, int, float, bool, type(None)}

# Safe: TorchScript for model serialization
import torch

@serve.deployment
class SafeModelSerializer:
    def __init__(self, model_path: str):
        # TorchScript is safe (no arbitrary code execution)
        self.model = torch.jit.load(model_path)

    async def __call__(self, request):
        data = await request.json()
        tensor = torch.tensor(data["input"])

        with torch.no_grad():
            output = self.model(tensor)

        return {"output": output.tolist()}
```

**Don't**:
```python
# VULNERABLE: Pickle serialization
import pickle

@serve.deployment
class PickleDeployment:
    async def __call__(self, request):
        data = await request.body()
        obj = pickle.loads(data)  # Arbitrary code execution
        return self.model(obj)

# VULNERABLE: Eval for deserialization
@serve.deployment
class EvalDeployment:
    async def __call__(self, request):
        data = await request.json()
        obj = eval(data["code"])  # Code injection
        return obj

# VULNERABLE: No type validation
@serve.deployment
class NoValidation:
    async def __call__(self, request):
        data = await request.json()
        return self.model(data)  # Any structure accepted
```

**Why**: Unsafe serialization like pickle allows arbitrary code execution when deserializing malicious payloads.

**Refs**: CWE-502, CWE-94, OWASP LLM04:2025 (Data and Model Poisoning)

---

## Multi-Application Security

### Rule: Isolate Ray Serve Applications

**Level**: `strict`

**When**: Running multiple applications on same Ray cluster.

**Do**:
```python
from ray import serve
from ray.serve.config import HTTPOptions
import os

# Safe: Namespace isolation
serve.start(
    detached=True,
    http_options=HTTPOptions(
        host="127.0.0.1",
        port=8000
    ),
    # Use namespaces for isolation
    namespace="production"
)

# Safe: Application-level resource quotas
@serve.deployment(
    name="app_a_model",
    ray_actor_options={
        "num_cpus": 2,
        "memory": 4 * 1024**3,
        # namespace is a top-level ray.init()/serve.start() arg, not per-actor
    }
)
class AppAModel:
    pass

@serve.deployment(
    name="app_b_model",
    ray_actor_options={
        "num_cpus": 2,
        "memory": 4 * 1024**3,
    }
)
class AppBModel:
    pass

# Safe: Route isolation with authentication
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader

app = FastAPI()
api_key_header = APIKeyHeader(name="X-API-Key")

# Different keys for different apps
APP_KEYS = {
    "app_a": os.environ.get("APP_A_KEY"),
    "app_b": os.environ.get("APP_B_KEY"),
}

async def verify_app_key(
    app_name: str,
    api_key: str = Depends(api_key_header)
):
    if APP_KEYS.get(app_name) != api_key:
        raise HTTPException(status_code=401)
    return api_key

@serve.deployment
@serve.ingress(app)
class Router:
    def __init__(self, app_a_handle, app_b_handle):
        self.handles = {
            "app_a": app_a_handle,
            "app_b": app_b_handle
        }

    @app.post("/{app_name}/predict")
    async def predict(
        self,
        app_name: str,
        data: dict,
        _: str = Depends(lambda: verify_app_key(app_name))
    ):
        if app_name not in self.handles:
            raise HTTPException(404)

        return await self.handles[app_name].remote(data)
```

**Don't**:
```python
# VULNERABLE: Shared namespace
serve.start(detached=True)  # Default namespace

@serve.deployment(name="model_a")
class ModelA:
    pass

@serve.deployment(name="model_b")
class ModelB:
    pass
# Both in same namespace - can interfere

# VULNERABLE: No resource isolation
@serve.deployment
class SharedResources:
    # No ray_actor_options - competes for all resources
    pass

# VULNERABLE: No authentication per app
@serve.deployment
class OpenRouter:
    async def __call__(self, request):
        app = request.path.split("/")[1]
        # Anyone can access any app
        return await self.handles[app].remote(request)
```

**Why**: Without isolation, applications can interfere with each other, access unauthorized data, or exhaust shared resources.

**Refs**: CWE-269, CWE-200

---

## Composition Security

### Rule: Secure Model Composition Pipelines

**Level**: `strict`

**When**: Building pipelines with multiple deployments.

**Do**:
```python
from ray import serve

# Safe: Validated pipeline with type checking
@serve.deployment
class Preprocessor:
    async def __call__(self, data: dict) -> dict:
        # Validate input
        if "image" not in data:
            raise ValueError("Missing image field")

        if len(data["image"]) > 10_000_000:
            raise ValueError("Image too large")

        # Process and return validated output
        processed = self._preprocess(data["image"])
        return {"processed": processed, "metadata": data.get("metadata", {})}

@serve.deployment
class Classifier:
    async def __call__(self, data: dict) -> dict:
        # Validate preprocessor output
        if "processed" not in data:
            raise ValueError("Invalid preprocessor output")

        result = self._classify(data["processed"])
        return {"class": result, "metadata": data.get("metadata", {})}

@serve.deployment
class Pipeline:
    def __init__(self, preprocessor, classifier):
        self.preprocessor = preprocessor
        self.classifier = classifier

    async def __call__(self, request):
        data = await request.json()

        # Validate initial input
        if not isinstance(data, dict):
            return {"error": "Invalid input format"}, 400

        try:
            # Pipeline with error handling
            prep_result = await self.preprocessor.remote(data)
            class_result = await self.classifier.remote(prep_result)

            return class_result

        except ValueError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            # Log but don't expose internal errors
            import logging
            logging.error(f"Pipeline error: {e}")
            return {"error": "Internal error"}, 500

# Safe: Build pipeline with dependency injection
preprocessor = Preprocessor.bind()
classifier = Classifier.bind()
pipeline = Pipeline.bind(preprocessor, classifier)

serve.run(pipeline)
```

**Don't**:
```python
# VULNERABLE: No validation between stages
@serve.deployment
class UnsafePipeline:
    async def __call__(self, request):
        data = await request.json()
        # No validation - any data flows through
        result1 = await self.step1.remote(data)
        result2 = await self.step2.remote(result1)
        return result2

# VULNERABLE: Error information leakage
@serve.deployment
class LeakyPipeline:
    async def __call__(self, request):
        try:
            return await self.process(request)
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}
            # Exposes internal details

# VULNERABLE: Circular dependencies
step_a = StepA.bind(step_b)
step_b = StepB.bind(step_a)  # Circular
```

**Why**: Unvalidated data flow between pipeline stages can propagate malicious inputs or enable information leakage through error messages. Handle references passed between deployments via `.remote()` are trust boundaries: a compromised replica can call any handle it holds without further authentication, so callee deployments must validate the shape and bounds of data from every caller regardless of its origin.

**Refs**: CWE-20, CWE-209, CWE-284, OWASP LLM10:2025 (Unbounded Consumption)

---

## Dashboard Security

### Rule: Authenticate the Ray Dashboard

**Level**: `strict`

**When**: Starting Ray or Ray Serve in any environment with network access beyond localhost.

**Do**:
```python
import os
import subprocess

# Safe: Start Ray with dashboard token so the dashboard on port 8265
# requires authentication before exposing actor metadata, job logs,
# and task information.
#
# Option A — CLI flag (preferred for scripted cluster startup):
#   ray start --head --dashboard-token=$RAY_DASHBOARD_TOKEN \
#             --dashboard-host=127.0.0.1
#
# Option B — environment variable picked up by ray.init():
#   export RAY_DASHBOARD_TOKEN=<strong-random-secret>
#   ray.init()
#
# Option C — reverse proxy (use when you need external access):
#   Place nginx/traefik in front of 127.0.0.1:8265 and enforce
#   mTLS or a token header at the proxy layer. Never expose 8265
#   directly on a public interface.

# Validate the token is set before starting a cluster-aware process.
dashboard_token = os.environ.get("RAY_DASHBOARD_TOKEN")
if not dashboard_token or len(dashboard_token) < 32:
    raise RuntimeError(
        "RAY_DASHBOARD_TOKEN must be set to a secret of at least "
        "32 characters before starting Ray in a networked environment."
    )

import ray
ray.init()

# Safe serve.start: bind the HTTP server to loopback; dashboard
# access is handled by the token-gated path above.
from ray import serve
from ray.serve.config import HTTPOptions

serve.start(
    http_options=HTTPOptions(
        host="127.0.0.1",
        port=8000,
    )
)
```

**Don't**:
```python
import ray
import os

# VULNERABLE: Ray starts with dashboard on 0.0.0.0:8265 by default.
# Any host that can reach this port can inspect actors, cancel jobs,
# download logs, and exfiltrate task metadata with no credentials.
ray.init()  # --dashboard-host defaults to 0.0.0.0 in many versions

# VULNERABLE: Explicitly binding the dashboard to a public interface
# without a token.
# ray start --head --dashboard-host=0.0.0.0
# Anyone on the network owns your cluster.

from ray import serve
from ray.serve.config import HTTPOptions

# VULNERABLE: HTTP server on all interfaces with no upstream auth gate.
serve.start(
    http_options=HTTPOptions(
        host="0.0.0.0",
        port=8000,
    )
)
```

**Why**: The Ray dashboard on port 8265 is unauthenticated by default. An attacker with network access can enumerate actors, kill jobs, read environment variables from task metadata, and exfiltrate model outputs without any credentials. In Kubernetes, this is reachable from any pod in the cluster unless a NetworkPolicy blocks it.

**Refs**: CWE-306 (Missing Authentication), CWE-200 (Information Exposure), OWASP A07:2025

---

## Runtime Environment Security

### Rule: Pin Packages in runtime_env to Prevent Supply-Chain RCE

**Level**: `strict`

**When**: Using `runtime_env` with a `pip` section to install packages at deployment time.

**Do**:
```python
from ray import serve

# Safe: Pin every package to an exact version with a hash.
# Ray installs these at replica startup; an unpinned package from
# PyPI is an untrusted code execution point for every worker.
PINNED_RUNTIME_ENV = {
    "pip": [
        # Use pip hash-checking mode: version + --hash.
        # Generate with: pip download <pkg>==<ver> && pip hash <file>
        "numpy==1.26.4 --hash=sha256:2a02aba9ed12e4ac4eb3ea9421c420301a0c6460d9830d74a9df87efa4912010",
        "scikit-learn==1.4.2 --hash=sha256:3b2c1b3f7e29319bc46e3efa9d8b4c37ce8b6bd726de4f87a68069d87d44fc40",
    ],
    # Restrict the index to an internal registry you control.
    # Prohibit git+https:// or VCS refs without a pinned commit SHA.
    "pip_check": False,       # handled by hash verification above
    "env_vars": {
        "PIP_NO_INDEX": "1",  # force use of --extra-index-url only
        "PIP_EXTRA_INDEX_URL": "https://pypi.internal.example.com/simple/",
    },
}

@serve.deployment(
    runtime_env=PINNED_RUNTIME_ENV,
    ray_actor_options={"num_cpus": 1, "memory": 2 * 1024**3},
)
class SecureReplica:
    def __init__(self):
        import numpy as np          # version-verified at install time
        import sklearn              # same
        self.ready = True

    async def __call__(self, request):
        data = await request.json()
        return {"ok": True}

# Better alternative: pre-bake dependencies into the container image
# and set no pip installs in runtime_env at all.
# runtime_env = {"working_dir": "/app"}   # no pip key → no runtime install

# Note on cloudpickle: Ray uses cloudpickle internally to serialize
# tasks and actor state across the cluster. Untrusted task code
# submitted to a shared Ray cluster is equivalent to arbitrary code
# execution on every worker that deserializes it. Run shared clusters
# with strict job submission controls; do not expose ray.init() or
# the Ray client port (10001) to untrusted callers.
```

**Don't**:
```python
from ray import serve

# VULNERABLE: Unpinned package — PyPI serves whatever the latest
# version is at deploy time. A compromised release or a dependency
# confusion attack gives an attacker RCE in every replica at startup.
@serve.deployment(
    runtime_env={
        "pip": ["numpy", "scikit-learn"],  # no version, no hash
    }
)
class UnsafeReplica:
    pass

# VULNERABLE: VCS reference without a pinned commit SHA.
# The branch tip changes; an attacker who pushes to that branch
# owns every worker on the next cold start.
@serve.deployment(
    runtime_env={
        "pip": ["git+https://github.com/example/ml-lib.git@main"],
    }
)
class VCSReplica:
    pass

# VULNERABLE: Public PyPI index with no hash verification.
# Dependency confusion: an internal package name served from PyPI
# with a higher version number wins and executes at install time.
@serve.deployment(
    runtime_env={
        "pip": ["internal-feature-lib==1.0.0"],
        # No index restriction — public PyPI is tried first.
    }
)
class ConfusionVulnerable:
    pass
```

**Why**: Ray installs `runtime_env` pip packages inside each replica's virtual environment at startup. An unpinned or VCS-sourced package gives a supply-chain attacker code execution across all replicas simultaneously, equivalent to cluster-wide RCE. Dependency confusion attacks exploit the same vector when an internal package name is also published on public PyPI at a higher version. Pre-baking dependencies into the container image eliminates the runtime install surface entirely.

**Refs**: CWE-494 (Download Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), OWASP LLM03:2025 (Supply Chain Vulnerabilities), OWASP A06:2025

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure deployment configuration | strict | CWE-400, CWE-502, OWASP LLM10:2025 |
| Implement secure autoscaling policies | strict | CWE-400, CWE-770 |
| Use safe serialization for Ray objects | strict | CWE-502, CWE-94, OWASP LLM04:2025 |
| Isolate Ray Serve applications | strict | CWE-269, CWE-200 |
| Secure model composition pipelines | strict | CWE-20, CWE-209, OWASP LLM10:2025 |
| Authenticate the Ray dashboard | strict | CWE-306, CWE-200, OWASP A07:2025 |
| Pin packages in runtime_env | strict | CWE-494, CWE-829, OWASP LLM03:2025 |

---

## Version History

- **v2.0.0** - Fix OWASP LLM taxonomy to 2025 edition; add dashboard auth and runtime_env supply-chain rules; remove invalid namespace key from ray_actor_options
- **v1.0.0** - Initial Ray Serve security rules
