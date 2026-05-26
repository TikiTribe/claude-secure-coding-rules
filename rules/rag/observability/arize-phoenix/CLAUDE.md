# CLAUDE.md - Arize Phoenix Security Rules

Security rules for Arize Phoenix ML observability platform in RAG systems.

**Prerequisites**: `rules/_core/ai-security.md`, `rules/_core/rag-security.md`

---

## Rule: Secure Trace Ingestion

**Level**: `strict`

**When**: Ingesting traces from LLM applications into Phoenix

**Do**:
```python
import os
import phoenix as px

# Phoenix v16 auth is controlled via environment variables, not px.launch_app() kwargs.
# Set these before starting the process or in your container/system environment.
#
#   PHOENIX_ENABLE_AUTH=true
#   PHOENIX_SECRET=<random-256-bit-hex>           # signs session tokens
#   PHOENIX_ADMIN_SECRET=<separate-random-secret>  # admin bootstrap password
#
# For TLS, terminate at a reverse proxy (nginx/caddy) or set:
#   PHOENIX_TLS_CERT_FILE=/run/secrets/phoenix.crt
#   PHOENIX_TLS_KEY_FILE=/run/secrets/phoenix.key

# Validate required env vars at startup - fail fast rather than run insecure.
_REQUIRED = [
    "PHOENIX_ENABLE_AUTH",
    "PHOENIX_SECRET",
    "PHOENIX_ADMIN_SECRET",
]
for _var in _REQUIRED:
    if not os.environ.get(_var):
        raise RuntimeError(f"Required env var missing: {_var}")

# Bind to localhost for local dev; use a reverse proxy for production.
px.launch_app(host="127.0.0.1", port=6006)

# Sanitize trace data before ingestion.
def sanitize_trace_spans(spans: list[dict]) -> list[dict]:
    """Remove sensitive data from trace spans before storage."""
    sanitized = []
    for span in spans:
        span_copy = span.copy()
        if "attributes" in span_copy:
            attrs = span_copy["attributes"]
            for key in ["input.value", "output.value"]:
                if key in attrs:
                    attrs[key] = redact_pii(attrs[key])
        sanitized.append(span_copy)
    return sanitized

sanitized_spans = sanitize_trace_spans(raw_spans)
```

**Don't**:
```python
import phoenix as px

# Insecure: no auth env vars set, bound to all interfaces.
px.launch_app(host="0.0.0.0", port=6006)

# Insecure: raw traces with PII sent without sanitization.
px.Client().log_traces(traces=raw_traces)

# Hardcoded secret in source.
PHOENIX_SECRET_VAL = "phx_abc123secret"  # exposed in code
```

**Why**: Trace data contains LLM inputs/outputs that may include user PII, proprietary prompts, and secrets. Unauthenticated endpoints allow data exfiltration; unencrypted transport exposes data to interception.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-319 (Cleartext Transmission), OWASP LLM02:2025 (Sensitive Information Disclosure)

---

## Rule: OTLP Exporter TLS and Authentication

**Level**: `strict`

**When**: Sending traces from instrumented applications to a remote Phoenix collector via OTLP

**Do**:
```python
import os
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
import grpc

# Load CA cert for mutual TLS or server-only TLS.
ca_cert = open(os.environ["OTLP_CA_CERT"], "rb").read()
credentials = grpc.ssl_channel_credentials(root_certificates=ca_cert)

exporter = OTLPSpanExporter(
    endpoint=os.environ["PHOENIX_COLLECTOR_ENDPOINT"],  # host:4317
    credentials=credentials,
    headers={
        # Bearer token issued by Phoenix auth; rotate on a schedule.
        "authorization": f"Bearer {os.environ['PHOENIX_API_KEY']}",
    },
    compression=grpc.Compression.Gzip,
)

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

**Don't**:
```python
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# Insecure: no TLS, no auth header.
exporter = OTLPSpanExporter(endpoint="http://phoenix:4317")

# Insecure: disables TLS verification.
exporter = OTLPSpanExporter(
    endpoint="https://phoenix:4317",
    insecure=True,  # MITM vector
)
```

**Why**: OTLP gRPC carries all LLM traces. Sending without TLS exposes prompts, completions, and embedded secrets to any network observer. Missing bearer-token auth allows unauthorized span injection that corrupts audit trails.

**Refs**: CWE-319 (Cleartext Transmission), CWE-306 (Missing Authentication), CWE-295 (Improper Certificate Validation)

---

## Rule: Collector-Side Attribute Filtering

**Level**: `strict`

**When**: Running an OpenTelemetry Collector in front of Phoenix to ingest spans from multiple services

**Do**:
```yaml
# otel-collector-config.yaml
processors:
  # Drop attributes that may carry PII or secrets before forwarding to Phoenix.
  attributes/redact_sensitive:
    actions:
      - key: "input.value"
        action: delete
      - key: "output.value"
        action: delete
      - key: "http.request.header.authorization"
        action: delete
      - key: "db.statement"
        action: hash   # preserve cardinality without raw SQL

  # Hash user identifiers to prevent PII storage.
  attributes/hash_user:
    actions:
      - key: "user.id"
        action: hash

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, attributes/redact_sensitive, attributes/hash_user, batch]
      exporters: [otlp/phoenix]
```

**Don't**:
```yaml
# No attribute filtering - raw spans with PII forwarded to Phoenix.
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/phoenix]
```

**Why**: Filtering at the collector layer enforces a hard boundary independent of application code. A single misconfigured instrumentation library cannot bypass the collector filter, limiting blast radius from accidental PII capture.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File), NIST AI RMF GOVERN 1.6

---

## Rule: Embedding Drift Monitoring Protection

**Level**: `warning`

**When**: Monitoring embedding drift and vector distributions

**Do**:
```python
# phoenix.evals.EmbeddingDrift was removed in Phoenix v12.
# Use statistical summaries computed outside Phoenix, then log
# scalar metrics as custom span attributes or experiment annotations.
import numpy as np
import time
from scipy.spatial.distance import cosine

def compute_drift_metrics(
    reference_embeddings: np.ndarray,
    production_embeddings: np.ndarray,
) -> dict:
    """Return aggregate drift statistics without storing raw vectors."""
    sample_size = min(1000, len(production_embeddings))
    rng = np.random.default_rng(seed=0)
    sample_idx = rng.choice(len(production_embeddings), size=sample_size, replace=False)
    sample = production_embeddings[sample_idx]

    # Centroid-distance drift - no raw vectors returned.
    ref_centroid = reference_embeddings.mean(axis=0)
    prod_centroid = sample.mean(axis=0)
    return {
        "cosine_drift": float(cosine(ref_centroid, prod_centroid)),
        "sample_size": sample_size,
    }

class DriftMonitor:
    def __init__(self, min_interval_seconds: int = 300):
        self.min_interval = min_interval_seconds
        self.last_computation: float = 0

    def compute_if_allowed(
        self,
        ref_emb: np.ndarray,
        prod_emb: np.ndarray,
    ) -> dict:
        now = time.monotonic()
        if now - self.last_computation < self.min_interval:
            raise RuntimeError("Drift computation rate-limited; retry later")
        self.last_computation = now
        return compute_drift_metrics(ref_emb, prod_emb)
```

**Don't**:
```python
# EmbeddingDrift class no longer exists - import will raise ImportError.
from phoenix.evals import EmbeddingDrift  # removed in v12+

def check_drift_on_every_request(embeddings):
    # Resource exhaustion: runs on every request with no rate limiting.
    drift = EmbeddingDrift(reference_embeddings=load_all_reference_embeddings())
    return drift.compute(embeddings)

def export_drift_report(reference_emb, prod_emb, score):
    # Raw embedding export enables model-extraction attacks.
    return {
        "raw_reference_embeddings": reference_emb.tolist(),
        "raw_production_embeddings": prod_emb.tolist(),
        "drift_score": score,
    }
```

**Why**: Embedding drift analysis is computationally expensive, creating DoS opportunities if unthrottled. Raw embedding export enables model extraction attacks where adversaries reconstruct the embedding model from vector samples.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), MITRE ATLAS AML.T0047 (ML Model Inference API Access)

---

## Rule: Evaluation Dataset Protection

**Level**: `strict`

**When**: Managing evaluation datasets for LLM quality assessment

**Do**:
```python
# phoenix.datasets.Dataset was removed in Phoenix v12.
# Evaluation datasets are now managed via the px.Client dataset API (v15+).
import hashlib
import pandas as pd
import phoenix as px

class SecureEvalDataset:
    def __init__(self, dataset_name: str, client: px.Client, access_level: str = "internal"):
        self.access_level = access_level
        self.client = client
        self.dataset_name = dataset_name

    def get_subset_for_eval(self, eval_type: str, max_samples: int = 100) -> pd.DataFrame:
        """Return a limited, role-appropriate subset for evaluation."""
        if eval_type not in {"relevance", "toxicity", "factuality"}:
            raise ValueError(f"Unknown eval type: {eval_type!r}")

        # Fetch via client - avoids loading the full dataset locally.
        df: pd.DataFrame = self.client.get_dataset(self.dataset_name).as_dataframe()

        subset = df.sample(n=min(max_samples, len(df)), random_state=0)

        if self.access_level != "admin":
            subset = self._redact_sensitive_labels(subset)

        return subset

    def _redact_sensitive_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove ground-truth labels for non-admin callers."""
        drop_cols = [c for c in df.columns if c in {"expected_output", "ground_truth"}]
        return df.drop(columns=drop_cols)

    @staticmethod
    def verify_file_integrity(path: str, expected_sha256: str) -> None:
        """Verify a local dataset file before loading."""
        with open(path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        if actual != expected_sha256:
            raise ValueError(f"Dataset integrity check failed for {path}")

def store_eval_results(results: list, user_role: str) -> list:
    if user_role not in {"evaluator", "admin"}:
        raise PermissionError("Unauthorized to store eval results")
    log_audit_event("eval_results_stored", user_role, len(results))
    return results
```

**Don't**:
```python
# phoenix.datasets.Dataset no longer exists - import raises ImportError.
from phoenix.datasets import Dataset  # removed in v12+

eval_dataset = Dataset.from_file("/data/eval_golden.jsonl")

# No access control; exposes full golden dataset.
def get_eval_data():
    return eval_dataset.to_dataframe()

# No integrity check on remote data.
def load_eval_from_url(url: str):
    return Dataset.from_url(url)
```

**Why**: Evaluation datasets contain golden labels representing significant investment. Unrestricted access enables dataset theft for competitor training, and manipulation of eval data can mask model quality degradation.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-345 (Insufficient Verification of Data Authenticity)

---

## Rule: LLM-as-Judge Security

**Level**: `strict`

**When**: Using LLM evaluators for automated quality assessment

**Do**:
```python
import os
import pandas as pd
from phoenix.evals import llm_classify
from phoenix.evals.models import OpenAIModel

def create_secure_evaluator() -> OpenAIModel:
    """Create evaluator with security controls."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY required")

    return OpenAIModel(
        model="gpt-4o",
        api_key=api_key,
        max_tokens=500,    # cap spend; cost-attack mitigation
        temperature=0.0,   # deterministic grading
    )

def contains_injection_patterns(template: str) -> bool:
    suspicious = [
        "ignore previous",
        "disregard instructions",
        "system prompt",
    ]
    return any(p in template.lower() for p in suspicious)

def evaluate_with_guards(
    responses: list[dict],
    evaluator: OpenAIModel,
    eval_template: str,
) -> list:
    """Run evaluation with input/output guards."""
    if contains_injection_patterns(eval_template):
        raise ValueError("Eval template contains suspicious patterns")

    sanitized = [
        {
            "input": truncate_and_sanitize(r["input"], max_len=2000),
            "output": truncate_and_sanitize(r["output"], max_len=2000),
        }
        for r in responses
    ]

    results = llm_classify(
        dataframe=pd.DataFrame(sanitized),
        model=evaluator,
        template=eval_template,
        rails=["relevant", "irrelevant"],
        provide_explanation=False,
    )

    for result in results:
        if result["label"] not in {"relevant", "irrelevant"}:
            raise ValueError(f"Unexpected evaluator label: {result['label']!r}")

    return results
```

**Don't**:
```python
from phoenix.evals import llm_classify
from phoenix.evals.models import OpenAIModel

# Insecure: hardcoded API key.
model = OpenAIModel(
    model="gpt-4",
    api_key="sk-proj-abc123secret",
    max_tokens=4096,  # excessive - cost-attack vector
)

# No input validation - user-controlled template enables prompt injection.
def evaluate_responses(responses, user_template):
    return llm_classify(
        dataframe=pd.DataFrame(responses),
        model=model,
        template=user_template,
        rails=None,  # unconstrained output
    )
```

**Why**: LLM-as-judge systems can be manipulated through prompt injection to produce favorable evaluations. Unconstrained token usage enables cost attacks, and trusting evaluator output without validation can mask actual model quality issues.

**Refs**: OWASP LLM01:2025 (Prompt Injection), CWE-20 (Improper Input Validation), MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Retrieval Metrics Collection Security

**Level**: `warning`

**When**: Collecting and analyzing RAG retrieval performance metrics

**Do**:
```python
from datetime import datetime
from phoenix.trace.dsl import SpanQuery
import phoenix as px

class SecureMetricsCollector:
    ALLOWED_METRICS = frozenset([
        "latency", "token_count", "retrieval_count",
        "relevance_score", "embedding_dimension",
    ])

    def __init__(self, client: px.Client):
        self.client = client

    def collect_metrics(self, time_range: dict, metric_names: list[str]) -> list:
        """Collect only allowed aggregate metrics."""
        for metric in metric_names:
            if metric not in self.ALLOWED_METRICS:
                raise ValueError(f"Metric not in allowlist: {metric!r}")

        return self.client.query_spans(
            SpanQuery()
            .select(
                "avg(attributes.latency_ms)",
                "count()",
                "avg(attributes.retrieval_count)",
            )
            .where(f"start_time >= '{time_range['start']}'")
            .group_by("span_kind")
        )

    def export_metrics_report(self, spans: list, include_examples: bool = False) -> dict:
        report: dict = {
            "timestamp": datetime.utcnow().isoformat(),
            "aggregates": self._compute_aggregates(spans),
        }
        if include_examples:
            report["examples"] = self._get_sanitized_examples(spans, n=5)
        return report

    def _get_sanitized_examples(self, spans: list, n: int = 5) -> list:
        return [
            {
                "span_id": s.span_id,
                "latency_ms": s.attributes.get("latency_ms"),
                "retrieval_count": s.attributes.get("retrieval_count"),
                # Excluded: input.value, output.value, user.id
            }
            for s in spans[:n]
        ]
```

**Don't**:
```python
from phoenix.trace.dsl import SpanQuery

# Exports raw user queries and retrieved documents - bulk PII exfiltration.
def export_all_retrieval_data():
    spans = client.query_spans(SpanQuery().select("*"))
    return [
        {
            "query": span.attributes["input.value"],
            "retrieved_docs": span.attributes["retrieval.documents"],
            "user_id": span.attributes["user.id"],
        }
        for span in spans
    ]

# No access control on metrics endpoint.
@app.get("/metrics/all")
def get_all_metrics():
    return export_all_retrieval_data()
```

**Why**: Retrieval metrics can expose user queries, retrieved documents, and usage patterns. Unrestricted metric export enables competitive intelligence gathering and may violate user privacy expectations.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File)

---

## Rule: Local vs Hosted Deployment Security

**Level**: `strict`

**When**: Choosing and configuring Phoenix deployment model

**Do**:
```python
import os
import phoenix as px

def launch_local_phoenix() -> None:
    """Launch Phoenix locally - binds to loopback only."""
    px.launch_app(host="127.0.0.1", port=6006)
    print("Phoenix running at http://127.0.0.1:6006 (local only)")

def validate_production_env() -> None:
    """Abort startup if required security env vars are absent."""
    required = [
        "PHOENIX_ENABLE_AUTH",   # must equal "true"
        "PHOENIX_SECRET",        # random 256-bit hex
        "PHOENIX_ADMIN_SECRET",  # separate bootstrap secret
        "PHOENIX_TLS_CERT_FILE",
        "PHOENIX_TLS_KEY_FILE",
    ]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"Missing required production env vars: {missing}")

def connect_to_arize_hosted() -> px.Client:
    """Connect to Arize hosted Phoenix with proper auth."""
    api_key = os.environ.get("ARIZE_API_KEY")
    space_id = os.environ.get("ARIZE_SPACE_ID")
    if not api_key or not space_id:
        raise ValueError("ARIZE_API_KEY and ARIZE_SPACE_ID required")

    return px.Client(
        endpoint=f"https://app.arize.com/v1/spaces/{space_id}",
        api_key=api_key,
        # TLS verification is on by default; never disable it.
    )
```

**Don't**:
```python
import phoenix as px

# Binds to all interfaces with no auth.
px.launch_app(host="0.0.0.0", port=6006)

# px.launch_app() has never accepted these kwargs - they silently no-op or raise TypeError.
px.launch_app(
    host="0.0.0.0",
    port=6006,
    enable_auth=True,         # does not exist
    ssl_certfile="/certs/c",  # does not exist
    allowed_origins=["*"],    # does not exist
)
```

**Why**: Local deployments bound to all interfaces without authentication expose trace data to network attackers. Passing non-existent kwargs to `px.launch_app()` silently does nothing, leaving auth unconfigured. Production auth and TLS require env vars.

**Refs**: CWE-319 (Cleartext Transmission), CWE-295 (Improper Certificate Validation), CWE-306 (Missing Authentication)

---

## Rule: OpenInference Instrumentation

**Level**: `strict`

**When**: Instrumenting LLM applications to produce Phoenix-compatible traces

**Do**:
```python
# OpenInferenceSpan from phoenix.trace.opentelemetry never existed in any
# released version of Phoenix. Use openinference-instrumentation-* packages,
# which emit OpenTelemetry spans conforming to the OpenInference spec.

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry import trace

# Install the library for your framework, e.g.:
#   pip install openinference-instrumentation-openai==0.1.*
from openinference.instrumentation.openai import OpenAIInstrumentor

provider = TracerProvider()
trace.set_tracer_provider(provider)

# Register instrumentor - automatically wraps the OpenAI client.
OpenAIInstrumentor().instrument()

# For custom spans, use the standard OpenTelemetry API.
tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("rag.retrieval") as span:
    span.set_attribute("retrieval.query_hash", hash_query(query))  # no raw PII
    span.set_attribute("retrieval.collection", collection_name)
    results = vector_store.query(query_vector=embed(query), top_k=10)
    span.set_attribute("retrieval.result_count", len(results))
```

**Don't**:
```python
# This import does not exist in any Phoenix release - always raises ImportError.
from phoenix.trace.opentelemetry import OpenInferenceSpan  # non-existent

# Logs raw query text and document content.
with OpenInferenceSpan("retrieval") as span:
    span.set_attribute("query", raw_user_query)     # PII risk
    span.set_attribute("documents", str(all_docs))  # bulk content exposure
```

**Why**: Using non-existent imports causes runtime failures that silently drop all observability. The `openinference-instrumentation-*` packages are the supported path for Phoenix-compatible tracing and receive active security patches.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-862 (Missing Authorization), MITRE ATLAS AML.T0047 (ML Model Inference API Access)

---

## Rule: Export and Data Retention Security

**Level**: `warning`

**When**: Exporting data from Phoenix or configuring retention policies

**Do**:
```python
from datetime import datetime, timedelta
from phoenix.trace.dsl import SpanQuery
import phoenix as px

class SecureExporter:
    EXPORT_LIMITS = {"viewer": 100, "analyst": 1000, "admin": 10_000}

    def __init__(self, client: px.Client, user_role: str):
        self.client = client
        self.user_role = user_role

    def export_traces(self, time_range: dict, output_path: str) -> int:
        if self.user_role not in self.EXPORT_LIMITS:
            raise PermissionError(f"Role {self.user_role!r} cannot export")

        traces = self.client.query_spans(
            SpanQuery()
            .where(f"start_time >= '{time_range['start']}'")
            .limit(self.EXPORT_LIMITS[self.user_role])
        )

        sanitized = self._sanitize_for_export(traces)
        log_audit_event("trace_export", self.user_role, len(sanitized), output_path)
        self._write_secure(sanitized, output_path)
        return len(sanitized)

    def _sanitize_for_export(self, traces) -> list[dict]:
        return [
            {
                "trace_id": t.trace_id,
                "timestamp": t.timestamp,
                "latency_ms": t.latency_ms,
                # Excluded: input.value, output.value, user identifiers
            }
            for t in traces
        ]

def configure_retention_policy() -> None:
    """Set up data retention with security controls."""
    retention: dict[str, timedelta] = {
        "traces_with_pii": timedelta(days=7),
        "aggregate_metrics": timedelta(days=90),
        "eval_results": timedelta(days=30),
    }

    for data_type, period in retention.items():
        cutoff = datetime.utcnow() - period
        delete_data_before(data_type, cutoff)
        log_audit_event("retention_cleanup", data_type, cutoff.isoformat())
```

**Don't**:
```python
# No access control on exports - bulk PII exfiltration risk.
@app.get("/export/all")
def export_all_data():
    traces = client.get_all_traces()
    return traces.to_json()

# World-readable temp file, no audit log.
def export_traces():
    import json
    traces = client.get_traces()
    with open("/tmp/traces.json", "w") as f:
        json.dump(traces, f)
```

**Why**: Unrestricted exports enable bulk data exfiltration. Indefinite retention increases breach impact and may violate data protection regulations. Exports without sanitization expose PII and proprietary data.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File)

---

## Summary

These rules protect Arize Phoenix deployments by:

1. **Trace Ingestion**: Env-var-based auth (`PHOENIX_ENABLE_AUTH`/`PHOENIX_SECRET`), sanitization before storage
2. **OTLP Transport**: Mutual TLS and bearer-token auth on all collector connections
3. **Collector Filtering**: OTel Collector attribute-filter processor removes PII before it reaches Phoenix
4. **Embedding Drift**: Rate-limited computation using current statistical APIs; `EmbeddingDrift` removed v12
5. **Evaluation Datasets**: Access control and integrity verification via current `px.Client` dataset API
6. **LLM-as-Judge**: Input validation, output constraints, cost controls
7. **Retrieval Metrics**: Aggregate-only exports, sanitized examples
8. **Deployment Security**: `px.launch_app()` takes no auth kwargs - configure via env vars
9. **OpenInference**: Use `openinference-instrumentation-*` packages; `OpenInferenceSpan` does not exist
10. **Export/Retention**: Role-based limits, automatic cleanup

Always apply the prerequisite rules from `rules/_core/ai-security.md` and `rules/_core/rag-security.md` for comprehensive protection.
