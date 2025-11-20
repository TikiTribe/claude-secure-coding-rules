# CLAUDE.md - Arize Phoenix Security Rules

Security rules for Arize Phoenix ML observability platform in RAG systems.

**Prerequisites**: `rules/_core/ai-security.md`, `rules/_core/rag-security.md`

---

## Rule: Secure Trace Ingestion

**Level**: `strict`

**When**: Ingesting traces from LLM applications into Phoenix

**Do**:
```python
import phoenix as px
from phoenix.trace import TraceDataset
import os

# Use environment variables for credentials
phoenix_api_key = os.environ.get("PHOENIX_API_KEY")
if not phoenix_api_key:
    raise ValueError("PHOENIX_API_KEY environment variable required")

# Configure with authentication and TLS
px.launch_app(
    host="0.0.0.0",
    port=6006,
    enable_auth=True,
    api_key=phoenix_api_key,
    # Use TLS in production
    ssl_certfile=os.environ.get("PHOENIX_SSL_CERT"),
    ssl_keyfile=os.environ.get("PHOENIX_SSL_KEY"),
)

# Sanitize trace data before ingestion
def sanitize_trace_spans(spans):
    """Remove sensitive data from trace spans before storage."""
    sanitized = []
    for span in spans:
        span_copy = span.copy()
        # Remove PII from inputs/outputs
        if "attributes" in span_copy:
            attrs = span_copy["attributes"]
            # Redact sensitive patterns
            for key in ["input.value", "output.value"]:
                if key in attrs:
                    attrs[key] = redact_pii(attrs[key])
        sanitized.append(span_copy)
    return sanitized

# Apply sanitization before adding traces
sanitized_spans = sanitize_trace_spans(raw_spans)
```

**Don't**:
```python
import phoenix as px

# Insecure: No authentication, hardcoded credentials
px.launch_app(
    host="0.0.0.0",
    port=6006,
    # No auth enabled - anyone can access
    # No TLS - data transmitted in plaintext
)

# Insecure: Logging raw traces with sensitive data
px.Client().log_traces(
    traces=raw_traces,  # May contain PII, API keys, secrets
)

# Hardcoded API key
PHOENIX_KEY = "phx_abc123secret"  # Exposed in code
```

**Why**: Trace data contains LLM inputs/outputs that may include user PII, proprietary prompts, and sensitive business data. Unauthenticated endpoints allow data exfiltration, and unencrypted transmission exposes data to interception.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-319 (Cleartext Transmission), OWASP LLM06 (Sensitive Information Disclosure)

---

## Rule: Embedding Drift Monitoring Protection

**Level**: `warning`

**When**: Monitoring embedding drift and vector distributions

**Do**:
```python
from phoenix.experiments import run_experiment
from phoenix.evals import EmbeddingDrift
import numpy as np

# Anonymize embeddings for drift analysis
def compute_drift_metrics(reference_embeddings, production_embeddings):
    """Compute drift without exposing raw embedding values."""
    # Use statistical summaries instead of raw vectors
    drift_calculator = EmbeddingDrift(
        reference_embeddings=reference_embeddings,
        # Compute aggregate metrics only
        metrics=["cosine_distance", "euclidean_distance"],
        # Don't store raw embeddings in results
        store_embeddings=False,
        # Use sampling for large datasets
        sample_size=min(1000, len(production_embeddings)),
    )

    return drift_calculator.compute(production_embeddings)

# Rate limit drift computation to prevent resource exhaustion
from functools import lru_cache
import time

class DriftMonitor:
    def __init__(self, min_interval_seconds=300):
        self.min_interval = min_interval_seconds
        self.last_computation = 0

    def compute_if_allowed(self, ref_emb, prod_emb):
        current_time = time.time()
        if current_time - self.last_computation < self.min_interval:
            raise ValueError("Drift computation rate limited")

        self.last_computation = current_time
        return compute_drift_metrics(ref_emb, prod_emb)
```

**Don't**:
```python
from phoenix.evals import EmbeddingDrift

# Insecure: No rate limiting on expensive computation
def check_drift_on_every_request(embeddings):
    # Resource exhaustion risk - runs on every request
    drift = EmbeddingDrift(
        reference_embeddings=load_all_reference_embeddings(),
        store_embeddings=True,  # Stores all raw vectors
    )
    return drift.compute(embeddings)

# Exposes raw embeddings in logs/exports
def export_drift_report():
    report = {
        "raw_reference_embeddings": reference_emb.tolist(),
        "raw_production_embeddings": prod_emb.tolist(),
        "drift_score": score
    }
    # Raw embeddings can be used for model extraction
    return json.dumps(report)
```

**Why**: Embedding drift analysis can be computationally expensive, creating DoS opportunities. Raw embedding exposure enables model extraction attacks where adversaries reconstruct the embedding model from vector samples.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), MITRE ATLAS AML.T0047 (ML Model Inference API Access)

---

## Rule: Evaluation Dataset Protection

**Level**: `strict`

**When**: Managing evaluation datasets for LLM quality assessment

**Do**:
```python
from phoenix.evals import run_evals
from phoenix.datasets import Dataset
import hashlib

# Secure evaluation dataset management
class SecureEvalDataset:
    def __init__(self, dataset_path, access_level="internal"):
        self.access_level = access_level
        self.dataset = self._load_with_validation(dataset_path)

    def _load_with_validation(self, path):
        """Load dataset with integrity verification."""
        # Verify dataset integrity
        with open(path, 'rb') as f:
            content = f.read()
            actual_hash = hashlib.sha256(content).hexdigest()

        expected_hash = self._get_expected_hash(path)
        if actual_hash != expected_hash:
            raise ValueError("Dataset integrity check failed")

        return Dataset.from_file(path)

    def get_subset_for_eval(self, eval_type, max_samples=100):
        """Return limited subset for evaluation."""
        # Prevent full dataset extraction
        if eval_type not in ["relevance", "toxicity", "factuality"]:
            raise ValueError(f"Unknown eval type: {eval_type}")

        # Sample subset to limit exposure
        subset = self.dataset.sample(n=min(max_samples, len(self.dataset)))

        # Redact ground truth for certain access levels
        if self.access_level != "admin":
            subset = self._redact_sensitive_labels(subset)

        return subset

# Use role-based access for evaluation results
def store_eval_results(results, user_role):
    if user_role not in ["evaluator", "admin"]:
        raise PermissionError("Unauthorized to store eval results")

    # Audit log
    log_audit_event("eval_results_stored", user_role, len(results))

    return results
```

**Don't**:
```python
from phoenix.datasets import Dataset

# Insecure: No access control on evaluation data
eval_dataset = Dataset.from_file("/data/eval_golden.jsonl")

# Exposes entire golden dataset
def get_eval_data():
    return eval_dataset.to_dataframe()  # Full dataset returned

# No integrity verification
def load_eval_from_url(url):
    # Loads arbitrary data without validation
    return Dataset.from_url(url)

# Stores results without access control
def save_results(results):
    with open("/shared/results.json", "w") as f:
        json.dump(results, f)  # Anyone can read
```

**Why**: Evaluation datasets contain golden labels and expected outputs that represent significant investment. Unrestricted access allows dataset theft for competitor training, and manipulation of eval data can mask model quality degradation.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-345 (Insufficient Verification of Data Authenticity)

---

## Rule: LLM-as-Judge Security

**Level**: `strict`

**When**: Using LLM evaluators for automated quality assessment

**Do**:
```python
from phoenix.evals import llm_classify
from phoenix.evals.models import OpenAIModel
import os

# Secure LLM-as-judge configuration
def create_secure_evaluator():
    """Create evaluator with security controls."""

    # Use environment variables for API keys
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY required")

    model = OpenAIModel(
        model="gpt-4",
        api_key=api_key,
        # Limit token usage to prevent cost attacks
        max_tokens=500,
        # Use lower temperature for consistent evaluation
        temperature=0.0,
    )

    return model

def evaluate_with_guards(responses, evaluator, eval_template):
    """Run evaluation with input/output guards."""

    # Validate eval template to prevent prompt injection
    if contains_injection_patterns(eval_template):
        raise ValueError("Eval template contains suspicious patterns")

    # Sanitize inputs before evaluation
    sanitized_responses = []
    for resp in responses:
        sanitized = {
            "input": truncate_and_sanitize(resp["input"], max_len=2000),
            "output": truncate_and_sanitize(resp["output"], max_len=2000),
        }
        sanitized_responses.append(sanitized)

    # Run evaluation with timeout
    results = llm_classify(
        dataframe=pd.DataFrame(sanitized_responses),
        model=evaluator,
        template=eval_template,
        rails=["relevant", "irrelevant"],  # Constrained output
        provide_explanation=False,  # Reduce token usage
    )

    # Validate evaluator outputs
    for result in results:
        if result["label"] not in ["relevant", "irrelevant"]:
            raise ValueError("Unexpected evaluator output")

    return results

def contains_injection_patterns(template):
    """Check for prompt injection in eval templates."""
    suspicious = [
        "ignore previous",
        "disregard instructions",
        "system prompt",
        "```",  # Code blocks that might escape context
    ]
    return any(p in template.lower() for p in suspicious)
```

**Don't**:
```python
from phoenix.evals import llm_classify
from phoenix.evals.models import OpenAIModel

# Insecure: Hardcoded API key
model = OpenAIModel(
    model="gpt-4",
    api_key="sk-proj-abc123secret",  # Exposed
    max_tokens=4096,  # Excessive - cost attack vector
)

# No input validation - prompt injection risk
def evaluate_responses(responses, user_template):
    # User-controlled template can manipulate evaluation
    return llm_classify(
        dataframe=pd.DataFrame(responses),
        model=model,
        template=user_template,  # Untrusted input
        rails=None,  # Unconstrained output
    )

# No output validation
results = evaluate_responses(data, template)
store_results(results)  # Trusts evaluator output blindly
```

**Why**: LLM-as-judge systems can be manipulated through prompt injection to produce favorable evaluations. Unconstrained token usage enables cost attacks, and trusting evaluator output without validation can mask actual model quality issues.

**Refs**: OWASP LLM01 (Prompt Injection), CWE-20 (Improper Input Validation), MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Retrieval Metrics Collection Security

**Level**: `warning`

**When**: Collecting and analyzing RAG retrieval performance metrics

**Do**:
```python
from phoenix.trace.dsl import SpanQuery
from phoenix.trace import TraceDataset
import phoenix as px

# Secure retrieval metrics collection
class SecureMetricsCollector:
    def __init__(self, client):
        self.client = client
        self.allowed_metrics = [
            "latency", "token_count", "retrieval_count",
            "relevance_score", "embedding_dimension"
        ]

    def collect_metrics(self, time_range, metric_names):
        """Collect only allowed aggregate metrics."""

        # Validate requested metrics
        for metric in metric_names:
            if metric not in self.allowed_metrics:
                raise ValueError(f"Metric not allowed: {metric}")

        # Query aggregates only - not raw data
        spans = self.client.query_spans(
            SpanQuery().select(
                # Aggregate metrics only
                "avg(attributes.latency_ms)",
                "count()",
                "avg(attributes.retrieval_count)",
            ).where(
                f"start_time >= '{time_range['start']}'"
            ).group_by(
                "span_kind"  # Group by type, not individual queries
            )
        )

        return spans

    def export_metrics_report(self, spans, include_examples=False):
        """Export metrics with optional sanitized examples."""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "aggregates": self._compute_aggregates(spans),
        }

        if include_examples:
            # Sanitize examples before including
            report["examples"] = self._get_sanitized_examples(spans, n=5)

        return report

    def _get_sanitized_examples(self, spans, n=5):
        """Get sanitized example spans for debugging."""
        examples = []
        for span in spans[:n]:
            examples.append({
                "span_id": span.span_id,
                "latency_ms": span.attributes.get("latency_ms"),
                "retrieval_count": span.attributes.get("retrieval_count"),
                # Exclude actual query text and retrieved content
            })
        return examples
```

**Don't**:
```python
from phoenix.trace.dsl import SpanQuery

# Insecure: Exports raw query data
def export_all_retrieval_data():
    spans = client.query_spans(
        SpanQuery().select(
            "*",  # Selects everything including sensitive data
        )
    )

    # Exports raw user queries and retrieved documents
    return [
        {
            "query": span.attributes["input.value"],
            "retrieved_docs": span.attributes["retrieval.documents"],
            "user_id": span.attributes["user.id"],
        }
        for span in spans
    ]

# No access control on metrics endpoint
@app.get("/metrics/all")
def get_all_metrics():
    return export_all_retrieval_data()  # Anyone can access
```

**Why**: Retrieval metrics can expose user queries, retrieved documents, and usage patterns. Unrestricted metric export enables competitive intelligence gathering and may violate user privacy expectations.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File)

---

## Rule: Local vs Hosted Deployment Security

**Level**: `strict`

**When**: Choosing and configuring Phoenix deployment model

**Do**:
```python
import phoenix as px
import os

# Secure local deployment
def launch_local_phoenix():
    """Launch Phoenix locally with security controls."""

    # Bind to localhost only for local development
    px.launch_app(
        host="127.0.0.1",  # Not 0.0.0.0
        port=6006,
    )

    print("Phoenix running at http://127.0.0.1:6006")
    print("Access restricted to local machine only")

# Secure hosted/production deployment
def launch_production_phoenix():
    """Launch Phoenix for production with full security."""

    # Validate required security configuration
    required_vars = [
        "PHOENIX_API_KEY",
        "PHOENIX_SSL_CERT",
        "PHOENIX_SSL_KEY",
        "PHOENIX_ALLOWED_ORIGINS",
    ]

    for var in required_vars:
        if not os.environ.get(var):
            raise ValueError(f"Required env var missing: {var}")

    px.launch_app(
        host="0.0.0.0",
        port=6006,
        # Authentication required
        enable_auth=True,
        api_key=os.environ["PHOENIX_API_KEY"],
        # TLS encryption
        ssl_certfile=os.environ["PHOENIX_SSL_CERT"],
        ssl_keyfile=os.environ["PHOENIX_SSL_KEY"],
        # CORS configuration
        allowed_origins=os.environ["PHOENIX_ALLOWED_ORIGINS"].split(","),
    )

# Use Arize hosted with proper tenant isolation
def connect_to_arize_hosted():
    """Connect to Arize hosted Phoenix with security."""

    api_key = os.environ.get("ARIZE_API_KEY")
    space_id = os.environ.get("ARIZE_SPACE_ID")

    if not api_key or not space_id:
        raise ValueError("ARIZE_API_KEY and ARIZE_SPACE_ID required")

    # Use HTTPS endpoint
    endpoint = f"https://app.arize.com/v1/spaces/{space_id}"

    return px.Client(
        endpoint=endpoint,
        api_key=api_key,
        # Verify TLS certificates
        verify_ssl=True,
    )
```

**Don't**:
```python
import phoenix as px

# Insecure: Binds to all interfaces without auth
px.launch_app(
    host="0.0.0.0",  # Exposed to network
    port=6006,
    # No authentication
    # No TLS
)

# Insecure: Disables SSL verification
client = px.Client(
    endpoint="https://app.arize.com/v1/...",
    api_key=os.environ["ARIZE_API_KEY"],
    verify_ssl=False,  # MITM attack vector
)

# Insecure: Mixed local/production configuration
def launch_phoenix(env):
    # Same insecure config for all environments
    px.launch_app(
        host="0.0.0.0",
        port=6006,
    )
```

**Why**: Local deployments bound to all interfaces without authentication expose trace data to network attackers. Production deployments require TLS, authentication, and proper access controls. Disabling SSL verification enables man-in-the-middle attacks.

**Refs**: CWE-319 (Cleartext Transmission), CWE-295 (Improper Certificate Validation), CWE-306 (Missing Authentication)

---

## Rule: Export and Data Retention Security

**Level**: `warning`

**When**: Exporting data from Phoenix or configuring retention policies

**Do**:
```python
from phoenix.trace import TraceDataset
import phoenix as px
from datetime import datetime, timedelta

# Secure export with access control
class SecureExporter:
    def __init__(self, client, user_role):
        self.client = client
        self.user_role = user_role
        self.export_limits = {
            "viewer": 100,
            "analyst": 1000,
            "admin": 10000,
        }

    def export_traces(self, time_range, output_path):
        """Export traces with role-based limits and sanitization."""

        # Check permissions
        if self.user_role not in self.export_limits:
            raise PermissionError(f"Role {self.user_role} cannot export")

        max_records = self.export_limits[self.user_role]

        # Query with limits
        traces = self.client.query_spans(
            SpanQuery()
            .where(f"start_time >= '{time_range['start']}'")
            .limit(max_records)
        )

        # Sanitize before export
        sanitized = self._sanitize_for_export(traces)

        # Log export action
        log_audit_event(
            "trace_export",
            self.user_role,
            len(sanitized),
            output_path
        )

        # Write to secure location
        self._write_secure(sanitized, output_path)

        return len(sanitized)

    def _sanitize_for_export(self, traces):
        """Remove sensitive data from export."""
        sanitized = []
        for trace in traces:
            clean_trace = {
                "trace_id": trace.trace_id,
                "timestamp": trace.timestamp,
                "latency_ms": trace.latency_ms,
                # Exclude: input.value, output.value, user identifiers
            }
            sanitized.append(clean_trace)
        return sanitized

# Configure secure retention
def configure_retention_policy():
    """Set up data retention with security controls."""

    retention_config = {
        # Shorter retention for sensitive data
        "traces_with_pii": timedelta(days=7),
        # Longer for aggregates
        "aggregate_metrics": timedelta(days=90),
        # Evaluation results
        "eval_results": timedelta(days=30),
    }

    # Automatic cleanup job
    def cleanup_expired_data():
        for data_type, retention in retention_config.items():
            cutoff = datetime.utcnow() - retention
            delete_data_before(data_type, cutoff)
            log_audit_event("data_retention_cleanup", data_type, str(cutoff))

    return cleanup_expired_data
```

**Don't**:
```python
# Insecure: No access control on exports
@app.get("/export/all")
def export_all_data():
    traces = client.get_all_traces()  # No limits
    return traces.to_json()  # Raw data with PII

# Insecure: No retention policy
# Data accumulates indefinitely with all PII

# Insecure: Export to insecure location
def export_traces():
    traces = client.get_traces()
    # World-readable file
    with open("/tmp/traces.json", "w") as f:
        json.dump(traces, f)
    # No audit logging
```

**Why**: Unrestricted exports enable bulk data exfiltration. Indefinite retention increases breach impact and may violate data protection regulations. Exports without sanitization expose PII and proprietary data.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File)

---

## Rule: Vector Store Integration Security

**Level**: `strict`

**When**: Connecting Phoenix to vector stores for retrieval tracing

**Do**:
```python
from phoenix.trace.opentelemetry import OpenInferenceSpan
import os

# Secure vector store integration
class SecureVectorStoreTracer:
    def __init__(self, vector_store_client):
        self.client = vector_store_client
        self.sensitive_collections = ["user_data", "pii_documents"]

    def trace_retrieval(self, query, collection_name, top_k=10):
        """Trace retrieval with security controls."""

        # Check collection access
        if collection_name in self.sensitive_collections:
            # Additional auth check for sensitive collections
            if not self._check_elevated_access():
                raise PermissionError(f"Elevated access required for {collection_name}")

        # Limit retrieval count
        safe_top_k = min(top_k, 100)

        # Create span with sanitized attributes
        with OpenInferenceSpan("retrieval") as span:
            # Don't log raw query for sensitive collections
            if collection_name in self.sensitive_collections:
                span.set_attribute("query_hash", hash_query(query))
            else:
                span.set_attribute("query", truncate(query, 200))

            span.set_attribute("collection", collection_name)
            span.set_attribute("top_k", safe_top_k)

            # Perform retrieval
            results = self.client.query(
                collection=collection_name,
                query_vector=self._embed(query),
                top_k=safe_top_k,
            )

            # Log result count, not content
            span.set_attribute("result_count", len(results))

            # Don't log retrieved document content
            # span.set_attribute("documents", results)  # DON'T DO THIS

            return results

    def _embed(self, text):
        """Embed text securely without logging."""
        # Embedding logic here
        pass

    def _check_elevated_access(self):
        """Check for elevated access permissions."""
        # Access control logic
        return check_user_permission("sensitive_collection_access")

# Secure connection configuration
def create_vector_store_connection():
    """Create secure vector store connection."""

    # Use environment variables
    api_key = os.environ.get("VECTOR_STORE_API_KEY")
    if not api_key:
        raise ValueError("VECTOR_STORE_API_KEY required")

    return VectorStoreClient(
        api_key=api_key,
        endpoint=os.environ.get("VECTOR_STORE_ENDPOINT"),
        # Verify TLS
        verify_ssl=True,
        # Connection timeout
        timeout=30,
    )
```

**Don't**:
```python
# Insecure: Logs all retrieved content
def trace_retrieval(query, collection):
    with OpenInferenceSpan("retrieval") as span:
        span.set_attribute("query", query)  # May contain PII

        results = client.query(collection, query)

        # Logs all retrieved documents
        span.set_attribute("documents", [
            {"content": doc.content, "metadata": doc.metadata}
            for doc in results
        ])

        return results

# Insecure: No access control on collections
def query_any_collection(collection, query, top_k):
    # No permission check
    return client.query(collection, query, top_k)

# Insecure: Hardcoded credentials
client = VectorStoreClient(
    api_key="pk_abc123secret",
    verify_ssl=False,  # MITM risk
)
```

**Why**: Vector store integrations can expose document content, user queries, and collection structure through tracing. Without access controls, attackers can enumerate and access all collections. Logging retrieved content significantly increases breach impact.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-862 (Missing Authorization), MITRE ATLAS AML.T0047 (ML Model Inference API Access)

---

## Summary

These rules protect Arize Phoenix deployments by:

1. **Trace Ingestion**: Sanitizing sensitive data, requiring authentication
2. **Embedding Drift**: Rate limiting expensive computations, protecting raw vectors
3. **Evaluation Datasets**: Access control, integrity verification
4. **LLM-as-Judge**: Input validation, output constraints, cost controls
5. **Retrieval Metrics**: Aggregate-only exports, sanitized examples
6. **Deployment Security**: Environment-appropriate configurations
7. **Export/Retention**: Role-based limits, automatic cleanup
8. **Vector Store Integration**: Collection access control, content protection

Always apply the prerequisite rules from `rules/_core/ai-security.md` and `rules/_core/rag-security.md` for comprehensive protection.
