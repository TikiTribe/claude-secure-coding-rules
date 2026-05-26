# CLAUDE.md - RAG Monitoring and Observability Security Rules

Security rules for RAG observability tooling including Weights & Biases, Prometheus/Grafana, and OpenTelemetry.

## Prerequisites

- `rules/_core/ai-security.md` - Core AI/ML security rules
- `rules/_core/rag-security.md` - RAG-specific security rules

## Overview

RAG monitoring systems collect sensitive telemetry including queries, retrieved documents, model responses, and performance metrics. Secure configuration prevents data leakage, unauthorized access, and injection attacks against monitoring infrastructure.

---

## Rule: W&B API Key Security

**Level**: `strict`

**When**: Configuring Weights & Biases for RAG experiment tracking

**Do**: Store API keys in secure secret management, use environment variables with restricted access

```python
import wandb
import os

# Load API key from secure secret manager
api_key = get_secret("wandb/api-key")  # From Vault, AWS Secrets Manager, etc.

# Initialize with explicit key (not from .netrc or environment)
wandb.login(key=api_key, relogin=True)

# Use restricted project with explicit entity
run = wandb.init(
    project="rag-pipeline-prod",
    entity="ml-team",
    config={
        "model": "gpt-4",
        "chunk_size": 512
    },
    # Disable automatic code saving if contains secrets
    save_code=False
)
```

**Don't**: Hardcode API keys or store in plaintext configuration files

```python
import wandb

# VULNERABLE: Hardcoded API key
wandb.login(key="your-api-key-here")

# VULNERABLE: Key in tracked config file
wandb.init(
    project="rag-pipeline",
    # No entity specified - may log to wrong organization
    config_exclude_keys=[]  # May expose sensitive config
)
```

**Why**: W&B API keys provide full access to projects, artifacts, and logged data. Compromised keys allow attackers to exfiltrate training data, inject malicious artifacts, or tamper with experiment history. Keys in code repositories are frequently scraped by automated tools.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-522 (Insufficiently Protected Credentials), OWASP A07:2025 (Identification and Authentication Failures)

---

## Rule: W&B Artifact Logging PII Protection

**Level**: `strict`

**When**: Logging RAG artifacts including queries, retrieved documents, or model outputs to W&B

**Do**: Sanitize PII before logging, use data masking, log only necessary fields

```python
import wandb
import re
from typing import Any

def sanitize_for_logging(data: dict[str, Any]) -> dict[str, Any]:
    """Remove PII before logging to W&B."""
    sanitized = data.copy()

    # Mask common PII patterns
    pii_patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    }

    for key, value in sanitized.items():
        if isinstance(value, str):
            for pii_type, pattern in pii_patterns.items():
                value = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', value)
            sanitized[key] = value

    return sanitized

# Log sanitized RAG interaction
rag_data = {
    "query": user_query,
    "retrieved_chunks": chunks,
    "response": model_response
}

wandb.log(sanitize_for_logging(rag_data))

# For artifacts, use restricted access
artifact = wandb.Artifact(
    name="rag-eval-dataset",
    type="dataset",
    metadata={"sanitized": True, "pii_removed": True}
)
```

**Don't**: Log raw user queries or retrieved documents without sanitization

```python
import wandb

# VULNERABLE: Logging raw user data
wandb.log({
    "query": user_query,  # May contain PII
    "context": retrieved_docs,  # May contain sensitive data
    "response": full_response,  # May echo PII
    "user_id": user_id,  # Direct identifier
    "ip_address": request.client.host  # PII
})

# VULNERABLE: Logging full document content
artifact = wandb.Artifact("retrieval-cache", type="dataset")
artifact.add_file("user_queries.json")  # Contains raw PII
```

**Why**: W&B artifacts and logs are often shared across teams, exported for analysis, or retained long-term. PII in logged data creates compliance violations (GDPR, CCPA), enables privacy breaches if W&B account is compromised, and may be used for unauthorized user profiling.

**Refs**: CWE-532 (Information Exposure Through Log Files), CWE-200 (Exposure of Sensitive Information), GDPR Article 5 (Data Minimization), OWASP A01:2025 (Broken Access Control)

---

## Rule: Prometheus Metric Endpoint Security

**Level**: `strict`

**When**: Exposing Prometheus metrics for RAG pipeline monitoring

**Do**: Restrict metric endpoint access, use authentication, avoid sensitive data in labels

```python
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()

# Define metrics without sensitive labels
rag_queries = Counter(
    'rag_queries_total',
    'Total RAG queries',
    ['status', 'model']  # No user IDs or query content
)

retrieval_latency = Histogram(
    'rag_retrieval_seconds',
    'Retrieval latency',
    ['vector_store']  # Generic labels only
)

def verify_metrics_access(credentials: HTTPBasicCredentials = Depends(security)):
    """Authenticate metrics endpoint access."""
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        os.environ["METRICS_USERNAME"].encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        os.environ["METRICS_PASSWORD"].encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(status_code=401)
    return True

@app.get("/metrics")
async def metrics(authenticated: bool = Depends(verify_metrics_access)):
    """Protected metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
```

**Don't**: Expose metrics endpoint publicly or include sensitive data in metric labels

```python
from prometheus_client import Counter, generate_latest
from fastapi import FastAPI

app = FastAPI()

# VULNERABLE: Sensitive data in labels
rag_queries = Counter(
    'rag_queries_total',
    'Total RAG queries',
    ['user_id', 'query_hash', 'ip_address']  # PII in labels
)

# VULNERABLE: Unauthenticated metrics endpoint
@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest())

# VULNERABLE: Exposing on all interfaces
# prometheus_client.start_http_server(8000, addr='0.0.0.0')
```

**Why**: Prometheus metrics endpoints expose operational intelligence including request patterns, error rates, and system architecture. Unprotected endpoints allow attackers to enumerate infrastructure, identify bottlenecks for DoS attacks, and extract user behavior patterns from high-cardinality labels.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-306 (Missing Authentication for Critical Function), OWASP A01:2025 (Broken Access Control), OWASP A09:2025 (Security Logging and Monitoring Failures)

---

## Rule: Grafana Dashboard Access Control

**Level**: `strict`

**When**: Configuring Grafana dashboards for RAG observability

**Do**: Implement role-based access, use authentication providers, restrict data source access

```yaml
# grafana.ini - Secure configuration
[auth]
disable_login_form = false
oauth_auto_login = false

[auth.generic_oauth]
enabled = true
name = Corporate SSO
client_id = ${GRAFANA_OAUTH_CLIENT_ID}
client_secret = ${GRAFANA_OAUTH_CLIENT_SECRET}
scopes = openid profile email groups
auth_url = https://sso.company.com/oauth2/authorize
token_url = https://sso.company.com/oauth2/token
api_url = https://sso.company.com/oauth2/userinfo
role_attribute_path = contains(groups[*], 'grafana-admins') && 'Admin' || contains(groups[*], 'grafana-editors') && 'Editor' || 'Viewer'

[security]
admin_password = ${GRAFANA_ADMIN_PASSWORD}
secret_key = ${GRAFANA_SECRET_KEY}
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict
strict_transport_security = true

[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Viewer

[dashboards]
versions_to_keep = 20
```

```python
# Programmatic dashboard provisioning with RBAC
dashboard_config = {
    "dashboard": {
        "title": "RAG Pipeline Metrics",
        "uid": "rag-metrics-prod",
        "editable": False,  # Prevent modification
        "panels": [...]
    },
    "folderId": rag_folder_id,
    "overwrite": False,
    "message": "Provisioned by CI/CD"
}

# Folder permissions - restrict to specific teams
folder_permissions = {
    "items": [
        {"role": "Viewer", "permission": 1},
        {"teamId": ml_ops_team_id, "permission": 2},  # Edit
        {"teamId": security_team_id, "permission": 4}  # Admin
    ]
}
```

**Don't**: Use default credentials, allow anonymous access, or share dashboards without access control

```yaml
# VULNERABLE: Insecure Grafana configuration
[auth.anonymous]
enabled = true  # Anonymous access
org_role = Viewer

[security]
admin_password = admin  # Default password
# Missing secret_key - uses default
cookie_secure = false

[users]
allow_sign_up = true  # Open registration
```

```python
# VULNERABLE: Dashboard with embedded credentials
dashboard = {
    "panels": [{
        "datasource": {
            "type": "prometheus",
            "url": "http://prometheus:9090",
            # Credentials visible in dashboard JSON
            "basicAuth": True,
            "basicAuthUser": "admin",
            "basicAuthPassword": "secret123"
        }
    }]
}
```

**Why**: Grafana dashboards reveal system architecture, performance characteristics, and operational patterns. Unauthorized access enables infrastructure reconnaissance, identification of security monitoring gaps, and potential manipulation of alerting rules. Dashboards may also expose data source credentials.

**Refs**: CWE-287 (Improper Authentication), CWE-862 (Missing Authorization), OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures)

---

## Rule: OpenTelemetry Span Data Privacy

**Level**: `strict`

**When**: Instrumenting RAG pipelines with OpenTelemetry tracing

**Do**: Filter sensitive attributes, use attribute limits, implement span processors for sanitization

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider, SpanProcessor
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
import re

class SanitizingSpanProcessor(SpanProcessor):
    """Remove sensitive data from spans before export."""

    SENSITIVE_PATTERNS = {
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'api_key': re.compile(r'(api[_-]?key|token|secret)["\s:=]+["\']?[\w-]{20,}', re.I),
        'password': re.compile(r'password["\s:=]+["\'][^"\']+["\']', re.I)
    }

    def on_start(self, span, parent_context):
        pass

    def on_end(self, span):
        # Sanitize span attributes
        for key in list(span.attributes.keys()):
            value = span.attributes.get(key)
            if isinstance(value, str):
                sanitized = self._sanitize_value(value)
                if sanitized != value:
                    span.set_attribute(key, sanitized)

    def _sanitize_value(self, value: str) -> str:
        for pii_type, pattern in self.SENSITIVE_PATTERNS.items():
            value = pattern.sub(f'[REDACTED_{pii_type.upper()}]', value)
        return value

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=None):
        pass

# Configure provider with sanitization
provider = TracerProvider(
    resource=Resource.create({
        "service.name": "rag-pipeline",
        "deployment.environment": "production"
    })
)

# Add sanitizing processor before export processor
provider.add_span_processor(SanitizingSpanProcessor())
provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)

# Use safe attribute names and values
with tracer.start_as_current_span("rag_query") as span:
    span.set_attribute("rag.query.length", len(query))  # Length, not content
    span.set_attribute("rag.chunks.count", len(chunks))
    span.set_attribute("rag.model", model_name)
    # Don't log: actual query, user ID, IP address
```

**Don't**: Log full queries, user identifiers, or sensitive content in span attributes

```python
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

# VULNERABLE: Sensitive data in spans
with tracer.start_as_current_span("rag_query") as span:
    span.set_attribute("user.query", user_query)  # Full query content
    span.set_attribute("user.id", user_id)  # PII
    span.set_attribute("user.ip", client_ip)  # PII
    span.set_attribute("retrieved.content", str(documents))  # Full doc content
    span.set_attribute("api.key", api_key)  # Credentials

    # VULNERABLE: Exception details may contain sensitive data
    try:
        result = process_query(query)
    except Exception as e:
        span.record_exception(e)  # May include PII in stack trace
        span.set_attribute("error.details", str(e))
```

**Why**: OpenTelemetry spans are exported to observability backends (Jaeger, Zipkin, commercial APM) where they are stored, searched, and often shared. Sensitive data in spans creates compliance violations, enables lateral movement if observability backend is compromised, and may be retained beyond data retention policies.

**Refs**: CWE-532 (Information Exposure Through Log Files), CWE-200 (Exposure of Sensitive Information), OWASP A09:2025 (Security Logging and Monitoring Failures)

---

## Rule: Trace Sampling for High-Volume LLM Workloads

**Level**: `warning`

**When**: Instrumenting RAG or LLM pipelines that process high request volumes with OpenTelemetry

**Do**: Use parent-based or tail sampling to control trace volume; never sample 100% in production at scale

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import (
    ParentBased,
    TraceIdRatioBased,
    ALWAYS_ON,
    ALWAYS_OFF,
)
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Parent-based sampling: respect the upstream caller's sampling decision.
# If no parent exists, sample 10% of root spans. This keeps distributed
# traces consistent — a trace is either fully sampled or fully dropped.
sampler = ParentBased(root=TraceIdRatioBased(0.10))

provider = TracerProvider(sampler=sampler)
provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

# For tail sampling, deploy an OpenTelemetry Collector with the tailsampling
# processor. This example collector config samples 100% of error traces and
# 5% of successful ones, which preserves signal on failures without
# overwhelming storage.
#
# processors:
#   tail_sampling:
#     decision_wait: 10s
#     policies:
#       - name: errors-policy
#         type: status_code
#         status_code: {status_codes: [ERROR]}
#       - name: probabilistic-policy
#         type: probabilistic
#         probabilistic: {sampling_percentage: 5}
```

**Don't**: Default to 100% sampling or disable sampling entirely in production

```python
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.sdk.trace import TracerProvider

# VULNERABLE: 100% sampling at LLM-scale throughput
# Each LLM call may generate dozens of spans; at 1000 req/s this produces
# millions of spans per minute, exhausting collector memory and budget.
provider = TracerProvider(sampler=ALWAYS_ON)
```

**Why**: LLM pipelines generate high span volumes because each request triggers retrieval, reranking, model inference, and post-processing spans. 100% sampling at scale causes collector memory exhaustion (DoS), storage cost explosion, and can slow instrumented services when the exporter queue backs up. Parent-based sampling preserves trace consistency across service boundaries. Tail sampling at the collector layer allows sampling decisions based on full trace outcomes (e.g., keep all error traces), which head sampling cannot do.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), OWASP LLM10:2025 (Unbounded Consumption), OpenTelemetry Sampling specification

---

## Rule: OTLP Exporter Security

**Level**: `strict`

**When**: Configuring OpenTelemetry Protocol (OTLP) exporters for traces, metrics, or logs

**Do**: Use TLS encryption, authenticate with headers, validate endpoints

```python
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
import os
import ssl

# Secure OTLP configuration
otlp_endpoint = os.environ["OTLP_ENDPOINT"]  # e.g., "https://collector.company.com:4317"
otlp_token = os.environ["OTLP_AUTH_TOKEN"]

# Validate endpoint uses TLS
if not otlp_endpoint.startswith("https://"):
    raise ValueError("OTLP endpoint must use TLS (https://)")

# Configure exporter with authentication and TLS
span_exporter = OTLPSpanExporter(
    endpoint=otlp_endpoint,
    headers={
        "Authorization": f"Bearer {otlp_token}",
        "X-Tenant-ID": os.environ["TENANT_ID"]
    },
    # TLS configuration
    credentials=ssl.create_default_context().load_cert_chain(
        certfile=os.environ.get("OTLP_CLIENT_CERT"),
        keyfile=os.environ.get("OTLP_CLIENT_KEY")
    ) if os.environ.get("OTLP_CLIENT_CERT") else None,
    timeout=30
)

metric_exporter = OTLPMetricExporter(
    endpoint=otlp_endpoint,
    headers={"Authorization": f"Bearer {otlp_token}"},
    insecure=False  # Require TLS
)

# For environment variable configuration
# OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.company.com:4317
# OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer token123
# OTEL_EXPORTER_OTLP_CERTIFICATE=/path/to/ca.crt
```

**Don't**: Use insecure connections or omit authentication for OTLP export

```python
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# VULNERABLE: Insecure connection
exporter = OTLPSpanExporter(
    endpoint="http://collector:4317",  # No TLS
    insecure=True  # Explicitly disabling security
)

# VULNERABLE: No authentication
exporter = OTLPSpanExporter(
    endpoint="https://collector:4317"
    # Missing headers for authentication
)

# VULNERABLE: Credentials in endpoint URL
exporter = OTLPSpanExporter(
    endpoint="https://user:password@collector:4317"  # Credentials in URL
)
```

**Why**: OTLP exporters transmit telemetry data including traces, metrics, and logs. Without TLS, this data can be intercepted, exposing application behavior and potentially sensitive span attributes. Without authentication, attackers can inject malicious telemetry or perform denial-of-service attacks on collectors.

**Refs**: CWE-319 (Cleartext Transmission of Sensitive Information), CWE-287 (Improper Authentication), OWASP A02:2025 (Cryptographic Failures), OWASP A07:2025 (Identification and Authentication Failures)

---

## Rule: Custom Metric Injection Prevention

**Level**: `strict`

**When**: Creating Prometheus metrics with user-controlled label values

**Do**: Validate and sanitize all label values, use allow-lists for dynamic labels

```python
from prometheus_client import Counter, Histogram
import re

# Define allowed values for dynamic labels
ALLOWED_MODELS = {"gpt-4", "gpt-3.5-turbo", "claude-3", "llama-2"}
ALLOWED_STATUSES = {"success", "error", "timeout", "rate_limited"}

rag_queries = Counter(
    'rag_queries_total',
    'Total RAG queries',
    ['model', 'status']
)

def sanitize_label(value: str, allowed: set[str] | None = None, max_length: int = 64) -> str:
    """Sanitize metric label value."""
    # Normalize to string
    value = str(value)

    # Check against allow-list if provided
    if allowed and value not in allowed:
        return "unknown"

    # Remove characters that could cause issues
    value = re.sub(r'[^\w\-_.]', '_', value)

    # Truncate to prevent high cardinality
    return value[:max_length]

def record_rag_query(model: str, status: str):
    """Record RAG query with sanitized labels."""
    safe_model = sanitize_label(model, ALLOWED_MODELS)
    safe_status = sanitize_label(status, ALLOWED_STATUSES)

    rag_queries.labels(model=safe_model, status=safe_status).inc()

# For histograms, avoid user-controlled bucket boundaries
retrieval_latency = Histogram(
    'rag_retrieval_seconds',
    'Retrieval latency',
    ['vector_store'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]  # Fixed buckets
)
```

**Don't**: Use unsanitized user input in metric labels or names

```python
from prometheus_client import Counter

rag_queries = Counter(
    'rag_queries_total',
    'Total RAG queries',
    ['model', 'user_query']  # User query as label = high cardinality attack
)

def record_query(model: str, query: str, user_id: str):
    # VULNERABLE: Direct user input in labels
    rag_queries.labels(
        model=model,  # Could be injected
        user_query=query[:100]  # User input in label
    ).inc()

    # VULNERABLE: Dynamic metric name from user input
    dynamic_counter = Counter(
        f'rag_queries_{user_id}',  # Metric injection
        f'Queries for {user_id}'
    )
```

**Why**: User-controlled metric labels enable cardinality attacks that exhaust Prometheus memory. Malicious label values can inject fake metrics, corrupt monitoring data, or cause denial-of-service. High-cardinality labels (like query content) make metrics unusable and expensive to store.

**Refs**: CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption), OWASP A03:2025 (Injection)

---

## Rule: Log Injection Prevention (CRLF)

**Level**: `strict`

**When**: Writing user-supplied input — including LLM prompts, retrieved document excerpts, or RAG query strings — to any log sink

**Do**: Strip or encode CRLF sequences before user-controlled values reach log output

```python
import logging
import re

# Centralise the escape logic so every log call benefits automatically.
_CRLF = re.compile(r'[\r\n]+')

def sanitize_log_value(value: str, replacement: str = " ") -> str:
    """Escape CRLF sequences that would split log lines or inject fake records.

    Replaces bare CR, bare LF, and CRLF with a space by default. Use
    replacement=repr(value) if you need to preserve the original bytes for
    forensic review — but never emit the raw bytes to a log line.
    """
    return _CRLF.sub(replacement, value)

class CRLFSafeLogger:
    """Thin wrapper that sanitizes user-controlled fields before logging."""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def info_query(self, query: str, **context):
        safe_query_len = len(query)  # Log length, not content
        # If you must log a query excerpt for debugging, sanitize first.
        safe_excerpt = sanitize_log_value(query[:120])
        self._log.info(
            "rag_query_received",
            extra={"query_length": safe_query_len, "query_excerpt": safe_excerpt, **context}
        )

logger = CRLFSafeLogger("rag")

# Safe usage
logger.info_query(user_query, model="gpt-4", tenant="acme")
```

**Don't**: Write unsanitized user input directly into log messages

```python
import logging

log = logging.getLogger("rag")

# VULNERABLE: attacker sends query = "normal query\nERROR fake_service - auth bypass"
# This injects a fake ERROR log line into the log stream, spoofing alerts.
log.info(f"Processing query: {user_query}")

# VULNERABLE: same problem with f-string formatting of retrieved content
log.debug("Retrieved chunk: " + chunk_text)

# VULNERABLE: logging full exception message that may echo user input
try:
    result = call_llm(prompt)
except Exception as exc:
    log.error(f"LLM call failed: {exc}")  # exc may contain injected newlines
```

**Why**: An attacker who controls query text can embed `\r\n` sequences to forge additional log lines, spoof severity levels, or inject structured-log fields (JSON key injection). In aggregated log pipelines (Fluent Bit, Logstash, CloudWatch), injected lines can trigger false alerts, poison dashboards, or bypass detection rules that search on field values. CWE-117 specifically covers log injection via unescaped special characters.

**Refs**: CWE-117 (Improper Output Neutralization for Logs), CWE-93 (Improper Neutralization of CRLF Sequences), OWASP A03:2025 (Injection), OWASP A09:2025 (Security Logging and Monitoring Failures), OWASP LLM02:2025 (Sensitive Information Disclosure)

---

## Rule: Alerting Security

**Level**: `warning`

**When**: Configuring alerts for RAG pipeline monitoring

**Do**: Sanitize alert content, use templates that exclude sensitive data, authenticate webhook endpoints

```yaml
# Prometheus Alertmanager configuration
global:
  resolve_timeout: 5m
  # SMTP with TLS
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alertmanager@company.com'
  smtp_auth_username: '${SMTP_USERNAME}'
  smtp_auth_password: '${SMTP_PASSWORD}'
  smtp_require_tls: true

# Webhook with authentication
receivers:
  - name: 'rag-ops-team'
    webhook_configs:
      - url: 'https://hooks.company.com/alertmanager'
        http_config:
          authorization:
            type: Bearer
            credentials: '${WEBHOOK_TOKEN}'
          tls_config:
            ca_file: /etc/alertmanager/ca.crt
        send_resolved: true
        # Use safe templates

# Alert templates that exclude sensitive data
templates:
  - '/etc/alertmanager/templates/*.tmpl'
```

```go
// alertmanager template - safe_alert.tmpl
{{ define "safe.alert" }}
Alert: {{ .Labels.alertname }}
Severity: {{ .Labels.severity }}
Service: {{ .Labels.service }}
Summary: {{ .Annotations.summary }}
{{ if .Annotations.runbook_url }}Runbook: {{ .Annotations.runbook_url }}{{ end }}
{{ end }}
```

```yaml
# Prometheus alert rules - no secrets in annotations
groups:
  - name: rag-alerts
    rules:
      - alert: RAGHighErrorRate
        expr: rate(rag_queries_total{status="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
          service: rag-pipeline
        annotations:
          summary: "High RAG error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }} errors/sec"
          runbook_url: "https://wiki.company.com/rag-troubleshooting"
          # Don't include: API keys, user data, internal IPs
```

**Don't**: Include secrets, credentials, or sensitive data in alert messages

```yaml
# VULNERABLE: Secrets in alert configuration
groups:
  - name: rag-alerts
    rules:
      - alert: RAGAPIError
        expr: rag_api_errors_total > 0
        annotations:
          summary: "API error with key {{ $labels.api_key }}"  # Exposes API key
          description: "User {{ $labels.user_id }} query failed: {{ $labels.query }}"  # PII

# VULNERABLE: Unauthenticated webhook
receivers:
  - name: 'team'
    webhook_configs:
      - url: 'http://hooks.example.com/alert'  # No TLS
        # No authentication
```

**Why**: Alert messages are transmitted to multiple systems (email, Slack, PagerDuty, webhooks) and often logged by intermediaries. Secrets in alerts can be captured by insecure receivers, exposed in notification UIs, or stored in alert history. Unauthenticated webhooks allow alert injection attacks.

**Refs**: CWE-532 (Information Exposure Through Log Files), CWE-200 (Exposure of Sensitive Information), CWE-319 (Cleartext Transmission)

---

## Rule: Prompt Injection Detection Alerting

**Level**: `warning`

**When**: Operating a RAG pipeline that processes user queries against retrieved external documents

**Do**: Instrument prompt-injection detection signals and alert when the detection rate crosses operational thresholds

```python
from prometheus_client import Counter, Histogram
import re
import logging

log = logging.getLogger("rag.security")

# ── Metrics ──────────────────────────────────────────────────────────────────
prompt_injection_detections = Counter(
    "rag_prompt_injection_detected_total",
    "Queries flagged as probable prompt injection attempts",
    ["detector", "action_taken"],  # e.g. detector=heuristic|llm_judge, action=blocked|logged
)

# ── Heuristic detector (supplement with an LLM-based judge in production) ────
# These patterns target common injection scaffolding phrases. They are not
# exhaustive; treat them as a first-pass signal, not a complete defence.
_INJECTION_PATTERNS = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|system\s*prompt"
    r"|you\s+are\s+now\s+(?:a\s+)?(?:dan|jailbreak|evil|unrestricted)"
    r"|disregard\s+(?:your\s+)?(?:instructions|guidelines|constraints)"
    r"|reveal\s+(?:your\s+)?(?:system\s+)?prompt",
    re.IGNORECASE,
)

def check_for_prompt_injection(query: str, retrieved_chunks: list[str]) -> bool:
    """Return True and record a metric if injection patterns are found.

    Check both the user query and the retrieved context: an attacker may
    embed injection instructions inside a poisoned document (indirect injection,
    OWASP LLM02:2025 / MITRE ATLAS AML.T0051).
    """
    sources_to_check = [query] + retrieved_chunks
    for source in sources_to_check:
        if _INJECTION_PATTERNS.search(source):
            prompt_injection_detections.labels(
                detector="heuristic", action_taken="flagged"
            ).inc()
            # Log length/hash, never the raw payload, to avoid log injection
            log.warning(
                "prompt_injection_flagged",
                extra={
                    "query_len": len(query),
                    "source_count": len(retrieved_chunks),
                },
            )
            return True
    return False
```

```yaml
# Prometheus alert rule — fire when injection detection rate spikes
groups:
  - name: rag-security-alerts
    rules:
      - alert: RAGPromptInjectionSpike
        # More than 5 detections in any 5-minute window
        expr: increase(rag_prompt_injection_detected_total[5m]) > 5
        for: 2m
        labels:
          severity: critical
          service: rag-pipeline
          category: prompt-injection
        annotations:
          summary: "Prompt injection detection spike on RAG pipeline"
          description: >
            {{ $value | printf "%.0f" }} injection attempts detected in the last 5 minutes.
            Review retrieval logs and consider tightening source allowlists.
          runbook_url: "https://wiki.company.com/rag-prompt-injection-response"
```

**Don't**: Treat prompt injection purely as a model-layer concern and omit monitoring signals

```python
def process_query(query: str, chunks: list[str]) -> str:
    # INSUFFICIENT: relies solely on the LLM to refuse injected instructions.
    # No metric is emitted, so a sustained injection campaign is invisible
    # to the operations team until user-facing damage occurs.
    combined_prompt = f"Context:\n{chr(10).join(chunks)}\n\nQuestion: {query}"
    return llm.complete(combined_prompt)
```

**Why**: Prompt injection (OWASP LLM01:2025) and indirect prompt injection through retrieved documents are active attack vectors against RAG systems. Without telemetry, a campaign of injection attempts is invisible until the model produces harmful output. Detection signals fed into Prometheus and Alertmanager give the security team early warning and an audit trail. Alerting on rate spikes — rather than individual events — reduces noise while catching coordinated attacks.

**Refs**: CWE-20 (Improper Input Validation), OWASP LLM01:2025 (Prompt Injection), OWASP LLM02:2025 (Sensitive Information Disclosure), OWASP A09:2025 (Security Logging and Monitoring Failures), MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Cost and Token Consumption Monitoring

**Level**: `strict`

**When**: Operating any RAG pipeline that calls external LLM APIs or self-hosted models with metered inference

**Do**: Track token consumption and API cost per user and endpoint; alert before thresholds are breached

```python
from prometheus_client import Counter, Histogram, Gauge
import os
import logging

log = logging.getLogger("rag.cost")

# ── Token counters ────────────────────────────────────────────────────────────
# Label on endpoint (e.g. /api/v1/query) and user tier, not raw user ID,
# to avoid high cardinality while still enabling per-group quota enforcement.
llm_tokens_total = Counter(
    "rag_llm_tokens_total",
    "Cumulative LLM tokens consumed (prompt + completion)",
    ["endpoint", "model", "user_tier"],
)

llm_cost_usd_total = Counter(
    "rag_llm_cost_usd_total",
    "Estimated cumulative LLM cost in USD",
    ["endpoint", "model", "user_tier"],
)

# Per-request token distribution — useful for detecting runaway prompt growth
llm_tokens_per_request = Histogram(
    "rag_llm_tokens_per_request",
    "Token count per LLM request",
    ["endpoint", "model"],
    buckets=[256, 512, 1024, 2048, 4096, 8192, 16384, 32768],
)

# Current sliding-window spend gauge (reset by a background job every hour)
llm_hourly_spend_usd = Gauge(
    "rag_llm_hourly_spend_usd",
    "Estimated LLM spend in the current rolling hour",
    ["endpoint"],
)

# ── Cost pricing table (update when provider pricing changes) ─────────────────
# Prices in USD per 1 000 tokens (prompt / completion)
_PRICE_PER_1K = {
    "gpt-4o":          (0.005,  0.015),
    "gpt-4o-mini":     (0.00015, 0.0006),
    "claude-3-5-sonnet": (0.003, 0.015),
}

def record_llm_usage(
    endpoint: str,
    model: str,
    user_tier: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> None:
    """Record token usage and estimated cost after each LLM call."""
    total_tokens = prompt_tokens + completion_tokens
    prompt_price, completion_price = _PRICE_PER_1K.get(model, (0.0, 0.0))
    estimated_cost = (
        prompt_tokens / 1000 * prompt_price
        + completion_tokens / 1000 * completion_price
    )

    llm_tokens_total.labels(
        endpoint=endpoint, model=model, user_tier=user_tier
    ).inc(total_tokens)

    llm_cost_usd_total.labels(
        endpoint=endpoint, model=model, user_tier=user_tier
    ).inc(estimated_cost)

    llm_tokens_per_request.labels(endpoint=endpoint, model=model).observe(total_tokens)

    if total_tokens > 8192:
        log.warning(
            "large_token_request",
            extra={"endpoint": endpoint, "model": model, "total_tokens": total_tokens},
        )
```

```yaml
# Prometheus alert rules for cost and consumption anomalies
groups:
  - name: rag-cost-alerts
    rules:
      # Fire when any single request consumes an unusually large token budget.
      # Tune the threshold to 2x your p99 request size baseline.
      - alert: RAGOversizedLLMRequest
        expr: |
          histogram_quantile(0.99,
            rate(rag_llm_tokens_per_request_bucket[10m])
          ) > 16384
        for: 5m
        labels:
          severity: warning
          service: rag-pipeline
        annotations:
          summary: "p99 LLM request size exceeds 16 K tokens"
          runbook_url: "https://wiki.company.com/rag-cost-runbook"

      # Fire when hourly cost projection exceeds budget ceiling.
      - alert: RAGHourlyCostBudgetExceeded
        expr: rag_llm_hourly_spend_usd > 50
        for: 0m
        labels:
          severity: critical
          service: rag-pipeline
        annotations:
          summary: "RAG hourly LLM spend exceeded $50 threshold"
          description: "Current value: ${{ $value | printf \"%.2f\" }}"
          runbook_url: "https://wiki.company.com/rag-cost-runbook"

      # Fire when per-user-tier token rate spikes — indicates a runaway agent
      # or a denial-of-wallet attack against a free tier.
      - alert: RAGTokenRateAnomaly
        expr: |
          rate(rag_llm_tokens_total{user_tier="free"}[5m]) > 500
        for: 3m
        labels:
          severity: warning
          service: rag-pipeline
        annotations:
          summary: "Abnormal token consumption rate on free tier"
          runbook_url: "https://wiki.company.com/rag-cost-runbook"
```

**Don't**: Treat LLM cost as a billing concern only and omit operational monitoring

```python
def call_llm(prompt: str) -> str:
    # VULNERABLE: No token tracking. An attacker or a buggy agent can issue
    # arbitrarily large or repeated requests, exhausting the API quota or
    # running up unbounded costs with no observable signal until the invoice
    # arrives or the API key is rate-limited.
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
```

**Why**: Unbounded token and cost consumption (OWASP LLM10:2025) is an active attack vector and an operational risk. Attackers can craft inputs that force excessive context retrieval or repeated LLM calls, exhausting API quotas or triggering runaway spend ("denial-of-wallet"). Prompt growth bugs in agentic loops produce the same effect unintentionally. Prometheus counters per endpoint and user tier provide the signal needed to enforce per-user quotas, detect anomalies early, and attribute costs for chargeback.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits), OWASP LLM10:2025 (Unbounded Consumption), OWASP A09:2025 (Security Logging and Monitoring Failures)

---

## Rule: Log Aggregation and Retention Security

**Level**: `warning`

**When**: Configuring log collection and storage for RAG observability

**Do**: Encrypt logs in transit and at rest, implement retention policies, use structured logging with sanitization

```python
import logging
import json
from datetime import datetime
from pythonjsonlogger import jsonlogger
import re

class SanitizingJsonFormatter(jsonlogger.JsonFormatter):
    """JSON formatter that sanitizes sensitive data."""

    SENSITIVE_KEYS = {'password', 'token', 'api_key', 'secret', 'authorization'}
    PII_PATTERNS = {
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'ip': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    }

    def process_log_record(self, log_record):
        # Sanitize sensitive keys
        for key in list(log_record.keys()):
            if key.lower() in self.SENSITIVE_KEYS:
                log_record[key] = '[REDACTED]'
            elif isinstance(log_record[key], str):
                # Sanitize PII in values
                for pii_type, pattern in self.PII_PATTERNS.items():
                    log_record[key] = pattern.sub(f'[{pii_type.upper()}_REDACTED]', log_record[key])

        return log_record

# Configure structured logging
handler = logging.StreamHandler()
handler.setFormatter(SanitizingJsonFormatter(
    fmt='%(timestamp)s %(level)s %(name)s %(message)s',
    timestamp=True
))

logger = logging.getLogger('rag')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Log with structured context (sensitive data auto-sanitized)
logger.info(
    "RAG query processed",
    extra={
        'query_length': len(query),
        'chunks_retrieved': len(chunks),
        'latency_ms': latency,
        'model': model_name,
        # Avoid: 'query': query, 'user_email': email
    }
)
```

```yaml
# Fluent Bit configuration with security
[SERVICE]
    Flush         5
    Log_Level     info
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/rag/*.log
    Parser            json
    Tag               rag.*
    Refresh_Interval  10

[FILTER]
    Name          modify
    Match         rag.*
    # Remove sensitive fields
    Remove        password
    Remove        api_key
    Remove        token
    Remove        authorization

[OUTPUT]
    Name          forward
    Match         *
    Host          ${FLUENTD_HOST}
    Port          24224
    tls           on
    tls.verify    on
    tls.ca_file   /etc/ssl/certs/ca.crt
    Shared_Key    ${FLUENTD_SHARED_KEY}
```

**Don't**: Log sensitive data in plaintext or transmit logs without encryption

```python
import logging

logger = logging.getLogger('rag')

# VULNERABLE: Logging sensitive data
logger.info(f"User {user_id} query: {query}")  # PII and query content
logger.debug(f"API response: {response}")  # May contain sensitive data
logger.error(f"Auth failed for token: {token}")  # Credentials in logs

# VULNERABLE: Unstructured logging makes sanitization difficult
logger.info("Query processed - " + str(request_data))  # Full request dump
```

**Why**: Logs are stored long-term, often replicated across systems, and accessed by many teams. Sensitive data in logs violates data retention policies, creates compliance risks, and can be exfiltrated if log aggregation systems are compromised. Unencrypted log transmission exposes data to network interception.

**Refs**: CWE-532 (Information Exposure Through Log Files), CWE-311 (Missing Encryption of Sensitive Data), OWASP A09:2025 (Security Logging and Monitoring Failures)

---

## Rule: Multi-Tenant Metric Isolation

**Level**: `strict`

**When**: Operating RAG observability infrastructure for multiple tenants or teams

**Do**: Implement tenant isolation at collection, storage, and query layers

```python
from prometheus_client import Counter, CollectorRegistry, generate_latest
from typing import Dict

class TenantMetricsManager:
    """Manage isolated metrics per tenant."""

    def __init__(self):
        self._registries: Dict[str, CollectorRegistry] = {}
        self._tenant_metrics: Dict[str, Dict[str, Counter]] = {}

    def get_registry(self, tenant_id: str) -> CollectorRegistry:
        """Get or create isolated registry for tenant."""
        if tenant_id not in self._registries:
            self._registries[tenant_id] = CollectorRegistry()
            self._tenant_metrics[tenant_id] = {}
        return self._registries[tenant_id]

    def record_query(self, tenant_id: str, model: str, status: str):
        """Record metric in tenant-isolated registry."""
        registry = self.get_registry(tenant_id)

        metric_key = 'rag_queries_total'
        if metric_key not in self._tenant_metrics[tenant_id]:
            self._tenant_metrics[tenant_id][metric_key] = Counter(
                'rag_queries_total',
                'Total RAG queries',
                ['model', 'status'],
                registry=registry
            )

        self._tenant_metrics[tenant_id][metric_key].labels(
            model=model,
            status=status
        ).inc()

    def get_metrics(self, tenant_id: str) -> bytes:
        """Get metrics for specific tenant only."""
        if tenant_id not in self._registries:
            return b''
        return generate_latest(self._registries[tenant_id])

# FastAPI with tenant isolation
from fastapi import FastAPI, Depends, HTTPException, Header

app = FastAPI()
metrics_manager = TenantMetricsManager()

async def get_tenant_id(x_tenant_id: str = Header(...)) -> str:
    """Extract and validate tenant ID."""
    # Validate tenant exists and is authorized
    if not await validate_tenant(x_tenant_id):
        raise HTTPException(status_code=403, detail="Invalid tenant")
    return x_tenant_id

@app.get("/metrics")
async def metrics(tenant_id: str = Depends(get_tenant_id)):
    """Return metrics for authenticated tenant only."""
    return Response(
        content=metrics_manager.get_metrics(tenant_id),
        media_type=CONTENT_TYPE_LATEST
    )
```

```yaml
# Grafana with tenant isolation using folders and data sources
# grafana-provisioning/datasources/tenant-prometheus.yaml
apiVersion: 1

datasources:
  - name: Prometheus-TenantA
    type: prometheus
    access: proxy
    url: http://prometheus-tenant-a:9090
    jsonData:
      httpHeaderName1: 'X-Tenant-ID'
    secureJsonData:
      httpHeaderValue1: 'tenant-a'
    orgId: 1  # Tenant A org

  - name: Prometheus-TenantB
    type: prometheus
    access: proxy
    url: http://prometheus-tenant-b:9090
    jsonData:
      httpHeaderName1: 'X-Tenant-ID'
    secureJsonData:
      httpHeaderValue1: 'tenant-b'
    orgId: 2  # Tenant B org
```

**Don't**: Allow cross-tenant metric access or use shared registries without isolation

```python
from prometheus_client import Counter

# VULNERABLE: Single global registry for all tenants
rag_queries = Counter(
    'rag_queries_total',
    'Total RAG queries',
    ['tenant_id', 'model', 'status']  # Tenant ID as label, not isolation
)

def record_query(tenant_id: str, model: str, status: str):
    # VULNERABLE: Tenant data in shared registry
    rag_queries.labels(
        tenant_id=tenant_id,  # Any tenant can see all data
        model=model,
        status=status
    ).inc()

# VULNERABLE: No tenant validation on metrics endpoint
@app.get("/metrics")
async def metrics():
    # Returns all tenants' data to any requestor
    return Response(content=generate_latest())
```

**Why**: Multi-tenant observability without isolation enables competitive intelligence gathering, exposes tenant-specific behavior patterns, and violates data isolation requirements. A compromised tenant account could access other tenants' operational data, enabling targeted attacks or business espionage.

**Refs**: CWE-200 (Exposure of Sensitive Information), CWE-862 (Missing Authorization), OWASP A01:2025 (Broken Access Control), OWASP A04:2025 (Insecure Design)

---

## Summary

| Rule | Level | Primary Risk |
|------|-------|--------------|
| W&B API Key Security | strict | Credential theft, artifact tampering |
| W&B Artifact Logging PII Protection | strict | Privacy violation, data exfiltration |
| Prometheus Metric Endpoint Security | strict | Infrastructure reconnaissance, DoS |
| Grafana Dashboard Access Control | strict | Unauthorized access, credential exposure |
| OpenTelemetry Span Data Privacy | strict | PII leakage through telemetry backends |
| Trace Sampling for High-Volume LLM Workloads | warning | Resource exhaustion, collector DoS |
| OTLP Exporter Security | strict | Telemetry interception, injection |
| Custom Metric Injection Prevention | strict | Cardinality DoS, metric spoofing |
| Log Injection Prevention (CRLF) | strict | Log forging, alert spoofing |
| Alerting Security | warning | Secret exposure, webhook injection |
| Prompt Injection Detection Alerting | warning | Undetected attack campaigns |
| Cost and Token Consumption Monitoring | strict | Denial-of-wallet, runaway spend |
| Log Aggregation and Retention Security | warning | PII exposure, compliance violation |
| Multi-Tenant Metric Isolation | strict | Cross-tenant data leakage |
