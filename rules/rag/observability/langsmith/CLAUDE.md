# LangSmith Observability Security Rules

Security rules for LangSmith tracing, evaluation, and monitoring in LLM applications.

**Prerequisites**: `rules/_core/ai-security.md`, `rules/_core/rag-security.md`

---

## Rule: API Key Security and Rotation

**Level**: `strict`

**When**: Configuring LangSmith API keys for tracing and monitoring

**Do**: Use environment variables with rotation policies and scoped permissions

```python
import os
from langsmith import Client

# Use environment variables with scoped API keys
client = Client(
    api_key=os.environ["LANGSMITH_API_KEY"],  # From secret manager
    api_url=os.environ.get("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com")
)

# Configure tracing with minimal permissions
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "production-app"

# Implement key rotation
def rotate_langsmith_key():
    """Rotate API key through secret manager"""
    from your_secret_manager import rotate_secret
    new_key = rotate_secret("langsmith-api-key")
    # Update running instances via config reload
    return new_key
```

**Don't**: Hardcode API keys or use keys with excessive permissions

```python
from langsmith import Client

# VULNERABLE: Hardcoded API key
client = Client(api_key="ls-abc123def456...")  # Exposed in code

# VULNERABLE: Using personal key for production
os.environ["LANGSMITH_API_KEY"] = "ls-personal-key..."

# VULNERABLE: Key in version control
LANGSMITH_CONFIG = {
    "api_key": "ls-production-key...",  # Will be committed
}
```

**Why**: Exposed API keys allow attackers to access all traced data including prompts, responses, and evaluation results. LangSmith traces often contain sensitive business logic, user data, and system prompts that could be exploited.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-522 (Insufficiently Protected Credentials), OWASP LLM02:2025

---

## Rule: Trace Data Privacy and PII Protection

**Level**: `strict`

**When**: Tracing LLM calls that may contain PII in prompts or responses

**Do**: Implement trace filtering and PII redaction before sending to LangSmith

```python
from langsmith import Client
from langsmith.run_helpers import traceable
import re

class PIIRedactor:
    """Redact PII from trace data before sending to LangSmith"""

    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    }

    def redact(self, text: str) -> str:
        for pii_type, pattern in self.PATTERNS.items():
            text = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', text)
        return text

redactor = PIIRedactor()

# Custom run processor for PII redaction
def redact_run_inputs(inputs: dict) -> dict:
    """Redact PII from inputs before tracing"""
    redacted = {}
    for key, value in inputs.items():
        if isinstance(value, str):
            redacted[key] = redactor.redact(value)
        else:
            redacted[key] = value
    return redacted

@traceable(
    name="secure_llm_call",
    process_inputs=redact_run_inputs
)
def call_llm_with_privacy(prompt: str) -> str:
    """LLM call with PII redaction in traces"""
    # Actual LLM call
    return llm.invoke(prompt)

# Disable tracing for highly sensitive operations
@traceable(enabled=False)
def process_medical_records(data: dict) -> str:
    """Sensitive operation - no tracing"""
    return llm.invoke(...)
```

**Don't**: Send unfiltered user data to LangSmith traces

```python
from langsmith.run_helpers import traceable

# VULNERABLE: Tracing PII without redaction
@traceable(name="process_user_query")
def handle_user_query(user_input: str, user_email: str, ssn: str):
    prompt = f"User {user_email} (SSN: {ssn}) asks: {user_input}"
    return llm.invoke(prompt)  # PII sent to LangSmith

# VULNERABLE: No filtering of sensitive response data
@traceable
def get_user_profile(user_id: str):
    profile = database.get_full_profile(user_id)
    return llm.summarize(str(profile))  # Full profile in traces
```

**Why**: LangSmith traces persist prompts, responses, and metadata that may contain PII, health data, financial information, or other sensitive content. This data is stored in LangSmith's infrastructure and visible to all workspace members.

**Refs**: CWE-200 (Information Exposure), CWE-532 (Log Files), GDPR Article 5, OWASP LLM02:2025

---

## Rule: Project and Workspace Isolation

**Level**: `strict`

**When**: Setting up LangSmith projects for different environments or teams

**Do**: Implement strict project isolation with environment-scoped API keys and separate projects per environment

```python
import os
from langsmith import Client

# Separate projects per environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
PROJECT_NAME = f"myapp-{ENVIRONMENT}"

os.environ["LANGCHAIN_PROJECT"] = PROJECT_NAME

client = Client()

def setup_project_isolation():
    """Create an isolated project per environment.

    create_project() accepts: project_name, description, metadata,
    upsert, project_extra, reference_dataset_id.
    Trace retention is NOT a parameter -- configure it in the LangSmith
    project Settings UI (Organization -> Projects -> Settings -> Retention).
    """
    project = client.create_project(
        project_name=PROJECT_NAME,
        description=f"{ENVIRONMENT} traces - restricted access",
        metadata={"environment": ENVIRONMENT},
    )
    return project

# Workspace membership is managed through the LangSmith web UI or the
# REST API directly (GET /api/v1/workspaces/<id>/members with a bearer
# token). The Python SDK has no list_workspace_members() or
# invite_to_workspace() methods; calls to those raise AttributeError.
# Use the requests library for programmatic member inspection:
#
#   import requests
#   resp = requests.get(
#       f"{LANGSMITH_ENDPOINT}/api/v1/workspaces/{workspace_id}/members",
#       headers={"X-API-Key": os.environ["LANGSMITH_API_KEY"]},
#   )
#   members = resp.json()

# Use separate API keys per project
def get_project_api_key(project: str) -> str:
    """Get scoped API key for specific project"""
    from secret_manager import get_secret
    return get_secret(f"langsmith-{project}-api-key")
```

**Don't**: Mix environments in a single project or pass nonexistent SDK parameters

```python
# VULNERABLE: Same project for all environments
os.environ["LANGCHAIN_PROJECT"] = "my-app"  # Dev and prod mixed

# VULNERABLE: No project isolation - all users see all data
client = Client()

# VULNERABLE: Nonexistent parameter raises TypeError at runtime
project = client.create_project(
    project_name="prod",
    trace_retention_days=30  # No such parameter - raises TypeError
)

# VULNERABLE: Fabricated SDK methods raise AttributeError at runtime
client.invite_to_workspace(email="user@example.com", role="admin")
```

**Why**: Without proper isolation, development traces mix with production data, and unauthorized users can access sensitive production traces, system prompts, and evaluation results containing business logic. Calling nonexistent SDK methods raises AttributeError in production while test mocks may hide the error.

**Refs**: CWE-284 (Improper Access Control), CWE-269 (Improper Privilege Management), NIST AC-3

---

## Rule: Dataset Security for Evaluation

**Level**: `warning`

**When**: Creating and managing datasets for LLM evaluation in LangSmith

**Do**: Protect evaluation datasets with sanitized data; control sharing through the LangSmith UI

```python
from langsmith import Client

client = Client()

def create_secure_dataset(name: str, examples: list[dict]) -> str:
    """Create dataset with security controls.

    create_dataset() accepts: dataset_name, description, data_type,
    inputs_schema, outputs_schema, metadata.
    There is no is_public parameter. Dataset visibility and sharing
    are managed in the LangSmith UI (Dataset -> Share), not via the SDK.
    """

    # Validate no PII in evaluation data
    sanitized_examples = []
    for example in examples:
        if contains_pii(example):
            raise ValueError("PII detected in evaluation dataset")
        sanitized_examples.append(example)

    dataset = client.create_dataset(
        dataset_name=name,
        description="Evaluation dataset - contains sanitized test data only",
    )

    # Add examples with metadata
    for example in sanitized_examples:
        client.create_example(
            inputs=example["inputs"],
            outputs=example.get("outputs"),
            dataset_id=dataset.id,
            metadata={
                "created_by": get_current_user(),
                "sanitized": True,
                "contains_pii": False
            }
        )

    return dataset.id

# Dataset sharing is workspace-level: use the LangSmith UI to share a
# dataset with specific workspace members or generate a public share link.
# share_dataset() returns a DatasetShareSchema with a public URL only;
# it does NOT accept share_with= or permission= parameters for per-user
# access grants. Per-user access requires managing workspace membership
# through the UI or the REST API.
def get_public_share_link(dataset_id: str) -> str:
    """Return a public read-only link for a dataset (use with caution).

    Anyone with this URL can read the dataset. Only call for datasets
    confirmed to contain no PII or secrets.
    """
    share_result = client.share_dataset(dataset_id=dataset_id)
    return share_result.url
```

**Don't**: Use production data in datasets or pass fabricated SDK parameters

```python
# VULNERABLE: Production data in evaluation dataset
def create_eval_dataset():
    production_runs = client.list_runs(project_name="production", limit=1000)
    client.create_dataset(
        dataset_name="eval-dataset",
        examples=[
            {"inputs": run.inputs, "outputs": run.outputs}
            for run in production_runs  # Real user data exposed
        ]
    )

# VULNERABLE: is_public is not a parameter - raises TypeError at runtime
client.create_dataset(
    dataset_name="company-eval",
    is_public=True  # No such param - raises TypeError
)

# VULNERABLE: Fabricated share_dataset signature - raises TypeError at runtime
client.share_dataset(
    dataset_id=dataset_id,
    share_with="user@example.com",  # No such param
    permission="read"               # No such param
)
```

**Why**: Evaluation datasets often get shared more broadly than production traces. Using real production data exposes user queries and system responses to unauthorized parties. Passing nonexistent SDK parameters raises TypeError in production while permissive test mocks may hide the error entirely.

**Refs**: CWE-200 (Information Exposure), CWE-359 (Privacy Violation), OWASP LLM02:2025

---

## Rule: Feedback Collection Security

**Level**: `warning`

**When**: Collecting user feedback through LangSmith for model improvement

**Do**: Validate and sanitize feedback data with proper attribution

```python
from langsmith import Client
from datetime import datetime
import hashlib

client = Client()

def submit_secure_feedback(
    run_id: str,
    score: float,
    comment: str | None = None,
    user_id: str | None = None
):
    """Submit feedback with security controls"""

    # Validate score range
    if not 0 <= score <= 1:
        raise ValueError("Score must be between 0 and 1")

    # Sanitize comment for PII
    sanitized_comment = None
    if comment:
        sanitized_comment = redact_pii(comment)
        # Limit length to prevent abuse
        sanitized_comment = sanitized_comment[:500]

    # Hash user ID for privacy
    hashed_user = None
    if user_id:
        hashed_user = hashlib.sha256(
            f"{user_id}-{os.environ['USER_SALT']}".encode()
        ).hexdigest()[:16]

    # Submit feedback
    client.create_feedback(
        run_id=run_id,
        key="user-rating",
        score=score,
        comment=sanitized_comment,
        source_info={
            "user_hash": hashed_user,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "production-app"
        }
    )

def process_feedback_batch(feedbacks: list[dict]):
    """Process multiple feedbacks with rate limiting"""

    # Rate limit feedback submissions
    if len(feedbacks) > 100:
        raise ValueError("Feedback batch too large")

    for feedback in feedbacks:
        # Validate feedback structure
        if not is_valid_feedback(feedback):
            continue

        submit_secure_feedback(**feedback)
```

**Don't**: Accept unvalidated feedback or expose user identities

```python
# VULNERABLE: Unvalidated feedback
@app.post("/feedback")
def receive_feedback(data: dict):
    client.create_feedback(
        run_id=data["run_id"],  # No validation
        key=data["key"],  # Arbitrary key injection
        score=data["score"],  # No range check
        comment=data["comment"]  # PII in comments
    )

# VULNERABLE: Exposing user identity
client.create_feedback(
    run_id=run_id,
    source_info={
        "user_email": user.email,  # Direct PII
        "user_name": user.full_name,
        "ip_address": request.client.host
    }
)
```

**Why**: Feedback endpoints can be abused for injection attacks or data manipulation. Unvalidated feedback corrupts evaluation metrics, and storing PII in feedback creates compliance risks and potential data exposure.

**Refs**: CWE-20 (Input Validation), CWE-359 (Privacy Violation), OWASP A03:2021 Injection

---

## Rule: Hub Integration Security

**Level**: `warning`

**When**: Using LangChain Hub for prompt management with LangSmith

**Do**: Verify prompt sources and implement version control for Hub artifacts

```python
from langchain import hub
from langsmith import Client
import hashlib

client = Client()

# Maintain allowlist of trusted prompt sources
TRUSTED_OWNERS = ["your-organization", "langchain-ai"]
APPROVED_PROMPTS = {
    "your-organization/rag-prompt:v2": "sha256:abc123...",
    "your-organization/qa-prompt:v1": "sha256:def456...",
}

def load_trusted_prompt(prompt_ref: str):
    """Load prompt from Hub with verification"""

    # Parse owner from reference
    owner = prompt_ref.split("/")[0]

    # Verify trusted source
    if owner not in TRUSTED_OWNERS:
        raise SecurityError(f"Untrusted prompt source: {owner}")

    # Check if prompt is pre-approved
    if prompt_ref not in APPROVED_PROMPTS:
        raise SecurityError(f"Prompt not in approved list: {prompt_ref}")

    # Load prompt
    prompt = hub.pull(prompt_ref)

    # Verify integrity
    prompt_hash = hashlib.sha256(
        prompt.template.encode()
    ).hexdigest()

    expected_hash = APPROVED_PROMPTS[prompt_ref].replace("sha256:", "")
    if prompt_hash != expected_hash:
        raise SecurityError(
            f"Prompt integrity check failed for {prompt_ref}"
        )

    return prompt

def push_prompt_securely(
    prompt,
    repo_name: str,
    is_public: bool = False
):
    """Push prompt to Hub with security review"""

    # Check for sensitive content
    if contains_sensitive_patterns(prompt.template):
        raise SecurityError("Prompt contains sensitive patterns")

    # Require review for public prompts
    if is_public:
        require_security_review(prompt)

    # Push with private visibility by default
    hub.push(
        repo_name,
        prompt,
        new_repo_is_public=is_public,
        new_repo_description="Internal use only"
    )
```

**Don't**: Load arbitrary prompts from Hub without verification

```python
# VULNERABLE: Loading any prompt without verification
def get_prompt(user_provided_ref: str):
    return hub.pull(user_provided_ref)  # User controls source

# VULNERABLE: Publishing prompts publicly
hub.push(
    "company-internal/secret-prompt",
    prompt_with_api_keys,
    new_repo_is_public=True  # Exposed to everyone
)

# VULNERABLE: No version pinning
prompt = hub.pull("some-org/prompt")  # Gets latest, may change
```

**Why**: Hub prompts can contain prompt injection attacks or be modified by malicious actors. Loading unverified prompts allows attackers to inject malicious instructions. Publishing internal prompts publicly exposes system architecture and potential vulnerabilities.

**Refs**: CWE-829 (Untrusted Sources), CWE-494 (Download Without Integrity Check), OWASP LLM01:2025

---

## Rule: Export and Retention Policies

**Level**: `warning`

**When**: Exporting trace data or configuring retention policies

**Do**: Implement data lifecycle policies with secure export procedures

```python
from langsmith import Client
from datetime import datetime, timedelta
import json

client = Client()

# Define retention policies per data classification
RETENTION_POLICIES = {
    "production": 30,  # 30 days
    "development": 7,  # 7 days
    "evaluation": 90,  # 90 days for audit
}

def export_traces_securely(
    project_name: str,
    start_date: datetime,
    end_date: datetime,
    output_path: str
):
    """Export traces with security controls"""

    # Verify export authorization
    if not user_has_export_permission(get_current_user()):
        raise PermissionError("User not authorized for data export")

    # Log export activity
    audit_log.info(
        "trace_export",
        user=get_current_user(),
        project=project_name,
        date_range=f"{start_date} to {end_date}"
    )

    # Export with PII redaction
    runs = client.list_runs(
        project_name=project_name,
        start_time=start_date,
        end_time=end_date
    )

    redacted_runs = []
    for run in runs:
        redacted_run = {
            "id": run.id,
            "name": run.name,
            "inputs": redact_pii_dict(run.inputs),
            "outputs": redact_pii_dict(run.outputs),
            "start_time": run.start_time.isoformat(),
            "end_time": run.end_time.isoformat() if run.end_time else None,
            # Exclude raw error messages that may contain PII
            "status": run.status,
        }
        redacted_runs.append(redacted_run)

    # Encrypt export file
    encrypted_data = encrypt_data(json.dumps(redacted_runs))

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    return len(redacted_runs)

def document_retention_policy(project_name: str):
    """Record the retention policy applied to a project.

    Trace retention in LangSmith is configured in the web UI:
    Organization Settings -> Projects -> <project> -> Settings -> Retention.

    The SDK's update_project() method accepts project_id (UUID, not a
    name string), name, description, metadata, project_extra, and end_time.
    It does NOT accept trace_retention_days. Passing that kwarg raises
    TypeError; passing a project name instead of a project_id UUID also
    raises TypeError. Both errors are runtime-only and may be hidden by
    permissive test mocks.
    """
    retention_days = RETENTION_POLICIES.get(
        get_project_environment(project_name),
        30  # Default
    )

    # Log the policy for audit trail; enforcement is done in the UI.
    audit_log.info(
        "retention_policy_documented",
        project=project_name,
        retention_days=retention_days,
        note="Configure matching value in LangSmith project Settings UI"
    )
```

**Don't**: Export data without controls or call update_project with fabricated parameters

```python
# VULNERABLE: Unrestricted export
@app.get("/export-all")
def export_all_traces():
    runs = client.list_runs()  # All projects, all time
    return [
        {"inputs": r.inputs, "outputs": r.outputs, "error": r.error}
        for r in runs  # Full data, no redaction
    ]

# VULNERABLE: Two signature errors - raises TypeError at runtime
# First arg must be a UUID project_id (not a name string),
# and trace_retention_days is not a valid kwarg.
client.update_project(
    project_name,           # Wrong type: expects UUID
    trace_retention_days=30  # Nonexistent parameter
)

# VULNERABLE: Unencrypted export
with open("traces.json", "w") as f:
    json.dump(all_trace_data, f)  # Plain text sensitive data
```

**Why**: Unbounded data retention increases exposure risk and may violate data protection regulations. Uncontrolled exports can leak sensitive data, and missing audit trails prevent forensic investigation of data breaches. Calling SDK methods with fabricated signatures fails silently in permissive test mocks but raises TypeError in production.

**Refs**: CWE-200 (Information Exposure), GDPR Article 17 (Right to Erasure), NIST AU-11 (Audit Record Retention)

---

## Rule: Monitoring Dashboard Access Control

**Level**: `warning`

**When**: Configuring access to LangSmith dashboards and monitoring views

**Do**: Use environment-scoped API keys and audit access patterns; manage workspace membership through the LangSmith UI

```python
from langsmith import Client
from enum import Enum

client = Client()

class DashboardRole(Enum):
    VIEWER = "viewer"  # Read-only metrics
    ANALYST = "analyst"  # Metrics + trace inspection
    ADMIN = "admin"  # Full access including settings

# Role permissions mapping (reflects what each role sees in the UI)
ROLE_PERMISSIONS = {
    DashboardRole.VIEWER: [
        "view_metrics",
        "view_aggregates"
    ],
    DashboardRole.ANALYST: [
        "view_metrics",
        "view_aggregates",
        "view_traces",
        "view_feedback",
        "run_evaluations"
    ],
    DashboardRole.ADMIN: [
        "view_metrics",
        "view_aggregates",
        "view_traces",
        "view_feedback",
        "run_evaluations",
        "manage_projects",
        "manage_members",
        "export_data",
        "delete_data"
    ]
}

# Workspace member management is performed in the LangSmith UI
# (Settings -> Members) or via the REST API with a bearer token.
# The Python SDK has no invite_to_workspace() or list_workspace_members()
# methods. Calls to those names raise AttributeError at runtime.
#
# REST-based member lookup (requests library):
#
#   import requests
#   members = requests.get(
#       f"{LANGSMITH_ENDPOINT}/api/v1/workspaces/{workspace_id}/members",
#       headers={"X-API-Key": os.environ["LANGSMITH_API_KEY"]},
#   ).json()

def grant_dashboard_access_intent(
    user_email: str,
    role: DashboardRole,
    projects: list[str] | None = None
):
    """Log a planned access grant for audit trail.

    Execution requires a workspace admin to complete the invite in the
    LangSmith UI or via the REST API.
    """
    if not current_user_is_admin():
        raise PermissionError("Only admins can grant access")

    audit_log.info(
        "dashboard_access_requested",
        granter=get_current_user(),
        grantee=user_email,
        role=role.value,
        projects=projects or "all",
        action_required="Complete invite in LangSmith UI"
    )

def audit_dashboard_access():
    """Monitor and audit dashboard access patterns"""

    access_logs = get_workspace_access_logs(days=7)

    for log in access_logs:
        if is_unusual_access_pattern(log):
            security_alert.send(
                f"Unusual dashboard access: {log.user} "
                f"accessed {log.resource} at {log.timestamp}"
            )

        if log.action in ["export_data", "view_traces"]:
            audit_log.info(
                "sensitive_access",
                user=log.user,
                action=log.action,
                resource=log.resource
            )
```

**Don't**: Call fabricated SDK methods or grant broad access without logging

```python
# VULNERABLE: invite_to_workspace does not exist in the Python SDK
# - raises AttributeError at runtime
def add_team_member(email: str):
    client.invite_to_workspace(
        email=email,
        role="admin"  # Method does not exist
    )

# VULNERABLE: No access logging
def view_traces(project: str):
    return client.list_runs(project_name=project)
    # No audit trail of who accessed what

# VULNERABLE: Sharing dashboard URLs without auth
def get_public_dashboard_url(project: str):
    return f"https://smith.langchain.com/public/{project}"
    # Anyone with URL can access
```

**Why**: Overly permissive dashboard access exposes traces containing system prompts, user queries, and model responses to unauthorized users. Without audit logging, security incidents cannot be properly investigated or attributed. Calling nonexistent SDK methods raises AttributeError in production while broad test mocks hide the defect.

**Refs**: CWE-284 (Improper Access Control), CWE-778 (Insufficient Logging), NIST AC-6 (Least Privilege)

---

## Rule: Self-Hosted LangSmith for Sensitive Data

**Level**: `advisory`

**When**: Processing data subject to regulatory constraints (HIPAA, GDPR, FedRAMP) or handling trade-secret-level system prompts

**Do**: Deploy LangSmith on-premises or in a private cloud to keep trace data within your security boundary

```python
import os
from langsmith import Client

# Point the SDK at your self-hosted instance.
# LANGSMITH_ENDPOINT must resolve to your internal deployment,
# not the public api.smith.langchain.com endpoint.
os.environ["LANGSMITH_ENDPOINT"] = os.environ["INTERNAL_LANGSMITH_URL"]
os.environ["LANGSMITH_API_KEY"] = os.environ["INTERNAL_LANGSMITH_KEY"]
os.environ["LANGCHAIN_TRACING_V2"] = "true"

client = Client(
    api_url=os.environ["LANGSMITH_ENDPOINT"],
    api_key=os.environ["LANGSMITH_API_KEY"],
)

def verify_internal_langsmith():
    """Confirm SDK is pointed at the internal instance, not the public cloud.

    Fail closed if the internal endpoint is unreachable so regulated
    workloads do not fall back to the public SaaS.
    """
    endpoint = os.environ.get("LANGSMITH_ENDPOINT", "")
    public_endpoint = "https://api.smith.langchain.com"

    if endpoint == public_endpoint or not endpoint:
        raise RuntimeError(
            "LANGSMITH_ENDPOINT must be set to an internal host for "
            "regulated workloads. Refusing to start."
        )

    # Smoke-test connectivity -- fail closed rather than silently degrading
    try:
        client.list_projects(limit=1)
    except Exception as exc:
        raise RuntimeError(
            f"Internal LangSmith unreachable at {endpoint}: {exc}"
        ) from exc
```

**Don't**: Send regulated or highly sensitive data to the public LangSmith cloud

```python
# VULNERABLE: Regulated data sent to public SaaS
os.environ["LANGCHAIN_TRACING_V2"] = "true"
# LANGSMITH_ENDPOINT not set -- defaults to api.smith.langchain.com

@traceable(name="process_phi")
def process_patient_record(record: dict) -> str:
    # PHI leaves your network and is stored in LangSmith's SaaS infrastructure
    return llm.invoke(f"Summarize: {record}")
```

**Why**: The public LangSmith SaaS stores traces in Langchain's infrastructure. HIPAA-covered entities that send PHI require a BAA with Langchain and appropriate controls, or must self-host to keep data fully within their boundary. Trade-secret system prompts are visible to all workspace members and to Langchain as the data processor. Self-hosting eliminates the third-party data-processor risk entirely.

**Refs**: CWE-200 (Information Exposure), HIPAA §164.312, GDPR Article 28 (Data Processors), OWASP LLM02:2025
