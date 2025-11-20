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

**Refs**: CWE-798 (Hardcoded Credentials), CWE-522 (Insufficiently Protected Credentials), OWASP LLM06

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

**Refs**: CWE-200 (Information Exposure), CWE-532 (Log Files), GDPR Article 5, OWASP LLM06

---

## Rule: Project and Workspace Isolation

**Level**: `strict`

**When**: Setting up LangSmith projects for different environments or teams

**Do**: Implement strict workspace and project isolation with RBAC

```python
import os
from langsmith import Client

# Separate projects per environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
PROJECT_NAME = f"myapp-{ENVIRONMENT}"

os.environ["LANGCHAIN_PROJECT"] = PROJECT_NAME

# Configure workspace-level isolation
client = Client()

def setup_project_isolation():
    """Configure project with appropriate access controls"""

    # Create project with specific settings
    project = client.create_project(
        project_name=PROJECT_NAME,
        description=f"Production traces - restricted access",
        # Set retention based on environment
        trace_retention_days=30 if ENVIRONMENT == "production" else 7
    )

    # Verify workspace membership
    workspace_members = client.list_workspace_members()
    production_authorized = ["security-team", "sre-team"]

    for member in workspace_members:
        if ENVIRONMENT == "production" and member.role == "admin":
            if member.email not in production_authorized:
                raise SecurityError(
                    f"Unauthorized admin in production workspace: {member.email}"
                )

    return project

# Use separate API keys per project
def get_project_api_key(project: str) -> str:
    """Get scoped API key for specific project"""
    from secret_manager import get_secret
    return get_secret(f"langsmith-{project}-api-key")
```

**Don't**: Mix environments or use shared workspaces without access control

```python
# VULNERABLE: Same project for all environments
os.environ["LANGCHAIN_PROJECT"] = "my-app"  # Dev and prod mixed

# VULNERABLE: No workspace isolation
client = Client()  # All users see all data

# VULNERABLE: Sharing production access broadly
def grant_access(user_email: str):
    client.invite_to_workspace(
        email=user_email,
        role="admin"  # Everyone gets admin
    )
```

**Why**: Without proper isolation, development traces mix with production data, and unauthorized users can access sensitive production traces, system prompts, and evaluation results containing business logic.

**Refs**: CWE-284 (Improper Access Control), CWE-269 (Improper Privilege Management), NIST AC-3

---

## Rule: Dataset Security for Evaluation

**Level**: `warning`

**When**: Creating and managing datasets for LLM evaluation in LangSmith

**Do**: Protect evaluation datasets with access controls and data sanitization

```python
from langsmith import Client
from langsmith.schemas import Example

client = Client()

def create_secure_dataset(
    name: str,
    examples: list[dict],
    is_public: bool = False
) -> str:
    """Create dataset with security controls"""

    # Validate no PII in evaluation data
    sanitized_examples = []
    for example in examples:
        if contains_pii(example):
            raise ValueError("PII detected in evaluation dataset")
        sanitized_examples.append(example)

    # Create private dataset by default
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

def share_dataset_securely(dataset_id: str, team_emails: list[str]):
    """Share dataset with specific team members only"""

    # Verify recipients are authorized
    authorized_teams = get_authorized_evaluators()
    for email in team_emails:
        if email not in authorized_teams:
            raise PermissionError(f"Unauthorized access request: {email}")

    # Share with read-only access
    for email in team_emails:
        client.share_dataset(
            dataset_id=dataset_id,
            share_with=email,
            permission="read"  # Not write/admin
        )
```

**Don't**: Use production data in datasets or share broadly

```python
# VULNERABLE: Production data in evaluation dataset
def create_eval_dataset():
    # Using real user queries for evaluation
    production_runs = client.list_runs(
        project_name="production",
        limit=1000
    )

    client.create_dataset(
        dataset_name="eval-dataset",
        examples=[
            {"inputs": run.inputs, "outputs": run.outputs}
            for run in production_runs  # Real user data exposed
        ]
    )

# VULNERABLE: Public dataset with sensitive examples
client.create_dataset(
    dataset_name="company-eval",
    is_public=True  # Anyone can access
)
```

**Why**: Evaluation datasets often get shared more broadly than production traces. Using real production data exposes user queries and system responses to unauthorized parties, potentially including competitors accessing public datasets.

**Refs**: CWE-200 (Information Exposure), CWE-359 (Privacy Violation), OWASP LLM06

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

**Refs**: CWE-20 (Input Validation), CWE-359 (Privacy Violation), OWASP A03 Injection

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

**Refs**: CWE-829 (Untrusted Sources), CWE-494 (Download Without Integrity Check), OWASP LLM01

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

def enforce_retention_policy(project_name: str):
    """Delete traces beyond retention period"""

    retention_days = RETENTION_POLICIES.get(
        get_project_environment(project_name),
        30  # Default
    )

    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    # Note: LangSmith handles retention through project settings
    # This demonstrates the policy enforcement pattern
    client.update_project(
        project_name,
        trace_retention_days=retention_days
    )

    audit_log.info(
        "retention_policy_applied",
        project=project_name,
        retention_days=retention_days
    )
```

**Don't**: Export data without controls or ignore retention requirements

```python
# VULNERABLE: Unrestricted export
@app.get("/export-all")
def export_all_traces():
    runs = client.list_runs()  # All projects, all time
    return [
        {"inputs": r.inputs, "outputs": r.outputs, "error": r.error}
        for r in runs  # Full data, no redaction
    ]

# VULNERABLE: No retention policy
# Traces accumulate indefinitely with no cleanup

# VULNERABLE: Unencrypted export
with open("traces.json", "w") as f:
    json.dump(all_trace_data, f)  # Plain text sensitive data
```

**Why**: Unbounded data retention increases exposure risk and may violate data protection regulations. Uncontrolled exports can leak sensitive data, and missing audit trails prevent forensic investigation of data breaches.

**Refs**: CWE-200 (Information Exposure), GDPR Article 17 (Right to Erasure), NIST AU-11 (Audit Record Retention)

---

## Rule: Monitoring Dashboard Access Control

**Level**: `warning`

**When**: Configuring access to LangSmith dashboards and monitoring views

**Do**: Implement role-based access with audit logging for dashboard access

```python
from langsmith import Client
from enum import Enum

client = Client()

class DashboardRole(Enum):
    VIEWER = "viewer"  # Read-only metrics
    ANALYST = "analyst"  # Metrics + trace inspection
    ADMIN = "admin"  # Full access including settings

# Role permissions mapping
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

def grant_dashboard_access(
    user_email: str,
    role: DashboardRole,
    projects: list[str] | None = None
):
    """Grant scoped dashboard access with audit logging"""

    # Verify granter has permission
    if not current_user_is_admin():
        raise PermissionError("Only admins can grant access")

    # Log access grant
    audit_log.info(
        "dashboard_access_granted",
        granter=get_current_user(),
        grantee=user_email,
        role=role.value,
        projects=projects or "all"
    )

    # Grant workspace access with role
    # Note: Actual API depends on LangSmith workspace management
    client.invite_to_workspace(
        email=user_email,
        role=role.value
    )

    # Restrict to specific projects if specified
    if projects:
        restrict_to_projects(user_email, projects)

def audit_dashboard_access():
    """Monitor and audit dashboard access patterns"""

    # Get recent access logs
    access_logs = get_workspace_access_logs(
        days=7
    )

    # Check for anomalies
    for log in access_logs:
        # Alert on unusual patterns
        if is_unusual_access_pattern(log):
            security_alert.send(
                f"Unusual dashboard access: {log.user} "
                f"accessed {log.resource} at {log.timestamp}"
            )

        # Alert on sensitive data access
        if log.action in ["export_data", "view_traces"]:
            audit_log.info(
                "sensitive_access",
                user=log.user,
                action=log.action,
                resource=log.resource
            )
```

**Don't**: Grant broad access or skip access logging

```python
# VULNERABLE: Everyone gets admin
def add_team_member(email: str):
    client.invite_to_workspace(
        email=email,
        role="admin"  # No role differentiation
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

**Why**: Overly permissive dashboard access exposes traces containing system prompts, user queries, and model responses to unauthorized users. Without audit logging, security incidents cannot be properly investigated or attributed.

**Refs**: CWE-284 (Improper Access Control), CWE-778 (Insufficient Logging), NIST AC-6 (Least Privilege)
