# Zilliz Cloud Security Rules for Claude Code

> Security rules for Zilliz Cloud (managed Milvus) vector database operations

**Prerequisites**: `rules/_core/rag-security.md`, `rules/rag/_core/vector-store-security.md`

---

## Rule: Secure API Key and Cluster Authentication

**Level**: `strict`

**When**: Connecting to Zilliz Cloud clusters or managing API credentials

**Do**:
```python
import os
from pymilvus import MilvusClient

# Load credentials from environment variables
ZILLIZ_URI = os.environ.get("ZILLIZ_URI")
ZILLIZ_TOKEN = os.environ.get("ZILLIZ_TOKEN")

if not ZILLIZ_URI or not ZILLIZ_TOKEN:
    raise ValueError("Zilliz credentials not configured")

# Connect with secure token authentication
client = MilvusClient(
    uri=ZILLIZ_URI,
    token=ZILLIZ_TOKEN,
    secure=True  # Enforce TLS
)

# Use dedicated API keys per environment
# Production: Read-only keys for query services
# Development: Scoped keys with limited collections
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: Hardcoded credentials
client = MilvusClient(
    uri="https://in01-abc123.serverless.gcp-us-west1.cloud.zilliz.com",
    token="db_admin:SuperSecretPassword123",  # Hardcoded credentials
    secure=False  # Disabled TLS
)

# VULNERABLE: Using root/admin credentials in application code
client = MilvusClient(
    uri=os.environ.get("ZILLIZ_URI"),
    token="root:Milvus"  # Default credentials
)
```

**Why**: Hardcoded API keys and credentials in source code can be exposed through version control, logs, or memory dumps. Using default credentials or disabling TLS allows credential interception and unauthorized cluster access.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-319 (Cleartext Transmission), OWASP API Security Top 10

---

## Rule: Collection Access Control and Isolation

**Level**: `strict`

**When**: Creating collections or managing collection-level permissions

**Do**:
```python
from pymilvus import MilvusClient, DataType

def create_tenant_collection(client: MilvusClient, tenant_id: str):
    """Create isolated collection with proper naming and access control."""
    # Validate tenant ID format
    if not tenant_id.isalnum() or len(tenant_id) > 64:
        raise ValueError("Invalid tenant ID format")

    collection_name = f"tenant_{tenant_id}_embeddings"

    # Check if collection already exists
    if client.has_collection(collection_name):
        raise ValueError(f"Collection {collection_name} already exists")

    # Define schema with security metadata
    schema = client.create_schema(
        auto_id=True,
        enable_dynamic_field=False  # Strict schema enforcement
    )

    schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True)
    schema.add_field(field_name="embedding", datatype=DataType.FLOAT_VECTOR, dim=1536)
    schema.add_field(field_name="tenant_id", datatype=DataType.VARCHAR, max_length=64)
    schema.add_field(field_name="created_at", datatype=DataType.INT64)

    # Create with explicit configuration
    client.create_collection(
        collection_name=collection_name,
        schema=schema,
        consistency_level="Strong"  # Data consistency for security
    )

    return collection_name

def verify_collection_access(client: MilvusClient, collection_name: str, tenant_id: str):
    """Verify tenant has access to collection before operations."""
    expected_prefix = f"tenant_{tenant_id}_"
    if not collection_name.startswith(expected_prefix):
        raise PermissionError(f"Access denied to collection {collection_name}")
    return True
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: No collection isolation
def create_collection(client: MilvusClient, name: str):
    # No tenant validation or access control
    client.create_collection(
        collection_name=name,  # User-controlled name
        dimension=1536
    )

# VULNERABLE: No access verification before operations
def query_collection(client: MilvusClient, collection_name: str, query_vector):
    # Direct access without authorization check
    results = client.search(
        collection_name=collection_name,  # Any collection accessible
        data=[query_vector],
        limit=10
    )
    return results
```

**Why**: Without collection-level access control, tenants can access other tenants' data. Collection naming without validation allows injection attacks and unauthorized collection creation/access.

**Refs**: CWE-284 (Improper Access Control), CWE-863 (Incorrect Authorization), OWASP LLM03

---

## Rule: GPU Resource Limits and Tenant Isolation

**Level**: `strict`

**When**: Configuring search parameters, index types, or resource allocation

**Do**:
```python
from pymilvus import MilvusClient

# Define resource limits per tenant tier
TIER_LIMITS = {
    "free": {"search_k": 64, "nprobe": 8, "max_results": 100},
    "standard": {"search_k": 128, "nprobe": 16, "max_results": 1000},
    "enterprise": {"search_k": 256, "nprobe": 32, "max_results": 10000}
}

def search_with_limits(
    client: MilvusClient,
    collection_name: str,
    query_vectors: list,
    tenant_tier: str,
    limit: int
):
    """Execute search with resource limits based on tenant tier."""
    tier_config = TIER_LIMITS.get(tenant_tier, TIER_LIMITS["free"])

    # Enforce result limits
    safe_limit = min(limit, tier_config["max_results"])

    # Configure search parameters within tier limits
    search_params = {
        "metric_type": "COSINE",
        "params": {
            "nprobe": tier_config["nprobe"],
            "search_k": tier_config["search_k"]
        }
    }

    results = client.search(
        collection_name=collection_name,
        data=query_vectors,
        limit=safe_limit,
        search_params=search_params,
        timeout=30.0  # Prevent long-running queries
    )

    return results

def create_index_with_limits(client: MilvusClient, collection_name: str, tenant_tier: str):
    """Create index with resource-appropriate parameters."""
    if tenant_tier == "free":
        # Lightweight index for free tier
        index_params = {
            "metric_type": "COSINE",
            "index_type": "IVF_FLAT",
            "params": {"nlist": 128}
        }
    else:
        # GPU-accelerated index for paid tiers
        index_params = {
            "metric_type": "COSINE",
            "index_type": "GPU_IVF_FLAT",
            "params": {"nlist": 1024}
        }

    client.create_index(
        collection_name=collection_name,
        field_name="embedding",
        index_params=index_params
    )
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: No resource limits
def search_unlimited(client: MilvusClient, collection_name: str, query_vectors: list, limit: int):
    # User-controlled limit with no bounds
    results = client.search(
        collection_name=collection_name,
        data=query_vectors,
        limit=limit,  # Could be 1000000
        search_params={
            "metric_type": "COSINE",
            "params": {"nprobe": 1024}  # Excessive GPU usage
        }
        # No timeout - queries can run indefinitely
    )
    return results

# VULNERABLE: Unrestricted index creation
def create_expensive_index(client: MilvusClient, collection_name: str):
    # Any user can create expensive GPU indexes
    client.create_index(
        collection_name=collection_name,
        field_name="embedding",
        index_params={
            "index_type": "GPU_CAGRA",  # Most expensive index
            "params": {"intermediate_graph_degree": 128}
        }
    )
```

**Why**: Unrestricted GPU resource usage allows denial-of-service through resource exhaustion. A single tenant can monopolize cluster resources, affecting all other tenants. High nprobe values and unlimited result sets cause excessive compute costs.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Rule: Dynamic Schema Security Validation

**Level**: `strict`

**When**: Using dynamic fields or accepting user-defined schema elements

**Do**:
```python
from pymilvus import MilvusClient, DataType
import re

# Allowed field types for user-defined schemas
ALLOWED_FIELD_TYPES = {
    "varchar": DataType.VARCHAR,
    "int64": DataType.INT64,
    "float": DataType.FLOAT,
    "bool": DataType.BOOL,
    "json": DataType.JSON
}

# Maximum limits
MAX_DYNAMIC_FIELDS = 10
MAX_VARCHAR_LENGTH = 1024
MAX_FIELD_NAME_LENGTH = 64

def validate_field_name(name: str) -> bool:
    """Validate field name against injection patterns."""
    if not name or len(name) > MAX_FIELD_NAME_LENGTH:
        return False
    # Only alphanumeric and underscore, must start with letter
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', name))

def create_collection_with_dynamic_fields(
    client: MilvusClient,
    collection_name: str,
    user_fields: list[dict]
):
    """Create collection with validated user-defined fields."""
    if len(user_fields) > MAX_DYNAMIC_FIELDS:
        raise ValueError(f"Maximum {MAX_DYNAMIC_FIELDS} custom fields allowed")

    schema = client.create_schema(
        auto_id=True,
        enable_dynamic_field=False  # Disable truly dynamic fields
    )

    # Required system fields
    schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True)
    schema.add_field(field_name="embedding", datatype=DataType.FLOAT_VECTOR, dim=1536)

    # Validate and add user fields
    for field in user_fields:
        field_name = field.get("name", "")
        field_type = field.get("type", "").lower()

        if not validate_field_name(field_name):
            raise ValueError(f"Invalid field name: {field_name}")

        if field_type not in ALLOWED_FIELD_TYPES:
            raise ValueError(f"Field type not allowed: {field_type}")

        datatype = ALLOWED_FIELD_TYPES[field_type]

        if datatype == DataType.VARCHAR:
            max_length = min(field.get("max_length", 256), MAX_VARCHAR_LENGTH)
            schema.add_field(
                field_name=field_name,
                datatype=datatype,
                max_length=max_length
            )
        else:
            schema.add_field(field_name=field_name, datatype=datatype)

    client.create_collection(collection_name=collection_name, schema=schema)
```

**Don't**:
```python
from pymilvus import MilvusClient, DataType

# VULNERABLE: Unrestricted dynamic fields
def create_dynamic_collection(client: MilvusClient, collection_name: str):
    schema = client.create_schema(
        auto_id=True,
        enable_dynamic_field=True  # Allows arbitrary fields at insert time
    )
    schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True)
    schema.add_field(field_name="embedding", datatype=DataType.FLOAT_VECTOR, dim=1536)

    client.create_collection(collection_name=collection_name, schema=schema)

# VULNERABLE: No validation of user-defined fields
def add_user_field(client: MilvusClient, collection_name: str, field_def: dict):
    # Directly using user input without validation
    field_name = field_def["name"]  # Could be malicious
    field_type = eval(field_def["type"])  # Code injection!

    # No limits on field count or size
    schema = client.create_schema()
    schema.add_field(field_name=field_name, datatype=field_type)
```

**Why**: Unrestricted dynamic fields allow data injection and schema manipulation. Attackers can create fields that interfere with application logic, inject malicious data, or cause resource exhaustion through excessive field creation.

**Refs**: CWE-94 (Code Injection), CWE-20 (Improper Input Validation), CWE-943 (Improper Neutralization in Data Query Logic)

---

## Rule: Partition Key Security for Multi-Tenancy

**Level**: `strict`

**When**: Implementing multi-tenant data isolation using partition keys

**Do**:
```python
from pymilvus import MilvusClient, DataType
import hashlib

def create_multi_tenant_collection(client: MilvusClient, collection_name: str):
    """Create collection with secure partition key for tenant isolation."""
    schema = client.create_schema(auto_id=True)

    schema.add_field(field_name="id", datatype=DataType.INT64, is_primary=True)
    schema.add_field(field_name="embedding", datatype=DataType.FLOAT_VECTOR, dim=1536)
    schema.add_field(
        field_name="tenant_id",
        datatype=DataType.VARCHAR,
        max_length=64,
        is_partition_key=True  # Enable partition-based isolation
    )
    schema.add_field(field_name="content", datatype=DataType.VARCHAR, max_length=65535)

    client.create_collection(
        collection_name=collection_name,
        schema=schema,
        num_partitions=64  # Configure based on expected tenant count
    )

def insert_tenant_data(
    client: MilvusClient,
    collection_name: str,
    tenant_id: str,
    data: list[dict],
    authenticated_tenant: str
):
    """Insert data with tenant verification."""
    # Verify caller has access to this tenant
    if tenant_id != authenticated_tenant:
        raise PermissionError(f"Cannot insert data for tenant {tenant_id}")

    # Ensure all records have correct tenant_id
    for record in data:
        record["tenant_id"] = tenant_id  # Enforce tenant_id

    client.insert(collection_name=collection_name, data=data)

def search_tenant_data(
    client: MilvusClient,
    collection_name: str,
    query_vector: list,
    authenticated_tenant: str,
    limit: int = 10
):
    """Search with mandatory tenant isolation."""
    # Always filter by authenticated tenant - never trust user input
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=f'tenant_id == "{authenticated_tenant}"',  # Server-side enforcement
        limit=min(limit, 100),
        output_fields=["content", "tenant_id"]
    )

    # Verify results (defense in depth)
    for hit in results[0]:
        if hit.get("entity", {}).get("tenant_id") != authenticated_tenant:
            raise SecurityError("Cross-tenant data leakage detected")

    return results
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: User-controlled tenant filter
def search_by_tenant(
    client: MilvusClient,
    collection_name: str,
    query_vector: list,
    tenant_id: str  # User-provided, not authenticated
):
    # User can query any tenant's data
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=f'tenant_id == "{tenant_id}"',  # No verification!
        limit=100
    )
    return results

# VULNERABLE: No partition key isolation
def insert_data(client: MilvusClient, collection_name: str, data: list[dict]):
    # tenant_id can be spoofed by caller
    client.insert(collection_name=collection_name, data=data)
```

**Why**: Without proper partition key enforcement and tenant verification, attackers can query or modify other tenants' data by spoofing tenant IDs. Partition keys provide physical isolation but require application-level enforcement.

**Refs**: CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP LLM03

---

## Rule: Backup and Restore Security

**Level**: `warning`

**When**: Performing backup operations or restoring data from backups

**Do**:
```python
from pymilvus import MilvusClient
import boto3
from datetime import datetime
import hashlib

def create_secure_backup(
    client: MilvusClient,
    collection_name: str,
    tenant_id: str,
    backup_bucket: str
):
    """Create backup with encryption and access control."""
    # Verify tenant owns the collection
    if not collection_name.startswith(f"tenant_{tenant_id}_"):
        raise PermissionError("Cannot backup collection not owned by tenant")

    # Use Zilliz Cloud backup feature (if available) or export data
    backup_name = f"{collection_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    # For manual backup: Query and export with encryption
    # Note: Use Zilliz Cloud console/API for managed backups when available

    # Log backup operation for audit
    audit_log = {
        "operation": "backup",
        "collection": collection_name,
        "tenant_id": tenant_id,
        "backup_name": backup_name,
        "timestamp": datetime.utcnow().isoformat()
    }
    log_security_event(audit_log)

    return backup_name

def restore_with_validation(
    client: MilvusClient,
    backup_name: str,
    target_collection: str,
    tenant_id: str,
    expected_checksum: str
):
    """Restore backup with integrity verification."""
    # Verify backup belongs to tenant
    if not backup_name.startswith(f"tenant_{tenant_id}_"):
        raise PermissionError("Cannot restore backup not owned by tenant")

    # Verify target collection ownership
    if not target_collection.startswith(f"tenant_{tenant_id}_"):
        raise PermissionError("Cannot restore to collection not owned by tenant")

    # Verify backup integrity before restore
    # actual_checksum = calculate_backup_checksum(backup_name)
    # if actual_checksum != expected_checksum:
    #     raise ValueError("Backup integrity check failed")

    # Perform restore operation
    # Use Zilliz Cloud restore API when available

    audit_log = {
        "operation": "restore",
        "backup_name": backup_name,
        "target_collection": target_collection,
        "tenant_id": tenant_id,
        "timestamp": datetime.utcnow().isoformat()
    }
    log_security_event(audit_log)

def log_security_event(event: dict):
    """Log security-relevant events for audit trail."""
    # Send to security logging system
    print(f"SECURITY_AUDIT: {event}")
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: No access control on backups
def backup_collection(client: MilvusClient, collection_name: str):
    # Anyone can backup any collection
    backup_name = f"{collection_name}_backup"
    # Create backup without authorization check
    return backup_name

# VULNERABLE: No integrity verification on restore
def restore_backup(client: MilvusClient, backup_name: str, target: str):
    # Restore without verifying backup ownership or integrity
    # Could restore malicious/tampered data
    pass

# VULNERABLE: No audit logging
def delete_backup(backup_name: str):
    # Delete without logging - no accountability
    pass
```

**Why**: Backup operations without access control allow unauthorized data exfiltration. Restoring backups without integrity verification can introduce corrupted or malicious data. Lack of audit logging prevents detection of unauthorized backup/restore operations.

**Refs**: CWE-284 (Improper Access Control), CWE-354 (Improper Validation of Integrity Check Value), NIST SP 800-53

---

## Rule: Query Injection Prevention in Filter Expressions

**Level**: `strict`

**When**: Building filter expressions for search or query operations

**Do**:
```python
from pymilvus import MilvusClient
import re

# Allowed operators for filter expressions
ALLOWED_OPERATORS = ["==", "!=", ">", "<", ">=", "<=", "in", "like"]
ALLOWED_CONNECTORS = ["and", "or", "not"]

def sanitize_string_value(value: str) -> str:
    """Escape special characters in string values."""
    # Escape quotes and backslashes
    return value.replace("\\", "\\\\").replace('"', '\\"')

def build_safe_filter(field: str, operator: str, value, tenant_id: str) -> str:
    """Build filter expression with proper sanitization."""
    # Validate field name
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', field):
        raise ValueError(f"Invalid field name: {field}")

    # Validate operator
    if operator.lower() not in ALLOWED_OPERATORS:
        raise ValueError(f"Invalid operator: {operator}")

    # Build value part based on type
    if isinstance(value, str):
        safe_value = f'"{sanitize_string_value(value)}"'
    elif isinstance(value, (int, float)):
        safe_value = str(value)
    elif isinstance(value, list):
        # For 'in' operator
        if all(isinstance(v, str) for v in value):
            safe_values = [f'"{sanitize_string_value(v)}"' for v in value]
        else:
            safe_values = [str(v) for v in value]
        safe_value = f"[{', '.join(safe_values)}]"
    else:
        raise ValueError(f"Unsupported value type: {type(value)}")

    # Always include tenant isolation
    user_filter = f'{field} {operator} {safe_value}'
    return f'tenant_id == "{tenant_id}" and ({user_filter})'

def search_with_safe_filter(
    client: MilvusClient,
    collection_name: str,
    query_vector: list,
    filters: list[dict],
    tenant_id: str
):
    """Execute search with safely constructed filters."""
    # Build filter parts
    filter_parts = []
    for f in filters:
        safe_filter = build_safe_filter(
            field=f["field"],
            operator=f["operator"],
            value=f["value"],
            tenant_id=tenant_id
        )
        filter_parts.append(safe_filter)

    # Combine with tenant isolation always enforced
    if filter_parts:
        final_filter = " and ".join(filter_parts)
    else:
        final_filter = f'tenant_id == "{tenant_id}"'

    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=final_filter,
        limit=100
    )

    return results
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: Direct string concatenation
def search_with_filter(client: MilvusClient, collection_name: str, query_vector: list, user_filter: str):
    # User can inject arbitrary filter expressions
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=user_filter,  # e.g., 'true or tenant_id == "other_tenant"'
        limit=100
    )
    return results

# VULNERABLE: Unescaped string interpolation
def search_by_category(client: MilvusClient, collection_name: str, query_vector: list, category: str):
    # category could be: '" or tenant_id != "attacker'
    filter_expr = f'category == "{category}"'
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=filter_expr,
        limit=100
    )
    return results

# VULNERABLE: No tenant isolation in filter
def search_all(client: MilvusClient, collection_name: str, query_vector: list, status: str):
    # Missing tenant_id filter allows cross-tenant access
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=f'status == "{status}"',  # No tenant isolation
        limit=100
    )
    return results
```

**Why**: Filter expression injection allows attackers to bypass access controls, access other tenants' data, or extract unauthorized information. Unlike SQL injection, filter injection in vector databases can expose entire collections of sensitive embeddings and metadata.

**Refs**: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic), CWE-89 (SQL Injection - similar pattern), OWASP LLM03

---

## Rule: Rate Limiting and Quota Management

**Level**: `strict`

**When**: Handling client requests or managing API usage

**Do**:
```python
from pymilvus import MilvusClient
from datetime import datetime, timedelta
import time
from functools import wraps
import threading

class RateLimiter:
    """Token bucket rate limiter for Zilliz operations."""

    def __init__(self):
        self.tenant_buckets = {}
        self.lock = threading.Lock()

        # Define limits per tier
        self.tier_limits = {
            "free": {"requests_per_minute": 60, "vectors_per_day": 10000},
            "standard": {"requests_per_minute": 300, "vectors_per_day": 100000},
            "enterprise": {"requests_per_minute": 1000, "vectors_per_day": 1000000}
        }

    def check_rate_limit(self, tenant_id: str, tier: str) -> bool:
        """Check if request is within rate limits."""
        with self.lock:
            now = datetime.utcnow()
            limits = self.tier_limits.get(tier, self.tier_limits["free"])

            if tenant_id not in self.tenant_buckets:
                self.tenant_buckets[tenant_id] = {
                    "requests": [],
                    "vectors_today": 0,
                    "day_start": now.date()
                }

            bucket = self.tenant_buckets[tenant_id]

            # Reset daily counter if new day
            if bucket["day_start"] != now.date():
                bucket["vectors_today"] = 0
                bucket["day_start"] = now.date()

            # Clean old requests (outside 1-minute window)
            cutoff = now - timedelta(minutes=1)
            bucket["requests"] = [r for r in bucket["requests"] if r > cutoff]

            # Check rate limit
            if len(bucket["requests"]) >= limits["requests_per_minute"]:
                return False

            bucket["requests"].append(now)
            return True

    def record_vectors(self, tenant_id: str, count: int, tier: str) -> bool:
        """Record vector operations and check quota."""
        with self.lock:
            limits = self.tier_limits.get(tier, self.tier_limits["free"])
            bucket = self.tenant_buckets.get(tenant_id, {})

            if bucket.get("vectors_today", 0) + count > limits["vectors_per_day"]:
                return False

            bucket["vectors_today"] = bucket.get("vectors_today", 0) + count
            return True

rate_limiter = RateLimiter()

def rate_limited(tier_func):
    """Decorator for rate-limited Zilliz operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tenant_id = kwargs.get("tenant_id") or args[1]  # Adjust index as needed
            tier = tier_func(tenant_id)

            if not rate_limiter.check_rate_limit(tenant_id, tier):
                raise Exception(f"Rate limit exceeded for tenant {tenant_id}")

            return func(*args, **kwargs)
        return wrapper
    return decorator

def get_tenant_tier(tenant_id: str) -> str:
    """Get tier for tenant from database/config."""
    # Implement actual tier lookup
    return "standard"

@rate_limited(get_tenant_tier)
def insert_vectors(
    client: MilvusClient,
    tenant_id: str,
    collection_name: str,
    vectors: list
):
    """Insert vectors with rate limiting and quota enforcement."""
    tier = get_tenant_tier(tenant_id)

    # Check vector quota
    if not rate_limiter.record_vectors(tenant_id, len(vectors), tier):
        raise Exception(f"Daily vector quota exceeded for tenant {tenant_id}")

    # Batch size limits
    max_batch = 1000
    if len(vectors) > max_batch:
        raise ValueError(f"Batch size exceeds limit of {max_batch}")

    # Execute insert
    client.insert(collection_name=collection_name, data=vectors)

@rate_limited(get_tenant_tier)
def search_vectors(
    client: MilvusClient,
    tenant_id: str,
    collection_name: str,
    query_vector: list,
    limit: int
):
    """Search with rate limiting."""
    results = client.search(
        collection_name=collection_name,
        data=[query_vector],
        filter=f'tenant_id == "{tenant_id}"',
        limit=min(limit, 100),
        timeout=30.0
    )
    return results
```

**Don't**:
```python
from pymilvus import MilvusClient

# VULNERABLE: No rate limiting
def insert_unlimited(client: MilvusClient, collection_name: str, vectors: list):
    # Any client can insert unlimited vectors
    client.insert(collection_name=collection_name, data=vectors)

# VULNERABLE: No quota tracking
def search_unlimited(client: MilvusClient, collection_name: str, query: list):
    # No limits on search frequency or result count
    results = client.search(
        collection_name=collection_name,
        data=query,
        limit=10000  # Excessive results
    )
    return results

# VULNERABLE: No batch size limits
def bulk_insert(client: MilvusClient, collection_name: str, vectors: list):
    # Could receive millions of vectors in single request
    client.insert(collection_name=collection_name, data=vectors)
```

**Why**: Without rate limiting and quota management, malicious or misconfigured clients can exhaust cluster resources, cause service degradation for all tenants, and incur excessive costs. Rate limiting protects against both intentional abuse and accidental resource exhaustion.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits), OWASP API4:2023 (Unrestricted Resource Consumption)

---

## Audit Trail

```yaml
- audit: p0.5
  date: 2026-05-26
  status: failed
  defects:
    - id: D1
      check: owasp-refs-versioned
      severity: warning
      detail: >
        All OWASP/LLM refs lack :2025 versioning. Found "OWASP API Security Top 10"
        (no year), "OWASP LLM03" (no year), "OWASP API4:2023". All must carry :2025 suffix.
    - id: D2
      check: vpc-peering-private-connectivity
      severity: warning
      detail: >
        No rule or advisory covering VPC peering for private Zilliz Cloud connectivity.
        Production deployments should route cluster traffic over private endpoints,
        not the public internet.
    - id: D3
      check: rbac-collection-partition-level
      severity: warning
      detail: >
        Collection access control uses naming-convention guards only. No pymilvus RBAC
        API usage (create_role, grant_privilege, grant_role) demonstrating
        collection- or partition-level role grants enforced by the cluster.
  passed_checks:
    - pymilvus-api-current        # MilvusClient uri+token matches pymilvus 2.x / Zilliz Cloud
    - cluster-auth-api-key        # Rule 1 covers env-var-sourced token with TLS enforcement
    - partition-isolation         # Partition key multi-tenancy rule present and correct
    - expr-filter-injection       # build_safe_filter with field/operator allowlist present
```
