# Pinecone Security Rules

Security rules for Pinecone vector database implementations. These rules extend the core vector store security rules with Pinecone-specific guidance.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| API Key Management | `strict` | Credential exposure, unauthorized access |
| Namespace Isolation for Multi-Tenancy | `strict` | Cross-tenant data leakage |
| Metadata Filter Injection Prevention | `strict` | Filter bypass, data exfiltration |
| Serverless Configuration Security | `strict` | Cost overruns, data residency violations |
| Hybrid Search Security | `warning` | Score manipulation, result poisoning |
| Index Operations Security | `warning` | Data loss, unauthorized modifications |
| Query Result Validation | `warning` | Data leakage, integrity violations |

---

## Rule: API Key Management

**Level**: `strict`

**When**: Initializing Pinecone client or managing API credentials

**Do**: Use environment variables, implement key rotation, and use scoped keys for different operations

```python
import os
from pinecone import Pinecone

# Secure client initialization
def create_pinecone_client(role: str = "query") -> Pinecone:
    """Create Pinecone client with role-appropriate API key."""

    # Use separate keys for different operations
    key_mapping = {
        "query": "PINECONE_QUERY_API_KEY",      # Read-only operations
        "index": "PINECONE_INDEX_API_KEY",      # Write operations
        "admin": "PINECONE_ADMIN_API_KEY"       # Administrative tasks
    }

    env_var = key_mapping.get(role)
    if not env_var:
        raise ValueError(f"Unknown role: {role}")

    api_key = os.environ.get(env_var)
    if not api_key:
        raise EnvironmentError(f"Missing environment variable: {env_var}")

    # Validate key format (basic check)
    if len(api_key) < 20 or not api_key.startswith(("pcsk_", "pk_")):
        raise ValueError("Invalid API key format")

    return Pinecone(
        api_key=api_key,
        pool_threads=4,
        timeout=30
    )

# Role-based client wrapper
class SecurePineconeClient:
    def __init__(self, role: str):
        self.client = create_pinecone_client(role)
        self.role = role
        self._can_write = role in ("index", "admin")
        self._can_admin = role == "admin"

    def get_index(self, index_name: str):
        return self.client.Index(index_name)

    def upsert(self, index_name: str, vectors: list, namespace: str):
        if not self._can_write:
            raise PermissionError(f"Role '{self.role}' cannot perform write operations")
        index = self.get_index(index_name)
        return index.upsert(vectors=vectors, namespace=namespace)

    def delete_index(self, index_name: str):
        if not self._can_admin:
            raise PermissionError(f"Role '{self.role}' cannot perform admin operations")
        return self.client.delete_index(index_name)

# Key rotation support
def rotate_api_key(old_key_env: str, new_key_env: str):
    """Rotate API key with validation."""
    old_key = os.environ.get(old_key_env)
    new_key = os.environ.get(new_key_env)

    if not new_key:
        raise EnvironmentError(f"New key not found: {new_key_env}")

    # Validate new key works
    try:
        test_client = Pinecone(api_key=new_key)
        test_client.list_indexes()  # Verify connectivity
    except Exception as e:
        raise ValueError(f"New API key validation failed: {e}")

    # Log rotation event (don't log actual keys)
    audit_log.info(
        "api_key_rotated",
        old_key_env=old_key_env,
        new_key_env=new_key_env
    )

    return True
```

**Don't**: Hardcode API keys, use single keys for all operations, or log credentials

```python
# VULNERABLE: Hardcoded API key
from pinecone import Pinecone
pc = Pinecone(api_key="pcsk_abc123xyz789")  # Exposed in source control

# VULNERABLE: Single shared key for all operations
PINECONE_KEY = os.environ["PINECONE_KEY"]  # Same key for query and admin

# VULNERABLE: Logging API key
def init_client():
    key = os.environ["PINECONE_API_KEY"]
    logger.info(f"Initializing Pinecone with key: {key}")  # Key in logs
    return Pinecone(api_key=key)

# VULNERABLE: Key in error messages
try:
    pc = Pinecone(api_key=api_key)
except Exception as e:
    raise Exception(f"Failed with key {api_key}: {e}")  # Key exposed
```

**Why**: Hardcoded keys are exposed through version control history, logs, and error messages. Single shared keys violate least privilege and make rotation difficult. Compromised query keys shouldn't allow data modification or deletion.

**Refs**: OWASP A07:2025 (Identification and Authentication Failures), CWE-798, CWE-522

---

## Rule: Namespace Isolation for Multi-Tenancy

**Level**: `strict`

**When**: Storing or querying vectors for multiple tenants in the same index

**Do**: Enforce namespace isolation at the server level with validation

```python
import re
from typing import Tuple
from pinecone import Pinecone

class TenantIsolatedIndex:
    """Pinecone index with mandatory namespace isolation."""

    def __init__(self, client: Pinecone, index_name: str):
        self.index = client.Index(index_name)
        self.index_name = index_name

    def _validate_tenant_id(self, tenant_id: str) -> str:
        """Validate and sanitize tenant ID."""
        if not tenant_id:
            raise ValueError("Tenant ID is required")

        # Strict format validation
        if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
            raise ValueError(
                "Invalid tenant_id format. "
                "Must be 1-64 alphanumeric characters, underscores, or hyphens."
            )

        return tenant_id

    def _validate_user_tenant_access(self, user_id: str, tenant_id: str) -> bool:
        """Verify user has access to tenant. Implement based on your auth system."""
        # Example: Check against auth service
        return auth_service.user_can_access_tenant(user_id, tenant_id)

    def upsert(self, tenant_id: str, vectors: list, user_id: str = None):
        """Upsert vectors with mandatory namespace isolation."""
        namespace = self._validate_tenant_id(tenant_id)

        # Optional: Verify user authorization
        if user_id and not self._validate_user_tenant_access(user_id, tenant_id):
            raise PermissionError(f"User {user_id} not authorized for tenant {tenant_id}")

        # Ensure tenant_id metadata matches namespace
        for vector in vectors:
            if "metadata" not in vector:
                vector["metadata"] = {}
            vector["metadata"]["tenant_id"] = tenant_id

        result = self.index.upsert(vectors=vectors, namespace=namespace)

        audit_log.info(
            "vectors_upserted",
            tenant_id=tenant_id,
            vector_count=len(vectors),
            user_id=user_id
        )

        return result

    def query(
        self,
        tenant_id: str,
        query_vector: list,
        top_k: int = 10,
        filter: dict = None,
        user_id: str = None,
        include_metadata: bool = True
    ):
        """Query with mandatory namespace isolation."""
        namespace = self._validate_tenant_id(tenant_id)

        # Verify user authorization
        if user_id and not self._validate_user_tenant_access(user_id, tenant_id):
            raise PermissionError(f"User {user_id} not authorized for tenant {tenant_id}")

        # Execute namespace-isolated query
        results = self.index.query(
            vector=query_vector,
            top_k=top_k,
            namespace=namespace,  # Server-enforced isolation
            filter=filter,
            include_metadata=include_metadata
        )

        # Defense in depth: Validate results belong to tenant
        validated_matches = []
        for match in results.matches:
            if match.metadata and match.metadata.get("tenant_id") != tenant_id:
                audit_log.error(
                    "cross_tenant_leak_detected",
                    expected_tenant=tenant_id,
                    actual_tenant=match.metadata.get("tenant_id"),
                    vector_id=match.id
                )
                continue
            validated_matches.append(match)

        results.matches = validated_matches

        audit_log.info(
            "vectors_queried",
            tenant_id=tenant_id,
            result_count=len(validated_matches),
            user_id=user_id
        )

        return results

    def delete(self, tenant_id: str, ids: list = None, delete_all: bool = False):
        """Delete vectors with namespace isolation."""
        namespace = self._validate_tenant_id(tenant_id)

        if delete_all:
            result = self.index.delete(delete_all=True, namespace=namespace)
        else:
            result = self.index.delete(ids=ids, namespace=namespace)

        audit_log.info(
            "vectors_deleted",
            tenant_id=tenant_id,
            delete_all=delete_all,
            ids_count=len(ids) if ids else 0
        )

        return result

# Usage example
client = SecurePineconeClient(role="index")
isolated_index = TenantIsolatedIndex(client.client, "my-index")

# Upsert with tenant isolation
isolated_index.upsert(
    tenant_id="tenant_123",
    vectors=[
        {"id": "vec1", "values": [0.1] * 1536, "metadata": {"content": "doc1"}}
    ],
    user_id="user_456"
)

# Query with tenant isolation
results = isolated_index.query(
    tenant_id="tenant_123",
    query_vector=[0.1] * 1536,
    top_k=5,
    user_id="user_456"
)
```

**Don't**: Query without namespace, rely solely on metadata filters, or trust user-provided tenant IDs without validation

```python
# VULNERABLE: No namespace isolation
def query_vectors(index, tenant_id, query_vector):
    return index.query(
        vector=query_vector,
        top_k=10,
        filter={"tenant_id": tenant_id}  # Only filter, no namespace
    )

# VULNERABLE: User controls namespace directly
def query_vectors(index, request):
    return index.query(
        vector=request["vector"],
        namespace=request["tenant_id"]  # No validation or authorization
    )

# VULNERABLE: Missing namespace in upsert
def upsert_vectors(index, vectors):
    return index.upsert(vectors=vectors)  # Goes to default namespace
```

**Why**: Without namespace isolation, metadata filters can be bypassed or misconfigured, allowing cross-tenant data access. Namespaces provide server-enforced isolation that cannot be circumvented by query manipulation. Defense in depth with result validation catches misconfigurations.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Metadata Filter Injection Prevention

**Level**: `strict`

**When**: Constructing Pinecone queries with user-provided filter values

**Do**: Validate filter fields against allowlist, sanitize values, and restrict operators

```python
from typing import Any

# Allowlisted filter configuration
ALLOWED_FILTER_FIELDS = {
    "category",
    "status",
    "date_created",
    "source",
    "document_type",
    "visibility"
}

ALLOWED_OPERATORS = {
    "$eq",
    "$ne",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$in",
    "$nin"
}

MAX_LIST_SIZE = 100
MAX_STRING_LENGTH = 1000

class SecureFilterBuilder:
    """Build Pinecone filters with validation and sanitization."""

    @staticmethod
    def sanitize_value(value: Any) -> Any:
        """Sanitize individual filter values."""
        if isinstance(value, str):
            if len(value) > MAX_STRING_LENGTH:
                raise ValueError(f"String value exceeds {MAX_STRING_LENGTH} characters")
            # Remove control characters
            return ''.join(char for char in value if char.isprintable())

        elif isinstance(value, bool):
            return value

        elif isinstance(value, (int, float)):
            # Prevent overflow attacks
            if abs(value) > 1e15:
                raise ValueError("Numeric value out of range")
            return value

        elif isinstance(value, list):
            if len(value) > MAX_LIST_SIZE:
                raise ValueError(f"List exceeds {MAX_LIST_SIZE} items")
            return [SecureFilterBuilder.sanitize_value(v) for v in value]

        else:
            raise ValueError(f"Unsupported value type: {type(value)}")

    @staticmethod
    def build_filter(user_filters: dict, tenant_id: str = None) -> dict:
        """Build secure filter from user input."""
        safe_filter = {}

        for field, condition in user_filters.items():
            # Validate field name
            if field not in ALLOWED_FILTER_FIELDS:
                raise ValueError(f"Filter field not allowed: {field}")

            # Process condition
            if isinstance(condition, dict):
                # Operator-based condition
                safe_condition = {}
                for op, value in condition.items():
                    if op not in ALLOWED_OPERATORS:
                        raise ValueError(f"Operator not allowed: {op}")
                    safe_condition[op] = SecureFilterBuilder.sanitize_value(value)
                safe_filter[field] = safe_condition
            else:
                # Simple equality
                safe_filter[field] = {
                    "$eq": SecureFilterBuilder.sanitize_value(condition)
                }

        # Add mandatory tenant filter if provided
        if tenant_id:
            safe_filter["tenant_id"] = {"$eq": tenant_id}

        return safe_filter

    @staticmethod
    def build_combined_filter(
        user_filters: dict,
        tenant_id: str,
        additional_filters: dict = None
    ) -> dict:
        """Build filter with mandatory constraints that cannot be overridden."""
        # Build user filter
        user_safe = SecureFilterBuilder.build_filter(user_filters)

        # Remove any attempt to override tenant_id
        user_safe.pop("tenant_id", None)

        # Mandatory filters
        mandatory = {"tenant_id": {"$eq": tenant_id}}

        if additional_filters:
            mandatory.update(additional_filters)

        # Combine with $and to ensure all conditions apply
        if user_safe:
            return {"$and": [mandatory, user_safe]}
        return mandatory

# Usage in query
def secure_query(
    index,
    tenant_id: str,
    query_vector: list,
    user_filters: dict = None,
    top_k: int = 10
):
    """Execute query with secure filter construction."""

    # Build secure filter
    safe_filter = SecureFilterBuilder.build_combined_filter(
        user_filters=user_filters or {},
        tenant_id=tenant_id
    )

    return index.query(
        vector=query_vector,
        top_k=top_k,
        namespace=tenant_id,
        filter=safe_filter,
        include_metadata=True
    )

# Example usage
results = secure_query(
    index=pinecone_index,
    tenant_id="tenant_123",
    query_vector=[0.1] * 1536,
    user_filters={
        "category": "documents",
        "date_created": {"$gte": "2024-01-01"},
        "status": {"$in": ["active", "pending"]}
    }
)
```

**Don't**: Pass user input directly to filters, allow arbitrary field names, or construct filters with string interpolation

```python
# VULNERABLE: Direct user input in filter
def query_vectors(index, query_vector, user_filter):
    return index.query(
        vector=query_vector,
        filter=user_filter  # User controls entire filter
    )

# VULNERABLE: No field validation
def build_filter(user_input):
    return {k: v for k, v in user_input.items()}  # Any field allowed

# VULNERABLE: String interpolation
def build_filter(field, value):
    return {field: value}  # Attacker can inject any field name

# VULNERABLE: No operator validation
def build_filter(user_filters):
    safe = {}
    for field, condition in user_filters.items():
        if field in ALLOWED_FIELDS:
            safe[field] = condition  # Operators not validated
    return safe
```

**Why**: Unvalidated filters allow attackers to query fields they shouldn't access (e.g., `tenant_id`, `internal_score`), use operators that bypass restrictions, or cause denial of service through expensive filter operations. Field allowlisting and operator validation prevent these attacks.

**Refs**: OWASP A03:2025 (Injection), CWE-943, CWE-20

---

## Rule: Serverless Configuration Security

**Level**: `strict`

**When**: Creating or configuring Pinecone serverless indexes

**Do**: Select appropriate regions for data residency, set capacity limits, and configure deletion protection

```python
from pinecone import Pinecone, ServerlessSpec

def create_secure_serverless_index(
    client: Pinecone,
    index_name: str,
    dimension: int,
    region: str,
    deletion_protection: str = "enabled",
    max_read_units: int = 100,
    max_write_units: int = 50
):
    """Create serverless index with security best practices."""

    # Validate region for data residency compliance
    APPROVED_REGIONS = {
        "us": ["us-east-1", "us-west-2"],
        "eu": ["eu-west-1"],
        "ap": ["ap-southeast-1"]
    }

    # Determine region category
    region_category = region.split("-")[0]
    if region not in APPROVED_REGIONS.get(region_category, []):
        raise ValueError(
            f"Region {region} not approved. "
            f"Approved regions: {APPROVED_REGIONS}"
        )

    # Validate index name
    if not re.match(r'^[a-z0-9-]{1,45}$', index_name):
        raise ValueError("Invalid index name format")

    # Create index with security configuration
    client.create_index(
        name=index_name,
        dimension=dimension,
        metric="cosine",
        spec=ServerlessSpec(
            cloud="aws",
            region=region
        ),
        deletion_protection=deletion_protection  # Prevent accidental deletion
    )

    audit_log.info(
        "serverless_index_created",
        index_name=index_name,
        region=region,
        deletion_protection=deletion_protection,
        dimension=dimension
    )

    return client.Index(index_name)

def configure_index_capacity_alerts(index_name: str, thresholds: dict):
    """Configure monitoring and alerts for capacity limits."""
    # Implement based on your monitoring system
    # This is a placeholder for alerting configuration

    alert_config = {
        "index_name": index_name,
        "alerts": [
            {
                "metric": "read_units",
                "threshold": thresholds.get("max_read_units", 100),
                "action": "notify_ops"
            },
            {
                "metric": "write_units",
                "threshold": thresholds.get("max_write_units", 50),
                "action": "notify_ops"
            },
            {
                "metric": "vector_count",
                "threshold": thresholds.get("max_vectors", 1000000),
                "action": "notify_ops"
            }
        ]
    }

    # Register alerts with monitoring system
    monitoring_service.register_alerts(alert_config)

    return alert_config

def validate_data_residency(index_name: str, required_region: str) -> bool:
    """Validate index is in required region for compliance."""
    index_info = pc.describe_index(index_name)

    actual_region = index_info.spec.serverless.region

    if actual_region != required_region:
        audit_log.error(
            "data_residency_violation",
            index_name=index_name,
            required_region=required_region,
            actual_region=actual_region
        )
        return False

    return True
```

**Don't**: Use default regions without consideration, disable deletion protection in production, or ignore capacity limits

```python
# VULNERABLE: No region consideration for data residency
client.create_index(
    name="my-index",
    dimension=1536,
    spec=ServerlessSpec(
        cloud="aws",
        region="us-east-1"  # May violate EU data residency requirements
    )
)

# VULNERABLE: Deletion protection disabled in production
client.create_index(
    name="production-index",
    dimension=1536,
    spec=ServerlessSpec(cloud="aws", region="us-east-1"),
    deletion_protection="disabled"  # Risk of accidental deletion
)

# VULNERABLE: No capacity monitoring
# Index created without alerts - potential cost overruns undetected
```

**Why**: Incorrect region selection violates data residency requirements (GDPR, etc.). Disabled deletion protection risks catastrophic data loss from accidents or attacks. Without capacity limits and monitoring, costs can spiral or service can be degraded by abuse.

**Refs**: OWASP A05:2025 (Security Misconfiguration), GDPR Article 44-49, CWE-1188

---

## Rule: Hybrid Search Security

**Level**: `warning`

**When**: Using Pinecone's hybrid search with sparse-dense vectors

**Do**: Validate both sparse and dense scores, implement score bounds, and prevent score manipulation

```python
from pinecone import Pinecone, SparseValues

class SecureHybridSearch:
    """Secure hybrid search with score validation."""

    def __init__(self, index, alpha: float = 0.5):
        self.index = index
        self.alpha = alpha  # Balance between dense and sparse

        # Score bounds for validation
        self.min_score = 0.0
        self.max_score = 1.0
        self.min_sparse_score = 0.0
        self.max_sparse_score = 100.0  # BM25 scores can be higher

    def validate_sparse_vector(self, sparse: dict) -> SparseValues:
        """Validate sparse vector format and values."""
        if not sparse:
            return None

        indices = sparse.get("indices", [])
        values = sparse.get("values", [])

        # Validate lengths match
        if len(indices) != len(values):
            raise ValueError("Sparse indices and values must have same length")

        # Validate indices are non-negative integers
        for idx in indices:
            if not isinstance(idx, int) or idx < 0:
                raise ValueError(f"Invalid sparse index: {idx}")

        # Validate values are reasonable
        for val in values:
            if not isinstance(val, (int, float)):
                raise ValueError(f"Invalid sparse value type: {type(val)}")
            if abs(val) > 1000:  # Reasonable bound
                raise ValueError(f"Sparse value out of bounds: {val}")

        return SparseValues(indices=indices, values=values)

    def query(
        self,
        dense_vector: list,
        sparse_vector: dict = None,
        top_k: int = 10,
        namespace: str = None,
        filter: dict = None
    ):
        """Execute hybrid search with score validation."""

        # Validate sparse vector if provided
        sparse = self.validate_sparse_vector(sparse_vector)

        # Execute query
        results = self.index.query(
            vector=dense_vector,
            sparse_vector=sparse,
            top_k=top_k,
            namespace=namespace,
            filter=filter,
            include_metadata=True
        )

        # Validate and normalize scores
        validated_matches = []
        for match in results.matches:
            score = match.score

            # Check for anomalous scores
            if score < self.min_score or score > self.max_score:
                audit_log.warning(
                    "anomalous_score_detected",
                    vector_id=match.id,
                    score=score,
                    namespace=namespace
                )
                # Optionally skip or flag result
                match.metadata["_score_anomaly"] = True

            validated_matches.append(match)

        results.matches = validated_matches
        return results

    def rerank_results(self, results, sparse_weight: float = None):
        """Re-rank results with controlled weighting."""
        alpha = sparse_weight if sparse_weight is not None else self.alpha

        # Validate alpha bounds
        if not 0.0 <= alpha <= 1.0:
            raise ValueError("Alpha must be between 0 and 1")

        # Apply controlled re-ranking
        for match in results.matches:
            # If both scores available, compute weighted score
            dense_score = match.score  # Already combined by Pinecone
            # Custom re-ranking logic can be applied here

        return results

# Usage
secure_hybrid = SecureHybridSearch(index, alpha=0.5)

results = secure_hybrid.query(
    dense_vector=[0.1] * 1536,
    sparse_vector={
        "indices": [0, 5, 10],
        "values": [0.5, 0.3, 0.2]
    },
    top_k=10,
    namespace="tenant_123"
)
```

**Don't**: Trust unbounded scores, allow arbitrary sparse vector manipulation, or skip score validation

```python
# VULNERABLE: No score validation
def hybrid_query(index, dense, sparse, top_k):
    results = index.query(
        vector=dense,
        sparse_vector=SparseValues(**sparse),
        top_k=top_k
    )
    return results  # Scores not validated

# VULNERABLE: User controls sparse weights directly
def query_with_weights(index, dense, sparse_indices, sparse_values):
    return index.query(
        vector=dense,
        sparse_vector=SparseValues(
            indices=sparse_indices,  # User can inject any indices
            values=sparse_values     # User can set extreme values
        )
    )

# VULNERABLE: No bounds on sparse values
sparse = SparseValues(
    indices=[0, 1, 2],
    values=[1000000, -1000000, float('inf')]  # Extreme values
)
```

**Why**: Manipulated sparse vectors can artificially boost or suppress results, enabling data exfiltration or poisoning search quality. Score anomalies may indicate attacks or data corruption. Bounded validation prevents manipulation while maintaining functionality.

**Refs**: MITRE ATLAS ML03 (Data Poisoning), CWE-20, CWE-129

---

## Rule: Index Operations Security

**Level**: `warning`

**When**: Performing administrative operations on Pinecone indexes (backup, delete, configure)

**Do**: Implement deletion protection, validate backups before restore, and maintain audit trails

```python
from datetime import datetime
from pinecone import Pinecone

class SecureIndexOperations:
    """Secure administrative operations for Pinecone indexes."""

    def __init__(self, client: Pinecone, audit_logger):
        self.client = client
        self.audit = audit_logger

    def create_collection_backup(self, index_name: str, collection_name: str):
        """Create a collection (backup) from index with validation."""

        # Validate index exists
        if index_name not in [idx.name for idx in self.client.list_indexes()]:
            raise ValueError(f"Index not found: {index_name}")

        # Validate collection name format
        if not re.match(r'^[a-z0-9-]{1,45}$', collection_name):
            raise ValueError("Invalid collection name format")

        # Get index stats for verification
        index = self.client.Index(index_name)
        stats_before = index.describe_index_stats()

        # Create collection
        self.client.create_collection(
            name=collection_name,
            source=index_name
        )

        # Log backup event
        self.audit.info(
            "index_backup_created",
            index_name=index_name,
            collection_name=collection_name,
            vector_count=stats_before.total_vector_count,
            namespaces=list(stats_before.namespaces.keys()),
            timestamp=datetime.utcnow().isoformat()
        )

        return {
            "collection_name": collection_name,
            "source_index": index_name,
            "vector_count": stats_before.total_vector_count
        }

    def restore_from_collection(
        self,
        collection_name: str,
        new_index_name: str,
        dimension: int,
        deletion_protection: str = "enabled"
    ):
        """Restore index from collection with validation."""

        # Validate collection exists
        collections = [c.name for c in self.client.list_collections()]
        if collection_name not in collections:
            raise ValueError(f"Collection not found: {collection_name}")

        # Get collection info for validation
        collection_info = self.client.describe_collection(collection_name)

        # Validate dimension matches
        if collection_info.dimension != dimension:
            raise ValueError(
                f"Dimension mismatch: collection={collection_info.dimension}, "
                f"requested={dimension}"
            )

        # Create index from collection
        self.client.create_index(
            name=new_index_name,
            dimension=dimension,
            metric="cosine",
            spec=ServerlessSpec(
                cloud="aws",
                region=collection_info.environment
            ),
            deletion_protection=deletion_protection
        )

        self.audit.info(
            "index_restored_from_collection",
            collection_name=collection_name,
            new_index_name=new_index_name,
            dimension=dimension
        )

        return new_index_name

    def safe_delete_index(
        self,
        index_name: str,
        require_backup: bool = True,
        confirm_string: str = None
    ):
        """Safely delete index with multiple safeguards."""

        # Require explicit confirmation
        expected_confirm = f"DELETE-{index_name}"
        if confirm_string != expected_confirm:
            raise ValueError(
                f"Deletion not confirmed. "
                f"Pass confirm_string='{expected_confirm}'"
            )

        # Check deletion protection
        index_info = self.client.describe_index(index_name)
        if index_info.deletion_protection == "enabled":
            raise PermissionError(
                f"Index {index_name} has deletion protection enabled. "
                "Disable it first if deletion is intended."
            )

        # Require backup before deletion
        if require_backup:
            backup_name = f"{index_name}-backup-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            self.create_collection_backup(index_name, backup_name)

        # Perform deletion
        self.client.delete_index(index_name)

        self.audit.warning(
            "index_deleted",
            index_name=index_name,
            backup_created=require_backup,
            timestamp=datetime.utcnow().isoformat()
        )

        return True

    def configure_deletion_protection(self, index_name: str, enabled: bool):
        """Configure deletion protection with audit trail."""

        current = self.client.describe_index(index_name)
        new_state = "enabled" if enabled else "disabled"

        if current.deletion_protection == new_state:
            return  # No change needed

        self.client.configure_index(
            name=index_name,
            deletion_protection=new_state
        )

        self.audit.info(
            "deletion_protection_changed",
            index_name=index_name,
            previous_state=current.deletion_protection,
            new_state=new_state
        )

# Usage
ops = SecureIndexOperations(pc, audit_log)

# Create backup
backup_info = ops.create_collection_backup(
    index_name="production-index",
    collection_name="prod-backup-20240115"
)

# Safe deletion with safeguards
ops.safe_delete_index(
    index_name="old-index",
    require_backup=True,
    confirm_string="DELETE-old-index"
)
```

**Don't**: Delete indexes without backups, disable deletion protection without audit, or skip validation on restore

```python
# VULNERABLE: Delete without backup
client.delete_index("production-index")  # No backup, no confirmation

# VULNERABLE: Disable protection without audit
client.configure_index(
    name="production-index",
    deletion_protection="disabled"
)  # No logging of this critical change

# VULNERABLE: Restore without validation
client.create_index(
    name="restored-index",
    source_collection="unknown-collection"  # No validation
)
```

**Why**: Accidental or malicious deletion of production indexes causes data loss. Without backups, recovery may be impossible. Deletion protection provides a safety net, and audit trails enable accountability and forensics for administrative actions.

**Refs**: OWASP A05:2025 (Security Misconfiguration), CWE-1188, CWE-778

---

## Rule: Query Result Validation

**Level**: `warning`

**When**: Processing query results before returning to users

**Do**: Validate score bounds, filter sensitive metadata, and implement result limits

```python
from typing import List, Dict, Any

class SecureResultProcessor:
    """Process and validate Pinecone query results."""

    def __init__(self, config: dict = None):
        config = config or {}

        # Score thresholds
        self.min_score_threshold = config.get("min_score", 0.0)
        self.max_score_threshold = config.get("max_score", 1.0)
        self.relevance_threshold = config.get("relevance_threshold", 0.5)

        # Metadata fields to redact from responses
        self.redacted_fields = config.get("redacted_fields", {
            "tenant_id",
            "owner_id",
            "internal_score",
            "pii_hash",
            "source_ip"
        })

        # Fields allowed in response
        self.allowed_response_fields = config.get("allowed_fields", {
            "content_preview",
            "category",
            "date_created",
            "source",
            "document_type"
        })

    def process_results(
        self,
        results,
        tenant_id: str,
        max_results: int = None,
        min_relevance: float = None
    ) -> List[Dict[str, Any]]:
        """Process results with validation and filtering."""

        processed = []
        relevance_threshold = min_relevance or self.relevance_threshold

        for match in results.matches:
            # Validate score bounds
            if not self._validate_score(match.score):
                audit_log.warning(
                    "invalid_score_filtered",
                    vector_id=match.id,
                    score=match.score
                )
                continue

            # Filter by relevance threshold
            if match.score < relevance_threshold:
                continue

            # Validate tenant ownership
            if match.metadata.get("tenant_id") != tenant_id:
                audit_log.error(
                    "cross_tenant_result_filtered",
                    vector_id=match.id,
                    expected_tenant=tenant_id,
                    actual_tenant=match.metadata.get("tenant_id")
                )
                continue

            # Redact sensitive metadata
            safe_metadata = self._redact_metadata(match.metadata)

            processed.append({
                "id": match.id,
                "score": round(match.score, 4),
                "metadata": safe_metadata
            })

        # Apply result limit
        if max_results:
            processed = processed[:max_results]

        return processed

    def _validate_score(self, score: float) -> bool:
        """Validate score is within expected bounds."""
        if score is None:
            return False

        return self.min_score_threshold <= score <= self.max_score_threshold

    def _redact_metadata(self, metadata: dict) -> dict:
        """Remove sensitive fields from metadata."""
        if not metadata:
            return {}

        # Only include allowed fields
        return {
            k: v for k, v in metadata.items()
            if k in self.allowed_response_fields
        }

    def validate_result_integrity(self, results, expected_count: int = None):
        """Validate overall result integrity."""

        actual_count = len(results.matches)

        # Check for suspicious patterns
        if actual_count == 0:
            audit_log.info("empty_results_returned")
            return True

        # Check score distribution
        scores = [m.score for m in results.matches]
        avg_score = sum(scores) / len(scores)

        # Flag if all scores are identical (potential issue)
        if len(set(scores)) == 1 and actual_count > 1:
            audit_log.warning(
                "uniform_scores_detected",
                score=scores[0],
                count=actual_count
            )

        # Flag unusually high average score
        if avg_score > 0.99:
            audit_log.warning(
                "unusually_high_scores",
                avg_score=avg_score,
                count=actual_count
            )

        return True

# Usage with provenance metadata
def upsert_with_provenance(
    index,
    tenant_id: str,
    vectors: list,
    owner_id: str,
    source_system: str
):
    """Upsert vectors with complete provenance tracking."""

    from datetime import datetime
    from uuid import uuid4
    import hashlib

    prepared_vectors = []

    for vec in vectors:
        content = vec.get("metadata", {}).get("content", "")

        prepared_vectors.append({
            "id": vec.get("id", str(uuid4())),
            "values": vec["values"],
            "metadata": {
                # Provenance fields
                "tenant_id": tenant_id,
                "owner_id": owner_id,
                "source_system": source_system,
                "upload_timestamp": datetime.utcnow().isoformat(),
                "content_hash": hashlib.sha256(content.encode()).hexdigest(),

                # User metadata
                **vec.get("metadata", {})
            }
        })

    result = index.upsert(
        vectors=prepared_vectors,
        namespace=tenant_id
    )

    audit_log.info(
        "vectors_upserted_with_provenance",
        tenant_id=tenant_id,
        owner_id=owner_id,
        count=len(prepared_vectors)
    )

    return result

# Complete secure query flow
def secure_query_with_validation(
    index,
    tenant_id: str,
    user_id: str,
    query_vector: list,
    filters: dict = None,
    top_k: int = 10
):
    """Complete secure query with all validations."""

    # Build secure filter
    safe_filter = SecureFilterBuilder.build_combined_filter(
        user_filters=filters or {},
        tenant_id=tenant_id
    )

    # Execute query
    results = index.query(
        vector=query_vector,
        top_k=top_k,
        namespace=tenant_id,
        filter=safe_filter,
        include_metadata=True
    )

    # Process and validate results
    processor = SecureResultProcessor()
    validated = processor.process_results(
        results=results,
        tenant_id=tenant_id,
        min_relevance=0.5
    )

    # Audit the query
    audit_log.info(
        "secure_query_executed",
        tenant_id=tenant_id,
        user_id=user_id,
        result_count=len(validated)
    )

    return validated
```

**Don't**: Return raw results without validation, expose internal metadata, or skip score checking

```python
# VULNERABLE: Return raw results
def query_vectors(index, query_vector):
    results = index.query(vector=query_vector, top_k=10)
    return results  # No validation, raw data exposed

# VULNERABLE: Expose all metadata
def process_results(results):
    return [
        {
            "id": m.id,
            "score": m.score,
            "metadata": m.metadata  # Includes tenant_id, owner_id, etc.
        }
        for m in results.matches
    ]

# VULNERABLE: No score validation
def filter_results(results):
    return [m for m in results.matches]  # Accepts any score
```

**Why**: Raw results may contain sensitive metadata (tenant IDs, internal scores). Anomalous scores indicate potential attacks or data corruption. Result validation provides defense in depth against data leakage and ensures only relevant, authorized data reaches users.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-200, CWE-209

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 Pinecone-specific security rules |

---

## Additional Resources

- [Pinecone Security Documentation](https://docs.pinecone.io/docs/security)
- [Pinecone API Key Management](https://docs.pinecone.io/docs/authentication)
- [Pinecone Namespaces](https://docs.pinecone.io/docs/namespaces)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
- Core vector store security: `rules/rag/_core/vector-store-security.md`
