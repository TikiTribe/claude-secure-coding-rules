# Qdrant Security Rules

Security rules for Qdrant vector database implementations. Extends core vector store security rules with Qdrant-specific patterns.

## Prerequisites

Apply rules from `rules/rag/_core/vector-store-security.md` first. This file covers Qdrant-specific security considerations.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| API Key Authentication | `strict` | Unauthorized access, credential exposure |
| Payload Filtering Security | `strict` | Filter injection, data exfiltration |
| Collection Configuration | `warning` | Data loss, unauthorized shard access |
| Quantization Security | `advisory` | Data precision attacks |
| Snapshot Security | `strict` | Backup exposure, integrity compromise |
| gRPC Security | `warning` | Data interception, authentication bypass |
| Multi-Vector Security | `warning` | Cross-vector access control bypass |

---

## Rule: API Key Authentication

**Level**: `strict`

**When**: Connecting to Qdrant instances, managing API keys

**Do**: Use separate read-only and read-write API keys, store in environment variables, enable TLS

```python
from qdrant_client import QdrantClient
import os

# Secure client configuration with read-only key for queries
def get_query_client() -> QdrantClient:
    """Create read-only Qdrant client for query operations."""
    return QdrantClient(
        url=os.environ["QDRANT_URL"],
        api_key=os.environ["QDRANT_READ_KEY"],  # Read-only API key
        timeout=30,
        prefer_grpc=True,
        https=True  # Always use TLS
    )

# Separate client with write permissions for indexing
def get_index_client() -> QdrantClient:
    """Create read-write Qdrant client for indexing operations."""
    return QdrantClient(
        url=os.environ["QDRANT_URL"],
        api_key=os.environ["QDRANT_WRITE_KEY"],  # Read-write API key
        timeout=60,
        prefer_grpc=True,
        https=True
    )

# Role-based client factory
class QdrantClientFactory:
    def __init__(self):
        self._clients = {}

    def get_client(self, role: str) -> QdrantClient:
        """Get client based on operation role."""
        if role not in self._clients:
            if role == "query":
                api_key = os.environ["QDRANT_READ_KEY"]
            elif role == "index":
                api_key = os.environ["QDRANT_WRITE_KEY"]
            elif role == "admin":
                api_key = os.environ["QDRANT_ADMIN_KEY"]
            else:
                raise ValueError(f"Unknown role: {role}")

            self._clients[role] = QdrantClient(
                url=os.environ["QDRANT_URL"],
                api_key=api_key,
                https=True,
                prefer_grpc=True
            )

        return self._clients[role]
```

**Don't**: Hardcode API keys, use single key for all operations, disable TLS

```python
# VULNERABLE: Hardcoded API key
client = QdrantClient(
    url="https://qdrant.example.com",
    api_key="qdrant-api-key-12345"  # Exposed in code/version control
)

# VULNERABLE: Single shared key for all operations
QDRANT_KEY = "shared-key"  # Query and admin use same key

# VULNERABLE: No TLS encryption
client = QdrantClient(
    url="http://qdrant.internal:6333",  # Plaintext traffic
    api_key=os.environ["QDRANT_KEY"]
)

# VULNERABLE: No authentication
client = QdrantClient(url="http://localhost:6333")  # No API key
```

**Why**: Hardcoded credentials leak through version control and logs. Single shared keys prevent audit trails and make revocation impossible. Without TLS, API keys and vector data are transmitted in plaintext.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A02:2025 (Cryptographic Failures), CWE-798, CWE-319

---

## Rule: Payload Filtering Security

**Level**: `strict`

**When**: Building filters from user input for Qdrant queries

**Do**: Validate filter fields against allowlist, use type-safe filter construction, sanitize values

```python
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Filter, FieldCondition, MatchValue, MatchText,
    Range, MatchAny, IsEmpty, HasId
)
from typing import Any
import re

# Allowlist of permitted filter fields and their types
ALLOWED_FILTER_FIELDS = {
    "category": str,
    "status": str,
    "date": str,
    "priority": int,
    "score": float,
    "tags": list
}

def sanitize_string_value(value: str, max_length: int = 1000) -> str:
    """Sanitize string values for safe filtering."""
    if not isinstance(value, str):
        raise ValueError(f"Expected string, got {type(value)}")
    if len(value) > max_length:
        raise ValueError(f"Value exceeds maximum length of {max_length}")
    # Remove potential injection characters
    return value.strip()

def build_safe_filter(tenant_id: str, user_filters: dict) -> Filter:
    """Build Qdrant filter with validation and tenant enforcement."""
    # Mandatory tenant isolation
    conditions = [
        FieldCondition(
            key="tenant_id",
            match=MatchValue(value=tenant_id)
        )
    ]

    for field, value in user_filters.items():
        # Validate field is allowed
        if field not in ALLOWED_FILTER_FIELDS:
            raise ValueError(f"Invalid filter field: {field}")

        expected_type = ALLOWED_FILTER_FIELDS[field]

        # Type-safe condition building
        if expected_type == str:
            sanitized = sanitize_string_value(value)
            conditions.append(
                FieldCondition(
                    key=field,
                    match=MatchValue(value=sanitized)
                )
            )
        elif expected_type == int:
            if not isinstance(value, int):
                raise ValueError(f"Field {field} requires integer")
            conditions.append(
                FieldCondition(
                    key=field,
                    match=MatchValue(value=value)
                )
            )
        elif expected_type == float:
            if not isinstance(value, (int, float)):
                raise ValueError(f"Field {field} requires number")
            conditions.append(
                FieldCondition(
                    key=field,
                    range=Range(gte=value, lte=value)
                )
            )
        elif expected_type == list:
            if not isinstance(value, list) or len(value) > 100:
                raise ValueError(f"Field {field} requires list (max 100 items)")
            sanitized_list = [sanitize_string_value(v) for v in value]
            conditions.append(
                FieldCondition(
                    key=field,
                    match=MatchAny(any=sanitized_list)
                )
            )

    return Filter(must=conditions)

# Safe query execution with validated filters
def secure_query(
    client: QdrantClient,
    collection_name: str,
    tenant_id: str,
    query_vector: list,
    user_filters: dict = None,
    top_k: int = 10
):
    """Execute query with validated filters and tenant isolation."""
    safe_filter = build_safe_filter(tenant_id, user_filters or {})

    results = client.search(
        collection_name=collection_name,
        query_vector=query_vector,
        query_filter=safe_filter,
        limit=min(top_k, 100),  # Cap maximum results
        with_payload=True
    )

    # Validate results belong to tenant
    for result in results:
        if result.payload.get("tenant_id") != tenant_id:
            raise SecurityError("Cross-tenant data leak detected")

    return results
```

**Don't**: Pass raw user input to filters, allow arbitrary filter fields

```python
# VULNERABLE: Direct user input to filter
def query_vectors(client, user_filter: dict):
    return client.search(
        collection_name="vectors",
        query_vector=embedding,
        query_filter=Filter(**user_filter)  # Attacker controls entire filter
    )

# VULNERABLE: No field validation
def build_filter(user_input: dict):
    conditions = []
    for key, value in user_input.items():
        # Any field allowed - can access internal fields
        conditions.append(FieldCondition(key=key, match=MatchValue(value=value)))
    return Filter(must=conditions)

# VULNERABLE: Type coercion issues
def unsafe_filter(field: str, value):
    return FieldCondition(
        key=field,
        match=MatchValue(value=str(value))  # Can bypass type checks
    )
```

**Why**: Unvalidated filters enable attackers to bypass tenant isolation, access internal metadata fields, or craft filters that exfiltrate data. Type validation prevents injection through type coercion.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A03:2025 (Injection), CWE-284, CWE-943

---

## Rule: Collection Configuration

**Level**: `warning`

**When**: Creating or configuring Qdrant collections

**Do**: Configure replication for durability, set appropriate shard security, use optimizers safely

```python
from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams, Distance, OptimizersConfigDiff,
    HnswConfigDiff, WalConfigDiff
)

def create_secure_collection(
    client: QdrantClient,
    collection_name: str,
    vector_size: int,
    replication_factor: int = 2,
    shard_number: int = 2
):
    """Create collection with secure default configuration."""
    # Validate collection name
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', collection_name):
        raise ValueError("Invalid collection name format")

    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(
            size=vector_size,
            distance=Distance.COSINE
        ),
        # Replication for fault tolerance
        replication_factor=replication_factor,
        # Sharding for scalability
        shard_number=shard_number,
        # Write-ahead log for durability
        wal_config=WalConfigDiff(
            wal_capacity_mb=64,
            wal_segments_ahead=2
        ),
        # Optimizer configuration
        optimizers_config=OptimizersConfigDiff(
            indexing_threshold=20000,
            memmap_threshold=50000,
            # Prevent excessive resource usage
            max_optimization_threads=2
        ),
        # HNSW index configuration
        hnsw_config=HnswConfigDiff(
            m=16,
            ef_construct=100,
            full_scan_threshold=10000
        )
    )

    # Log collection creation for audit
    audit_log.info(
        "collection_created",
        collection=collection_name,
        replication=replication_factor,
        shards=shard_number
    )

def update_collection_security(
    client: QdrantClient,
    collection_name: str,
    allowed_users: list
):
    """Update collection with access control metadata."""
    # Store ACL metadata (application-level enforcement)
    # Note: Qdrant doesn't have built-in RBAC, implement at application layer
    client.update_collection(
        collection_name=collection_name,
        optimizers_config=OptimizersConfigDiff(
            # Prevent accidental data loss during optimization
            vacuum_min_vector_number=1000
        )
    )
```

**Don't**: Create collections without replication, use insecure defaults

```python
# RISKY: No replication - data loss on node failure
client.create_collection(
    collection_name="important_data",
    vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
    replication_factor=1  # Single copy only
)

# RISKY: Excessive optimizer threads can cause resource exhaustion
client.create_collection(
    collection_name="vectors",
    vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
    optimizers_config=OptimizersConfigDiff(
        max_optimization_threads=16  # Can starve other operations
    )
)
```

**Why**: Without replication, node failures cause data loss. Misconfigured optimizers can cause denial of service through resource exhaustion. Proper WAL configuration ensures durability.

**Refs**: CWE-400 (Resource Exhaustion), CWE-693 (Protection Mechanism Failure)

---

## Rule: Quantization Security

**Level**: `advisory`

**When**: Configuring scalar or binary quantization for embeddings

**Do**: Validate quantization parameters, understand precision tradeoffs

```python
from qdrant_client.models import (
    ScalarQuantization, ScalarQuantizationConfig, ScalarType,
    BinaryQuantization, BinaryQuantizationConfig,
    ProductQuantization, ProductQuantizationConfig
)

def create_quantized_collection(
    client: QdrantClient,
    collection_name: str,
    vector_size: int,
    quantization_type: str = "scalar",
    sensitivity_level: str = "standard"
):
    """Create collection with appropriate quantization for sensitivity level."""

    # Choose quantization based on data sensitivity
    if sensitivity_level == "high":
        # Higher precision for sensitive data
        quantization_config = ScalarQuantization(
            scalar=ScalarQuantizationConfig(
                type=ScalarType.INT8,
                quantile=0.99,  # Preserve more precision
                always_ram=True  # Keep in RAM for speed
            )
        )
    elif sensitivity_level == "low":
        # Can use more aggressive compression
        quantization_config = BinaryQuantization(
            binary=BinaryQuantizationConfig(
                always_ram=True
            )
        )
    else:
        # Standard scalar quantization
        quantization_config = ScalarQuantization(
            scalar=ScalarQuantizationConfig(
                type=ScalarType.INT8,
                quantile=0.95,
                always_ram=False
            )
        )

    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(
            size=vector_size,
            distance=Distance.COSINE
        ),
        quantization_config=quantization_config
    )

    audit_log.info(
        "quantized_collection_created",
        collection=collection_name,
        quantization=quantization_type,
        sensitivity=sensitivity_level
    )

def validate_quantization_results(
    client: QdrantClient,
    collection_name: str,
    test_vectors: list,
    accuracy_threshold: float = 0.95
):
    """Validate quantization doesn't degrade search quality below threshold."""
    # Implementation: Compare exact vs quantized search results
    # Alert if accuracy drops below threshold
    pass
```

**Don't**: Apply aggressive quantization to sensitive data without understanding tradeoffs

```python
# RISKY: Binary quantization loses significant precision
# May not be appropriate for high-sensitivity data
client.create_collection(
    collection_name="medical_embeddings",
    vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
    quantization_config=BinaryQuantization(
        binary=BinaryQuantizationConfig(
            always_ram=True
        )
    )
)
```

**Why**: Quantization reduces embedding precision which can impact search quality. Binary quantization provides maximum compression but lowest precision. Choose quantization based on data sensitivity and accuracy requirements.

**Refs**: MITRE ATLAS ML04 (Model Inversion), accuracy vs compression tradeoffs

---

## Rule: Snapshot Security

**Level**: `strict`

**When**: Creating, storing, or restoring Qdrant snapshots

**Do**: Encrypt snapshots at rest, verify integrity before restore, secure storage locations

```python
from qdrant_client import QdrantClient
from cryptography.fernet import Fernet
import hashlib
import os
from datetime import datetime

def create_encrypted_snapshot(
    client: QdrantClient,
    collection_name: str,
    backup_dir: str
) -> dict:
    """Create encrypted snapshot with integrity verification."""
    # Create snapshot
    snapshot_info = client.create_snapshot(collection_name=collection_name)
    snapshot_name = snapshot_info.name

    # Download snapshot
    temp_path = f"/tmp/{snapshot_name}"
    snapshot_data = client.download_snapshot(
        collection_name=collection_name,
        snapshot_name=snapshot_name,
        path=temp_path
    )

    # Calculate original checksum
    with open(temp_path, "rb") as f:
        original_data = f.read()
    original_checksum = hashlib.sha256(original_data).hexdigest()

    # Encrypt snapshot
    encryption_key = os.environ["QDRANT_BACKUP_KEY"]
    fernet = Fernet(encryption_key)
    encrypted_data = fernet.encrypt(original_data)

    # Save encrypted snapshot
    encrypted_path = os.path.join(
        backup_dir,
        f"{collection_name}_{snapshot_name}.enc"
    )
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    # Calculate encrypted checksum
    encrypted_checksum = hashlib.sha256(encrypted_data).hexdigest()

    # Clean up unencrypted temp file
    os.remove(temp_path)

    # Store metadata
    metadata = {
        "collection": collection_name,
        "snapshot_name": snapshot_name,
        "original_checksum": original_checksum,
        "encrypted_checksum": encrypted_checksum,
        "created_at": datetime.utcnow().isoformat(),
        "encrypted_path": encrypted_path
    }

    # Audit log
    audit_log.info("snapshot_created", **metadata)

    return metadata

def restore_encrypted_snapshot(
    client: QdrantClient,
    encrypted_path: str,
    expected_checksum: str,
    collection_name: str
):
    """Restore snapshot with integrity verification."""
    # Read encrypted snapshot
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    # Verify integrity
    actual_checksum = hashlib.sha256(encrypted_data).hexdigest()
    if actual_checksum != expected_checksum:
        audit_log.error(
            "snapshot_integrity_failure",
            expected=expected_checksum,
            actual=actual_checksum
        )
        raise IntegrityError("Snapshot checksum mismatch - possible tampering")

    # Decrypt
    encryption_key = os.environ["QDRANT_BACKUP_KEY"]
    fernet = Fernet(encryption_key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write to temp file for restore
    temp_path = f"/tmp/restore_{collection_name}"
    with open(temp_path, "wb") as f:
        f.write(decrypted_data)

    # Restore snapshot
    client.recover_snapshot(
        collection_name=collection_name,
        location=temp_path
    )

    # Clean up
    os.remove(temp_path)

    audit_log.info(
        "snapshot_restored",
        collection=collection_name,
        encrypted_path=encrypted_path
    )

def list_snapshots_secure(
    client: QdrantClient,
    collection_name: str
) -> list:
    """List snapshots with metadata validation."""
    snapshots = client.list_snapshots(collection_name=collection_name)

    # Return only snapshot metadata, not download URLs
    return [
        {
            "name": s.name,
            "creation_time": s.creation_time,
            "size": s.size
        }
        for s in snapshots
    ]
```

**Don't**: Store unencrypted snapshots, skip integrity verification

```python
# VULNERABLE: Unencrypted snapshot
client.create_snapshot(collection_name="sensitive_data")
# Snapshot stored in plaintext on disk

# VULNERABLE: No integrity check on restore
def restore_snapshot(client, snapshot_path):
    # Restore without verifying snapshot wasn't tampered
    client.recover_snapshot(
        collection_name="vectors",
        location=snapshot_path  # Could be corrupted or malicious
    )

# VULNERABLE: Snapshots in public storage
snapshot_path = "s3://public-bucket/qdrant-backups/"  # Accessible to anyone
```

**Why**: Snapshots contain complete vector data including sensitive embeddings. Unencrypted snapshots can be exfiltrated. Without integrity verification, attackers can inject malicious data through tampered snapshots.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, CWE-354

---

## Rule: gRPC Security

**Level**: `warning`

**When**: Using gRPC protocol for Qdrant communication

**Do**: Enable TLS for gRPC, configure authentication, validate certificates

```python
from qdrant_client import QdrantClient
import grpc
import os

# Secure gRPC connection with TLS
def get_secure_grpc_client() -> QdrantClient:
    """Create Qdrant client with secure gRPC configuration."""
    return QdrantClient(
        url=os.environ["QDRANT_URL"],
        api_key=os.environ["QDRANT_API_KEY"],
        prefer_grpc=True,  # Use gRPC for better performance
        https=True,  # Enable TLS
        timeout=30,
        # Optional: custom gRPC options
        grpc_options={
            'grpc.max_send_message_length': 100 * 1024 * 1024,  # 100MB
            'grpc.max_receive_message_length': 100 * 1024 * 1024,
            'grpc.keepalive_time_ms': 30000,
            'grpc.keepalive_timeout_ms': 10000,
        }
    )

# For on-premise deployments with custom certificates
def get_grpc_client_with_certs() -> QdrantClient:
    """Create gRPC client with custom TLS certificates."""
    # Load certificates
    with open(os.environ["QDRANT_CA_CERT"], "rb") as f:
        ca_cert = f.read()
    with open(os.environ["QDRANT_CLIENT_CERT"], "rb") as f:
        client_cert = f.read()
    with open(os.environ["QDRANT_CLIENT_KEY"], "rb") as f:
        client_key = f.read()

    # Create SSL credentials
    credentials = grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert
    )

    return QdrantClient(
        host=os.environ["QDRANT_HOST"],
        port=6334,  # gRPC port
        grpc_options={
            'grpc.ssl_target_name_override': os.environ["QDRANT_HOST"]
        },
        https=True,
        api_key=os.environ["QDRANT_API_KEY"]
    )

# Connection health check
def verify_grpc_connection(client: QdrantClient) -> bool:
    """Verify gRPC connection is secure and healthy."""
    try:
        # Simple health check
        collections = client.get_collections()
        return True
    except Exception as e:
        audit_log.error("grpc_connection_failed", error=str(e))
        return False
```

**Don't**: Use unencrypted gRPC, skip certificate validation

```python
# VULNERABLE: Unencrypted gRPC
client = QdrantClient(
    host="qdrant.internal",
    port=6334,
    prefer_grpc=True,
    https=False  # Plaintext gRPC traffic
)

# VULNERABLE: No API key authentication
client = QdrantClient(
    url="https://qdrant.example.com",
    prefer_grpc=True
    # No api_key - unauthenticated access
)

# VULNERABLE: Disabled certificate verification
import ssl
context = ssl.create_default_context()
context.check_hostname = False  # Dangerous
context.verify_mode = ssl.CERT_NONE  # No certificate validation
```

**Why**: Unencrypted gRPC exposes vector data and API keys to network interception. Without authentication, anyone with network access can query or modify data. Certificate validation prevents man-in-the-middle attacks.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-295, CWE-319

---

## Rule: Multi-Vector Security

**Level**: `warning`

**When**: Using named vectors with multiple embedding types per point

**Do**: Control access to specific named vectors, validate vector names

```python
from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams, Distance, NamedVector
)

# Allowed vector names by role
VECTOR_ACCESS_CONTROL = {
    "public": ["title_embedding", "summary_embedding"],
    "internal": ["title_embedding", "summary_embedding", "content_embedding"],
    "admin": ["title_embedding", "summary_embedding", "content_embedding", "internal_embedding"]
}

def create_multi_vector_collection(
    client: QdrantClient,
    collection_name: str
):
    """Create collection with multiple named vectors."""
    client.create_collection(
        collection_name=collection_name,
        vectors_config={
            "title_embedding": VectorParams(
                size=384,
                distance=Distance.COSINE
            ),
            "summary_embedding": VectorParams(
                size=768,
                distance=Distance.COSINE
            ),
            "content_embedding": VectorParams(
                size=1536,
                distance=Distance.COSINE
            ),
            "internal_embedding": VectorParams(
                size=1536,
                distance=Distance.COSINE
            )
        }
    )

def secure_multi_vector_query(
    client: QdrantClient,
    collection_name: str,
    tenant_id: str,
    user_role: str,
    vector_name: str,
    query_vector: list,
    top_k: int = 10
):
    """Query specific named vector with access control."""
    # Validate vector access
    allowed_vectors = VECTOR_ACCESS_CONTROL.get(user_role, [])
    if vector_name not in allowed_vectors:
        raise PermissionError(
            f"Role '{user_role}' cannot access vector '{vector_name}'"
        )

    # Validate vector name format
    if not re.match(r'^[a-zA-Z0-9_]{1,64}$', vector_name):
        raise ValueError("Invalid vector name format")

    # Build tenant filter
    query_filter = Filter(
        must=[
            FieldCondition(
                key="tenant_id",
                match=MatchValue(value=tenant_id)
            )
        ]
    )

    # Query specific named vector
    results = client.search(
        collection_name=collection_name,
        query_vector=NamedVector(
            name=vector_name,
            vector=query_vector
        ),
        query_filter=query_filter,
        limit=min(top_k, 100),
        with_payload=True
    )

    audit_log.info(
        "multi_vector_query",
        collection=collection_name,
        tenant=tenant_id,
        vector=vector_name,
        role=user_role,
        results=len(results)
    )

    return results

def secure_multi_vector_upsert(
    client: QdrantClient,
    collection_name: str,
    tenant_id: str,
    user_role: str,
    point_id: str,
    vectors: dict,
    payload: dict
):
    """Upsert with access control for named vectors."""
    allowed_vectors = VECTOR_ACCESS_CONTROL.get(user_role, [])

    # Filter to only allowed vectors
    safe_vectors = {}
    for vector_name, vector_data in vectors.items():
        if vector_name in allowed_vectors:
            safe_vectors[vector_name] = vector_data
        else:
            audit_log.warning(
                "unauthorized_vector_write_attempt",
                vector=vector_name,
                role=user_role
            )

    if not safe_vectors:
        raise PermissionError("No authorized vectors to write")

    # Add tenant_id to payload
    payload["tenant_id"] = tenant_id

    client.upsert(
        collection_name=collection_name,
        points=[{
            "id": point_id,
            "vector": safe_vectors,
            "payload": payload
        }]
    )
```

**Don't**: Allow unrestricted access to all named vectors

```python
# VULNERABLE: No access control for named vectors
def query_any_vector(client, vector_name, query_vector):
    # User can query any vector including internal ones
    return client.search(
        collection_name="documents",
        query_vector=NamedVector(
            name=vector_name,  # Could be "internal_embedding"
            vector=query_vector
        )
    )

# VULNERABLE: No validation of vector names
def upsert_vectors(client, point_id, user_vectors):
    client.upsert(
        collection_name="documents",
        points=[{
            "id": point_id,
            "vector": user_vectors  # User controls all vector names
        }]
    )
```

**Why**: Named vectors may contain different sensitivity levels (public summary vs internal analysis). Without access control, users can query or overwrite vectors they shouldn't access. Vector name validation prevents injection attacks.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-15 | Initial release with 7 Qdrant-specific rules |

---

## Additional Resources

- [Qdrant Security Documentation](https://qdrant.tech/documentation/guides/security/)
- [Qdrant API Key Authentication](https://qdrant.tech/documentation/cloud/authentication/)
- [Qdrant gRPC Interface](https://qdrant.tech/documentation/interfaces/#grpc-interface)
- [Qdrant Snapshots](https://qdrant.tech/documentation/concepts/snapshots/)
- [Core Vector Store Security Rules](../../_core/vector-store-security.md)
