# Vector Store Security Rules

Security rules for vector database implementations across all platforms (Pinecone, Milvus, Qdrant, Weaviate, pgvector, Chroma).

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Connection Security | `strict` | Data interception, unauthorized access |
| Multi-Tenant Namespace Isolation | `strict` | Cross-tenant data leakage |
| Query Injection Prevention | `strict` | Filter bypass, data exfiltration |
| Index Access Control | `strict` | Unauthorized collection access |
| Data Lineage and Provenance | `strict` | Untraceable data, compliance violations |
| Backup Encryption | `strict` | Data exposure in backups |
| Vector Distance Attack Prevention | `warning` | Embedding inversion, membership inference |
| Cross-Tenant Query Filtering | `strict` | Multi-tenant query leakage |

---

## Rule: Connection Security

**Level**: `strict`

**When**: Establishing connections to any vector database

**Do**: Use TLS encryption, strong authentication, and connection pooling with timeouts

```python
# Pinecone - Secure connection
from pinecone import Pinecone

pc = Pinecone(
    api_key=os.environ["PINECONE_API_KEY"],  # Never hardcode
    environment="us-east-1-aws",
    pool_threads=4,
    timeout=30
)

# Milvus - TLS connection with authentication
from pymilvus import connections

connections.connect(
    alias="default",
    host=os.environ["MILVUS_HOST"],
    port="19530",
    user=os.environ["MILVUS_USER"],
    password=os.environ["MILVUS_PASSWORD"],
    secure=True,  # Enable TLS
    server_pem_path="/path/to/server.pem",
    server_name="milvus.example.com"
)

# pgvector - SSL connection with certificate verification
import psycopg2

conn = psycopg2.connect(
    host=os.environ["PGVECTOR_HOST"],
    database="vectors",
    user=os.environ["PGVECTOR_USER"],
    password=os.environ["PGVECTOR_PASSWORD"],
    sslmode="verify-full",
    sslrootcert="/path/to/ca.crt",
    sslcert="/path/to/client.crt",
    sslkey="/path/to/client.key",
    connect_timeout=10
)

# Qdrant - API key with TLS
from qdrant_client import QdrantClient

client = QdrantClient(
    url=os.environ["QDRANT_URL"],
    api_key=os.environ["QDRANT_API_KEY"],
    timeout=30,
    prefer_grpc=True,
    https=True
)
```

**Don't**: Use unencrypted connections or embed credentials

```python
# VULNERABLE: Hardcoded credentials, no TLS
from pinecone import Pinecone
pc = Pinecone(api_key="pk-abc123")  # Exposed in code/logs

# VULNERABLE: Unencrypted Milvus connection
connections.connect(
    host="milvus.internal",
    port="19530"
    # No auth, no TLS - plaintext traffic
)

# VULNERABLE: pgvector without SSL
conn = psycopg2.connect(
    host="db.example.com",
    password="hardcoded_password",
    sslmode="disable"  # Traffic can be intercepted
)
```

**Why**: Unencrypted connections expose vector data and queries to network interception. Hardcoded credentials leak through version control, logs, and error messages. Connection pooling without timeouts can exhaust resources.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-319, CWE-798

---

## Rule: Multi-Tenant Namespace Isolation

**Level**: `strict`

**When**: Storing vectors from multiple tenants/users in the same database

**Do**: Enforce strict namespace/collection separation per tenant with server-side validation

```python
# Pinecone - Namespace isolation per tenant
def get_tenant_index(tenant_id: str):
    """Get index with tenant namespace isolation."""
    # Validate tenant_id format
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
        raise ValueError("Invalid tenant_id format")

    index = pc.Index("main-index")
    return index, tenant_id  # Use tenant_id as namespace

def upsert_vectors(tenant_id: str, vectors: list):
    index, namespace = get_tenant_index(tenant_id)
    # All operations scoped to tenant namespace
    index.upsert(vectors=vectors, namespace=namespace)

def query_vectors(tenant_id: str, query_vector: list, top_k: int = 10):
    index, namespace = get_tenant_index(tenant_id)
    # Query restricted to tenant namespace only
    return index.query(
        vector=query_vector,
        top_k=top_k,
        namespace=namespace,  # Isolation enforced
        include_metadata=True
    )

# Milvus - Separate collections per tenant
def get_tenant_collection(tenant_id: str):
    """Get or create tenant-specific collection."""
    collection_name = f"tenant_{tenant_id}_vectors"

    # Validate collection name
    if not Collection.exists(collection_name):
        raise PermissionError(f"Tenant {tenant_id} not provisioned")

    return Collection(collection_name)

# pgvector - Row-level security for multi-tenancy
"""
-- Enable RLS on vectors table
ALTER TABLE vectors ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's vectors
CREATE POLICY tenant_isolation ON vectors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Set tenant context before queries
SET app.current_tenant = 'tenant-uuid-here';
"""

def query_with_tenant_context(conn, tenant_id: str, query_vector: list):
    with conn.cursor() as cur:
        # Set tenant context (enforced by RLS)
        cur.execute("SET app.current_tenant = %s", (tenant_id,))

        # Query automatically filtered by RLS policy
        cur.execute("""
            SELECT id, content, embedding <-> %s::vector AS distance
            FROM vectors
            ORDER BY distance
            LIMIT 10
        """, (query_vector,))
        return cur.fetchall()
```

**Don't**: Rely on application-level filtering alone or mix tenant data

```python
# VULNERABLE: Single namespace for all tenants
def query_vectors(query_vector, tenant_id):
    index = pc.Index("shared-index")
    results = index.query(
        vector=query_vector,
        top_k=10,
        # No namespace - queries all tenant data!
        filter={"tenant_id": tenant_id}  # Client-side only
    )
    return results

# VULNERABLE: Filter can be bypassed
def query_vectors(query_vector, filters):
    # Attacker can omit tenant_id from filters
    return index.query(
        vector=query_vector,
        filter=filters  # No tenant enforcement
    )
```

**Why**: Without namespace isolation, a malicious or buggy query can access other tenants' data. Application-level filtering can be bypassed through query manipulation. Namespace/collection separation provides defense in depth.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Query Injection Prevention

**Level**: `strict`

**When**: Constructing vector queries with user-provided filters or metadata

**Do**: Validate and sanitize all filter inputs, use allowlists for filter fields

```python
# Pinecone - Safe filter construction
ALLOWED_FILTER_FIELDS = {"category", "date", "status", "source"}
ALLOWED_OPERATORS = {"$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin"}

def build_safe_filter(user_filters: dict) -> dict:
    """Build filter with validation and sanitization."""
    safe_filter = {}

    for field, condition in user_filters.items():
        # Validate field name
        if field not in ALLOWED_FILTER_FIELDS:
            raise ValueError(f"Invalid filter field: {field}")

        # Validate condition structure
        if isinstance(condition, dict):
            for op, value in condition.items():
                if op not in ALLOWED_OPERATORS:
                    raise ValueError(f"Invalid operator: {op}")
                # Type validation
                safe_filter[field] = {op: sanitize_value(value)}
        else:
            safe_filter[field] = {"$eq": sanitize_value(condition)}

    return safe_filter

def sanitize_value(value):
    """Sanitize filter values."""
    if isinstance(value, str):
        # Prevent injection through special characters
        if len(value) > 1000:
            raise ValueError("Filter value too long")
        return value.strip()
    elif isinstance(value, (int, float, bool)):
        return value
    elif isinstance(value, list):
        return [sanitize_value(v) for v in value[:100]]  # Limit list size
    else:
        raise ValueError(f"Invalid value type: {type(value)}")

# Milvus - Parameterized expression building
def build_milvus_filter(tenant_id: str, user_filters: dict) -> str:
    """Build Milvus filter expression safely."""
    expressions = [f'tenant_id == "{tenant_id}"']  # Always enforce tenant

    for field, value in user_filters.items():
        if field not in ALLOWED_FILTER_FIELDS:
            continue

        # Use parameterized expressions
        if isinstance(value, str):
            # Escape quotes in string values
            escaped = value.replace('"', '\\"')
            expressions.append(f'{field} == "{escaped}"')
        elif isinstance(value, (int, float)):
            expressions.append(f'{field} == {value}')

    return " && ".join(expressions)

# Qdrant - Type-safe filter construction
from qdrant_client.models import Filter, FieldCondition, MatchValue

def build_qdrant_filter(tenant_id: str, user_filters: dict) -> Filter:
    """Build Qdrant filter with type safety."""
    conditions = [
        FieldCondition(
            key="tenant_id",
            match=MatchValue(value=tenant_id)
        )
    ]

    for field, value in user_filters.items():
        if field not in ALLOWED_FILTER_FIELDS:
            continue

        # Type-safe condition building
        conditions.append(
            FieldCondition(
                key=field,
                match=MatchValue(value=value)
            )
        )

    return Filter(must=conditions)
```

**Don't**: Construct filters from raw user input or use string interpolation

```python
# VULNERABLE: Direct user input in filter
def query_vectors(query_vector, user_filter):
    return index.query(
        vector=query_vector,
        filter=user_filter  # Attacker controls entire filter
    )

# VULNERABLE: String interpolation in Milvus
def query_milvus(collection, user_category):
    # SQL-injection style attack possible
    expr = f'category == "{user_category}"'  # user_category = '" || true || "'
    return collection.query(expr=expr)

# VULNERABLE: No field validation
def build_filter(user_input):
    return {k: v for k, v in user_input.items()}  # Any field allowed
```

**Why**: Unvalidated filters enable attackers to bypass access controls, exfiltrate data through crafted queries, or cause denial of service through expensive filter operations. Metadata injection can poison search results.

**Refs**: OWASP A03:2025 (Injection), CWE-89, CWE-943

---

## Rule: Index Access Control

**Level**: `strict`

**When**: Managing access to vector collections/indexes

**Do**: Implement RBAC with least privilege, separate read/write permissions

```python
# Pinecone - API key scoping (use separate keys per environment)
# Production: Read-only key for query services
# Admin: Full access key for indexing (secured separately)

class VectorStoreClient:
    def __init__(self, role: str):
        if role == "query":
            # Read-only operations
            self.pc = Pinecone(api_key=os.environ["PINECONE_QUERY_KEY"])
            self.can_write = False
        elif role == "indexer":
            # Write operations
            self.pc = Pinecone(api_key=os.environ["PINECONE_INDEX_KEY"])
            self.can_write = True
        else:
            raise ValueError(f"Unknown role: {role}")

    def upsert(self, vectors, namespace):
        if not self.can_write:
            raise PermissionError("Query role cannot write")
        return self.index.upsert(vectors=vectors, namespace=namespace)

# Milvus - Role-based access control
from pymilvus import Role, utility

def setup_milvus_rbac():
    # Create roles
    query_role = Role("query_role")
    query_role.create()

    # Grant read-only permissions
    query_role.grant("Collection", "vectors", "Search")
    query_role.grant("Collection", "vectors", "Query")

    # Create indexer role with write access
    indexer_role = Role("indexer_role")
    indexer_role.create()
    indexer_role.grant("Collection", "vectors", "*")

    # Assign users to roles
    query_role.add_user("query_service")
    indexer_role.add_user("indexing_pipeline")

# pgvector - PostgreSQL role-based access
"""
-- Create roles
CREATE ROLE vector_reader;
CREATE ROLE vector_writer;

-- Grant permissions
GRANT SELECT ON vectors TO vector_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON vectors TO vector_writer;

-- Create users with roles
CREATE USER query_service WITH PASSWORD 'secure_password';
GRANT vector_reader TO query_service;

CREATE USER indexing_service WITH PASSWORD 'secure_password';
GRANT vector_writer TO indexing_service;
"""

# Qdrant - Collection-level access control
def create_restricted_collection(client, collection_name: str, allowed_users: list):
    """Create collection with access metadata for application-level RBAC."""
    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(size=1536, distance=Distance.COSINE)
    )

    # Store ACL in collection metadata
    client.update_collection(
        collection_name=collection_name,
        metadata={"allowed_users": allowed_users, "created_at": datetime.utcnow().isoformat()}
    )
```

**Don't**: Use shared credentials or grant excessive permissions

```python
# VULNERABLE: Single shared API key for all operations
PINECONE_KEY = os.environ["PINECONE_KEY"]  # Full access everywhere

# VULNERABLE: All users have admin access
connections.connect(
    user="admin",  # Everyone uses admin
    password=os.environ["MILVUS_ADMIN_PASSWORD"]
)

# VULNERABLE: No permission separation
"""
GRANT ALL ON vectors TO public;  -- Everyone can do everything
"""
```

**Why**: Without access control, compromised query services can modify or delete indexes. Shared credentials make it impossible to audit actions or revoke specific access. Least privilege limits blast radius of compromises.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-732

---

## Rule: Data Lineage and Provenance

**Level**: `strict`

**When**: Storing vectors for compliance, auditability, or data governance

**Do**: Include provenance metadata (doc_id, source, owner, timestamps) with every vector

```python
# Standard provenance metadata schema
from datetime import datetime
from uuid import uuid4

def create_vector_with_provenance(
    embedding: list,
    content: str,
    source_doc_id: str,
    owner_id: str,
    source_system: str,
    **additional_metadata
) -> dict:
    """Create vector record with full provenance tracking."""
    return {
        "id": str(uuid4()),
        "values": embedding,
        "metadata": {
            # Required provenance fields
            "doc_id": source_doc_id,
            "owner_id": owner_id,
            "source_system": source_system,
            "upload_timestamp": datetime.utcnow().isoformat(),
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),

            # Compliance fields
            "data_classification": additional_metadata.get("classification", "internal"),
            "retention_days": additional_metadata.get("retention", 365),
            "pii_detected": additional_metadata.get("pii_detected", False),

            # Searchable content
            "content_preview": content[:500],
            **additional_metadata
        }
    }

# Pinecone upsert with provenance
def index_document(index, tenant_id: str, doc_id: str, chunks: list, embeddings: list, owner_id: str):
    vectors = []
    for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
        vectors.append(create_vector_with_provenance(
            embedding=embedding,
            content=chunk,
            source_doc_id=doc_id,
            owner_id=owner_id,
            source_system="document_processor",
            chunk_index=i,
            total_chunks=len(chunks)
        ))

    index.upsert(vectors=vectors, namespace=tenant_id)

    # Log indexing event for audit
    audit_log.info(
        "vectors_indexed",
        tenant_id=tenant_id,
        doc_id=doc_id,
        vector_count=len(vectors),
        owner_id=owner_id
    )

# Query with provenance for audit trail
def query_with_audit(index, tenant_id: str, user_id: str, query_vector: list, top_k: int = 10):
    results = index.query(
        vector=query_vector,
        top_k=top_k,
        namespace=tenant_id,
        include_metadata=True
    )

    # Audit log for compliance
    audit_log.info(
        "vector_query",
        tenant_id=tenant_id,
        user_id=user_id,
        query_timestamp=datetime.utcnow().isoformat(),
        result_doc_ids=[r.metadata.get("doc_id") for r in results.matches],
        result_owners=[r.metadata.get("owner_id") for r in results.matches]
    )

    return results

# Data lifecycle management
def enforce_retention(index, tenant_id: str):
    """Delete vectors past retention period."""
    cutoff = datetime.utcnow() - timedelta(days=1)

    # Query for expired vectors
    # Implementation varies by vector store
    expired = index.query(
        vector=[0] * 1536,  # Dummy vector
        top_k=10000,
        namespace=tenant_id,
        filter={
            "retention_expiry": {"$lt": cutoff.isoformat()}
        },
        include_metadata=True
    )

    if expired.matches:
        ids_to_delete = [m.id for m in expired.matches]
        index.delete(ids=ids_to_delete, namespace=tenant_id)
        audit_log.info("retention_cleanup", deleted_count=len(ids_to_delete))
```

**Don't**: Store vectors without source tracking or audit capabilities

```python
# VULNERABLE: No provenance metadata
index.upsert([
    {"id": "vec1", "values": embedding}  # No source, owner, or timestamp
])

# VULNERABLE: Cannot trace data origin
results = index.query(vector=query_vector, top_k=10)
# No way to know where results came from or who owns them

# VULNERABLE: No retention management
# Vectors stored indefinitely with no cleanup
```

**Why**: Without provenance, you cannot comply with data subject access requests (GDPR), audit data access, enforce retention policies, or trace the source of problematic content. Content hashes enable integrity verification.

**Refs**: GDPR Article 30, CCPA, CWE-778, CWE-779

---

## Rule: Backup Encryption

**Level**: `strict`

**When**: Creating backups or snapshots of vector data

**Do**: Encrypt backups at rest, secure restore processes, verify backup integrity

```python
# Pinecone - Collections (backup) are encrypted by default
# Verify encryption settings in Pinecone console

# Milvus - Encrypted backup with integrity verification
import subprocess
from cryptography.fernet import Fernet

def backup_milvus_collection(collection_name: str, backup_path: str):
    """Create encrypted backup of Milvus collection."""
    # Export collection data
    temp_path = f"/tmp/{collection_name}_backup"

    # Use Milvus backup tool
    subprocess.run([
        "milvus-backup", "create",
        "--collection", collection_name,
        "--output", temp_path
    ], check=True)

    # Encrypt backup
    key = os.environ["BACKUP_ENCRYPTION_KEY"]
    fernet = Fernet(key)

    with open(temp_path, "rb") as f:
        encrypted = fernet.encrypt(f.read())

    with open(backup_path, "wb") as f:
        f.write(encrypted)

    # Calculate checksum for integrity
    checksum = hashlib.sha256(encrypted).hexdigest()

    # Clean up unencrypted temp file
    os.remove(temp_path)

    # Log backup event
    audit_log.info(
        "backup_created",
        collection=collection_name,
        backup_path=backup_path,
        checksum=checksum,
        encrypted=True
    )

    return checksum

def restore_milvus_backup(backup_path: str, checksum: str):
    """Restore encrypted backup with integrity verification."""
    # Verify integrity
    with open(backup_path, "rb") as f:
        encrypted = f.read()

    if hashlib.sha256(encrypted).hexdigest() != checksum:
        raise IntegrityError("Backup checksum mismatch")

    # Decrypt
    key = os.environ["BACKUP_ENCRYPTION_KEY"]
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    # Restore with audit logging
    temp_path = f"/tmp/restore_{uuid4()}"
    with open(temp_path, "wb") as f:
        f.write(decrypted)

    subprocess.run([
        "milvus-backup", "restore",
        "--input", temp_path
    ], check=True)

    os.remove(temp_path)
    audit_log.info("backup_restored", backup_path=backup_path)

# pgvector - pg_dump with encryption
"""
# Encrypted backup using GPG
pg_dump -h localhost -U admin -d vectordb | \
    gpg --encrypt --recipient backup@company.com > backup.sql.gpg

# Verify and restore
gpg --verify backup.sql.gpg.sig backup.sql.gpg
gpg --decrypt backup.sql.gpg | psql -h localhost -U admin -d vectordb
"""

# Qdrant - Snapshot with encryption
def create_qdrant_snapshot(client, collection_name: str):
    """Create encrypted snapshot."""
    # Create snapshot
    snapshot_info = client.create_snapshot(collection_name=collection_name)

    # Download and encrypt
    snapshot_path = f"/backups/{collection_name}_{snapshot_info.name}"
    # Download snapshot file, then encrypt as shown above

    return snapshot_info
```

**Don't**: Store unencrypted backups or skip integrity verification

```python
# VULNERABLE: Unencrypted backup
subprocess.run(["milvus-backup", "create", "--output", "/backups/vectors"])
# Backup contains plaintext vector data

# VULNERABLE: No integrity check on restore
def restore_backup(backup_path):
    # Restore without verifying backup wasn't tampered
    subprocess.run(["milvus-backup", "restore", "--input", backup_path])

# VULNERABLE: Backups stored in public location
backup_path = "s3://public-bucket/backups/"  # Accessible to anyone
```

**Why**: Backups often contain the complete vector database including sensitive embeddings. Unencrypted backups can be exfiltrated or tampered with. Integrity verification prevents restoring corrupted or malicious backups.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, CWE-312

---

## Rule: Vector Distance Attack Prevention

**Level**: `warning`

**When**: Storing embeddings of sensitive content where privacy is critical

**Do**: Apply quantization, add differential privacy noise, or use secure computation

```python
import numpy as np

# Quantization to reduce embedding precision (limits inversion attacks)
def quantize_embedding(embedding: np.ndarray, bits: int = 8) -> np.ndarray:
    """Quantize embedding to reduce precision and limit inversion attacks."""
    # Normalize to [0, 1]
    min_val, max_val = embedding.min(), embedding.max()
    normalized = (embedding - min_val) / (max_val - min_val + 1e-10)

    # Quantize
    levels = 2 ** bits
    quantized = np.round(normalized * (levels - 1)) / (levels - 1)

    # Denormalize
    return quantized * (max_val - min_val) + min_val

# Differential privacy noise addition
def add_dp_noise(embedding: np.ndarray, epsilon: float = 1.0, sensitivity: float = 1.0) -> np.ndarray:
    """Add calibrated Laplacian noise for differential privacy."""
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale, embedding.shape)
    noisy_embedding = embedding + noise

    # Normalize to maintain unit length (for cosine similarity)
    return noisy_embedding / np.linalg.norm(noisy_embedding)

# Combined protection
def protect_embedding(embedding: np.ndarray, sensitivity_level: str = "standard") -> np.ndarray:
    """Apply appropriate protection based on data sensitivity."""
    if sensitivity_level == "high":
        # Maximum protection: quantization + strong DP
        embedding = quantize_embedding(embedding, bits=6)
        embedding = add_dp_noise(embedding, epsilon=0.5)
    elif sensitivity_level == "medium":
        # Moderate protection
        embedding = quantize_embedding(embedding, bits=8)
        embedding = add_dp_noise(embedding, epsilon=1.0)
    else:
        # Standard protection
        embedding = quantize_embedding(embedding, bits=8)

    return embedding

# Index with protected embeddings
def index_sensitive_document(index, doc_id: str, content: str, sensitivity: str):
    # Generate embedding
    embedding = embedding_model.encode(content)

    # Apply protection
    protected = protect_embedding(np.array(embedding), sensitivity)

    # Store with sensitivity metadata
    index.upsert([{
        "id": doc_id,
        "values": protected.tolist(),
        "metadata": {
            "sensitivity": sensitivity,
            "protection_applied": True,
            "original_not_stored": True
        }
    }])

# Query-time considerations
def similarity_threshold_for_sensitivity(sensitivity: str) -> float:
    """Adjust similarity thresholds for protected embeddings."""
    # Protected embeddings have lower similarity scores
    thresholds = {
        "high": 0.6,    # Lower threshold due to noise
        "medium": 0.7,
        "standard": 0.8
    }
    return thresholds.get(sensitivity, 0.8)
```

**Don't**: Store high-precision embeddings of sensitive content without protection

```python
# RISKY: Full precision embedding of sensitive data
embedding = model.encode(sensitive_medical_record)
index.upsert([{
    "id": doc_id,
    "values": embedding  # Full precision enables inversion attacks
}])

# RISKY: No protection for PII
embedding = model.encode(f"SSN: {ssn}, Name: {name}")
# Embedding can potentially be inverted to recover PII
```

**Why**: High-precision embeddings can be vulnerable to inversion attacks that recover original content, membership inference attacks, and model extraction. Quantization and DP noise provide protection while maintaining utility.

**Refs**: MITRE ATLAS ML04 (ML Model Inversion), CWE-200, Differential Privacy literature

---

## Rule: Cross-Tenant Query Filtering

**Level**: `strict`

**When**: Executing queries in multi-tenant vector stores

**Do**: Enforce tenant isolation at server level with defense in depth

```python
# Defense in depth: Multiple layers of tenant enforcement

class SecureVectorStore:
    def __init__(self, index, audit_logger):
        self.index = index
        self.audit = audit_logger

    def query(self, tenant_id: str, user_id: str, query_vector: list,
              filters: dict = None, top_k: int = 10):
        """Query with mandatory tenant isolation."""

        # Layer 1: Validate tenant access
        if not self._user_has_tenant_access(user_id, tenant_id):
            self.audit.warning(
                "unauthorized_tenant_access",
                user_id=user_id,
                attempted_tenant=tenant_id
            )
            raise PermissionError("User not authorized for tenant")

        # Layer 2: Namespace isolation (server-enforced)
        # Pinecone example - namespace is mandatory

        # Layer 3: Metadata filter enforcement
        safe_filters = self._build_tenant_filter(tenant_id, filters or {})

        # Execute query
        results = self.index.query(
            vector=query_vector,
            top_k=top_k,
            namespace=tenant_id,  # Primary isolation
            filter=safe_filters,  # Secondary isolation
            include_metadata=True
        )

        # Layer 4: Response validation
        validated_results = self._validate_results(results, tenant_id)

        # Audit successful query
        self.audit.info(
            "vector_query",
            tenant_id=tenant_id,
            user_id=user_id,
            result_count=len(validated_results)
        )

        return validated_results

    def _build_tenant_filter(self, tenant_id: str, user_filters: dict) -> dict:
        """Build filter with mandatory tenant constraint."""
        # Tenant ID is ALWAYS required in filter
        base_filter = {"tenant_id": {"$eq": tenant_id}}

        # Merge with user filters (tenant_id cannot be overridden)
        if user_filters:
            # Remove any attempt to override tenant_id
            user_filters.pop("tenant_id", None)
            return {"$and": [base_filter, user_filters]}

        return base_filter

    def _validate_results(self, results, expected_tenant: str) -> list:
        """Validate all results belong to expected tenant."""
        validated = []
        for match in results.matches:
            result_tenant = match.metadata.get("tenant_id")
            if result_tenant != expected_tenant:
                # Log security incident
                self.audit.error(
                    "cross_tenant_leak_detected",
                    expected_tenant=expected_tenant,
                    leaked_tenant=result_tenant,
                    vector_id=match.id
                )
                # Skip leaked result
                continue
            validated.append(match)

        return validated

    def _user_has_tenant_access(self, user_id: str, tenant_id: str) -> bool:
        """Check user authorization for tenant."""
        # Implement based on your auth system
        return auth_service.check_tenant_access(user_id, tenant_id)


# pgvector - Row-level security with application validation
class PgVectorSecureStore:
    def __init__(self, conn):
        self.conn = conn

    def query(self, tenant_id: str, query_vector: list, top_k: int = 10):
        with self.conn.cursor() as cur:
            # Set tenant context for RLS
            cur.execute(
                "SELECT set_config('app.current_tenant', %s, true)",
                (tenant_id,)
            )

            # Query with RLS active
            cur.execute("""
                SELECT id, content, metadata,
                       embedding <-> %s::vector AS distance,
                       tenant_id
                FROM vectors
                ORDER BY distance
                LIMIT %s
            """, (query_vector, top_k))

            results = cur.fetchall()

            # Defense in depth: verify tenant in results
            for row in results:
                if row['tenant_id'] != tenant_id:
                    raise SecurityError("RLS bypass detected")

            return results
```

**Don't**: Rely solely on client-side filtering or trust user-provided tenant IDs

```python
# VULNERABLE: Client-side filtering only
def query(user_provided_tenant, query_vector):
    # No server-side enforcement
    results = index.query(vector=query_vector, top_k=100)
    # Filter client-side - can be bypassed
    return [r for r in results if r.metadata.get("tenant_id") == user_provided_tenant]

# VULNERABLE: Trust user-provided tenant ID
def query(request):
    tenant_id = request.json["tenant_id"]  # User can provide any tenant
    return index.query(
        vector=request.json["vector"],
        namespace=tenant_id  # No authorization check
    )

# VULNERABLE: No result validation
def query(tenant_id, query_vector):
    results = index.query(vector=query_vector, namespace=tenant_id)
    return results  # Don't verify results actually belong to tenant
```

**Why**: Multi-tenant systems are high-value targets. Namespace isolation can have bugs or misconfigurations. Defense in depth with multiple enforcement layers and result validation ensures tenant data remains isolated even if one layer fails.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-15 | Initial release with 8 core rules |

---

## Additional Resources

- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [Pinecone Security Best Practices](https://docs.pinecone.io/docs/security)
- [Milvus Security Configuration](https://milvus.io/docs/security_overview.md)
- [pgvector Security](https://github.com/pgvector/pgvector)
- [Qdrant Security](https://qdrant.tech/documentation/guides/security/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
