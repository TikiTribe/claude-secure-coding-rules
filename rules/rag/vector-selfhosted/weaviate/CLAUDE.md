# Weaviate Self-Hosted Security Rules

Security rules for self-hosted Weaviate vector database deployments.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Authentication Configuration | `strict` | Unauthorized database access |
| HNSW Index Security | `warning` | Resource exhaustion, performance degradation |
| Backup and Restore Security | `strict` | Data exposure, integrity compromise |
| Multi-Vector Support Security | `warning` | Cross-tenant vector access |
| Module Configuration | `warning` | API key exposure, data leakage |
| Kubernetes Deployment Security | `strict` | Cluster compromise, network attacks |
| Replication Security | `warning` | Data sync interception, cluster poisoning |

---

## Rule: Authentication Configuration

**Level**: `strict`

**When**: Deploying Weaviate in any environment beyond local development

**Do**: Enable authentication with API keys or OIDC, disable anonymous access

```python
# Weaviate v4 client - Secure connection with API key authentication
import weaviate
from weaviate.auth import AuthApiKey
import os

# Production configuration with API key
client = weaviate.connect_to_custom(
    http_host=os.environ["WEAVIATE_HOST"],
    http_port=8080,
    http_secure=True,  # Enable HTTPS
    grpc_host=os.environ["WEAVIATE_GRPC_HOST"],
    grpc_port=50051,
    grpc_secure=True,  # Enable gRPC TLS
    auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
    additional_config=weaviate.config.AdditionalConfig(
        timeout=(30, 120)  # (connect, read) timeouts
    )
)

# OIDC authentication for enterprise deployments
from weaviate.auth import AuthClientCredentials

client = weaviate.connect_to_custom(
    http_host=os.environ["WEAVIATE_HOST"],
    http_port=8080,
    http_secure=True,
    grpc_host=os.environ["WEAVIATE_GRPC_HOST"],
    grpc_port=50051,
    grpc_secure=True,
    auth_credentials=AuthClientCredentials(
        client_secret=os.environ["WEAVIATE_OIDC_SECRET"],
        scope="openid offline_access"
    )
)

# Verify connection is authenticated
try:
    meta = client.get_meta()
    if not meta.get("authentication"):
        raise SecurityError("Authentication not enabled on server")
finally:
    client.close()

# Docker Compose configuration for API key auth
"""
services:
  weaviate:
    image: cr.weaviate.io/semitechnologies/weaviate:latest
    environment:
      AUTHENTICATION_APIKEY_ENABLED: 'true'
      AUTHENTICATION_APIKEY_ALLOWED_KEYS: '${WEAVIATE_API_KEY}'
      AUTHENTICATION_APIKEY_USERS: 'admin'
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'false'
      AUTHORIZATION_ADMINLIST_ENABLED: 'true'
      AUTHORIZATION_ADMINLIST_USERS: 'admin'
"""
```

**Don't**: Enable anonymous access or use hardcoded credentials

```python
# VULNERABLE: No authentication
client = weaviate.connect_to_local()  # Anonymous access in production

# VULNERABLE: Hardcoded API key
client = weaviate.connect_to_custom(
    http_host="weaviate.example.com",
    http_port=8080,
    http_secure=False,  # No TLS
    auth_credentials=AuthApiKey("my-secret-key-123")  # Exposed in code
)

# VULNERABLE: Anonymous access enabled in config
"""
AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'true'
AUTHENTICATION_APIKEY_ENABLED: 'false'
"""
```

**Why**: Without authentication, anyone with network access can read, modify, or delete all vector data. Anonymous access bypasses all access controls. Hardcoded credentials leak through version control and logs.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures), CWE-284, CWE-798

---

## Rule: HNSW Index Security

**Level**: `warning`

**When**: Configuring HNSW vector index parameters for collections

**Do**: Set appropriate ef and maxConnections values to balance performance and resource usage

```python
import weaviate.classes as wvc
from weaviate.classes.config import Configure, Property, DataType

# Secure HNSW configuration with resource limits
client.collections.create(
    name="Documents",
    vectorizer_config=Configure.Vectorizer.none(),
    vector_index_config=Configure.VectorIndex.hnsw(
        # Reasonable defaults for production
        ef=128,              # Search quality (default: 64, max recommended: 512)
        ef_construction=128, # Build quality (default: 128)
        max_connections=32,  # Graph connectivity (default: 32, max: 128)
        distance_metric=wvc.config.VectorDistances.COSINE,
        # Flat search threshold for small collections
        flat_search_cutoff=40000,
        # Dynamic ef adjustment
        dynamic_ef_min=100,
        dynamic_ef_max=500,
        dynamic_ef_factor=8
    ),
    properties=[
        Property(name="content", data_type=DataType.TEXT),
        Property(name="tenant_id", data_type=DataType.TEXT, skip_vectorization=True)
    ],
    # Enable multi-tenancy for isolation
    multi_tenancy_config=Configure.multi_tenancy(enabled=True)
)

# Query with bounded ef to prevent resource exhaustion
def secure_query(collection, query_vector: list, tenant_id: str, top_k: int = 10):
    """Query with resource-safe parameters."""
    # Limit top_k to prevent memory exhaustion
    safe_top_k = min(top_k, 100)

    with collection.with_tenant(tenant_id) as tenant_collection:
        results = tenant_collection.query.near_vector(
            near_vector=query_vector,
            limit=safe_top_k,
            return_metadata=wvc.query.MetadataQuery(distance=True)
        )

    return results

# Monitor index health
def check_index_health(client, collection_name: str):
    """Verify index configuration is within safe bounds."""
    config = client.collections.get(collection_name).config.get()
    hnsw = config.vector_index_config

    warnings = []
    if hnsw.ef > 512:
        warnings.append(f"ef={hnsw.ef} may cause slow queries")
    if hnsw.max_connections > 128:
        warnings.append(f"maxConnections={hnsw.max_connections} increases memory usage")

    return warnings
```

**Don't**: Use excessively high HNSW parameters that enable resource exhaustion

```python
# VULNERABLE: Excessive parameters enable DoS
client.collections.create(
    name="Documents",
    vector_index_config=Configure.VectorIndex.hnsw(
        ef=10000,              # Extremely slow queries
        ef_construction=1000,  # Very slow indexing
        max_connections=512    # Massive memory usage
    )
)

# VULNERABLE: No limits on query parameters
def query(collection, query_vector, top_k):
    return collection.query.near_vector(
        near_vector=query_vector,
        limit=top_k  # User can request top_k=1000000
    )
```

**Why**: HNSW parameters directly impact memory usage and query latency. Excessively high values can cause out-of-memory errors, slow queries that block other operations, or enable denial-of-service attacks through resource exhaustion.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Rule: Backup and Restore Security

**Level**: `strict`

**When**: Creating backups to S3, GCS, or filesystem backends

**Do**: Enable encryption at rest, use secure credentials, verify backup integrity

```python
import weaviate
import hashlib
import os

# S3 backup with server-side encryption
def configure_s3_backup(client):
    """Configure encrypted S3 backup backend."""
    # Set via environment variables in Weaviate config
    """
    BACKUP_S3_BUCKET: 'weaviate-backups'
    BACKUP_S3_PATH: 'production'
    BACKUP_S3_ENDPOINT: 's3.amazonaws.com'
    BACKUP_S3_USE_SSL: 'true'

    # IAM role or access keys (prefer IAM roles)
    AWS_ACCESS_KEY_ID: '${AWS_ACCESS_KEY_ID}'
    AWS_SECRET_ACCESS_KEY: '${AWS_SECRET_ACCESS_KEY}'
    AWS_REGION: 'us-east-1'
    """
    pass

# Create backup with audit logging
def create_secure_backup(client, backup_id: str, collections: list = None):
    """Create backup with security controls."""
    import structlog
    logger = structlog.get_logger()

    # Validate backup_id format
    if not backup_id.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Invalid backup_id format")

    # Create backup
    result = client.backup.create(
        backup_id=backup_id,
        backend="s3",
        include_collections=collections,  # None = all collections
        wait_for_completion=True
    )

    # Log backup creation for audit
    logger.info(
        "backup_created",
        backup_id=backup_id,
        backend="s3",
        collections=collections or "all",
        status=result.status
    )

    return result

# Restore with integrity verification
def restore_secure_backup(client, backup_id: str, expected_collections: list):
    """Restore backup with verification."""
    import structlog
    logger = structlog.get_logger()

    # Verify backup exists and is complete
    status = client.backup.get_create_status(
        backup_id=backup_id,
        backend="s3"
    )

    if status.status != "SUCCESS":
        raise ValueError(f"Backup {backup_id} not in SUCCESS state")

    # Restore
    result = client.backup.restore(
        backup_id=backup_id,
        backend="s3",
        include_collections=expected_collections,
        wait_for_completion=True
    )

    # Verify restored collections
    restored = client.collections.list_all().keys()
    for collection in expected_collections:
        if collection not in restored:
            logger.error("restore_incomplete", missing=collection)
            raise IntegrityError(f"Collection {collection} not restored")

    logger.info(
        "backup_restored",
        backup_id=backup_id,
        collections=expected_collections
    )

    return result

# GCS backup configuration
"""
BACKUP_GCS_BUCKET: 'weaviate-backups'
BACKUP_GCS_PATH: 'production'
BACKUP_GCS_USE_AUTH: 'true'
GOOGLE_APPLICATION_CREDENTIALS: '/secrets/gcp-sa.json'
"""

# Filesystem backup with encryption wrapper
def create_encrypted_local_backup(client, backup_id: str, encryption_key: bytes):
    """Create locally encrypted backup."""
    from cryptography.fernet import Fernet

    # Create backup to local filesystem
    result = client.backup.create(
        backup_id=backup_id,
        backend="filesystem",
        wait_for_completion=True
    )

    # Encrypt backup files
    backup_path = f"/var/lib/weaviate/backups/{backup_id}"
    fernet = Fernet(encryption_key)

    for root, dirs, files in os.walk(backup_path):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, "rb") as f:
                encrypted = fernet.encrypt(f.read())
            with open(filepath, "wb") as f:
                f.write(encrypted)

    return result
```

**Don't**: Store unencrypted backups or use insecure storage configurations

```python
# VULNERABLE: Unencrypted S3 bucket
"""
BACKUP_S3_BUCKET: 'public-bucket'
BACKUP_S3_USE_SSL: 'false'  # Unencrypted transfer
"""

# VULNERABLE: No access controls on backup
def create_backup(client, backup_id):
    return client.backup.create(
        backup_id=backup_id,
        backend="filesystem"  # No encryption, world-readable
    )

# VULNERABLE: Hardcoded credentials
"""
AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
"""
```

**Why**: Backups contain complete database contents including all vectors and metadata. Unencrypted backups can be exfiltrated from storage. Without integrity verification, corrupted or tampered backups may be restored.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, CWE-312, CWE-798

---

## Rule: Multi-Vector Support Security

**Level**: `warning`

**When**: Using named vectors for multiple embeddings per object

**Do**: Implement access control for individual named vectors

```python
import weaviate.classes as wvc
from weaviate.classes.config import Configure, Property, DataType

# Collection with multiple named vectors
client.collections.create(
    name="MultiModalDocs",
    vectorizer_config=[
        # Different vectors for different content types
        Configure.NamedVectors.none(
            name="text_vector",
            vector_index_config=Configure.VectorIndex.hnsw()
        ),
        Configure.NamedVectors.none(
            name="image_vector",
            vector_index_config=Configure.VectorIndex.hnsw()
        ),
        Configure.NamedVectors.none(
            name="summary_vector",
            vector_index_config=Configure.VectorIndex.hnsw()
        )
    ],
    properties=[
        Property(name="content", data_type=DataType.TEXT),
        Property(name="tenant_id", data_type=DataType.TEXT),
        Property(name="vector_access_level", data_type=DataType.TEXT)
    ],
    multi_tenancy_config=Configure.multi_tenancy(enabled=True)
)

# Query with named vector access control
def query_named_vector(
    collection,
    tenant_id: str,
    user_permissions: list,
    vector_name: str,
    query_vector: list,
    top_k: int = 10
):
    """Query specific named vector with access control."""
    # Define vector access requirements
    VECTOR_PERMISSIONS = {
        "text_vector": "read:text",
        "image_vector": "read:image",
        "summary_vector": "read:summary"
    }

    # Check permission for requested vector
    required_permission = VECTOR_PERMISSIONS.get(vector_name)
    if required_permission not in user_permissions:
        raise PermissionError(f"No access to {vector_name}")

    with collection.with_tenant(tenant_id) as tenant_collection:
        results = tenant_collection.query.near_vector(
            near_vector=query_vector,
            target_vector=vector_name,  # Query specific named vector
            limit=min(top_k, 100),
            return_metadata=wvc.query.MetadataQuery(distance=True)
        )

    return results

# Hybrid query with multiple vectors
def secure_hybrid_query(
    collection,
    tenant_id: str,
    user_permissions: list,
    vectors: dict,  # {"text_vector": [...], "image_vector": [...]}
    top_k: int = 10
):
    """Query multiple named vectors with permission checks."""
    # Verify permissions for all requested vectors
    for vector_name in vectors.keys():
        required = f"read:{vector_name.replace('_vector', '')}"
        if required not in user_permissions:
            raise PermissionError(f"No access to {vector_name}")

    with collection.with_tenant(tenant_id) as tenant_collection:
        # Query with combined vectors
        results = tenant_collection.query.near_vector(
            near_vector=vectors,
            limit=min(top_k, 100)
        )

    return results
```

**Don't**: Allow unrestricted access to all named vectors

```python
# VULNERABLE: No access control for named vectors
def query_any_vector(collection, vector_name, query_vector):
    # User can query any named vector without permission
    return collection.query.near_vector(
        near_vector=query_vector,
        target_vector=vector_name  # No permission check
    )

# VULNERABLE: Exposing all vector names to client
def get_available_vectors(collection):
    config = collection.config.get()
    # Returns all vectors including restricted ones
    return [v.name for v in config.vector_config]
```

**Why**: Named vectors may contain embeddings with different sensitivity levels (e.g., PII in text vs. public image embeddings). Without per-vector access control, users may access embeddings they shouldn't see.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Module Configuration

**Level**: `warning`

**When**: Configuring text2vec, img2vec, or other Weaviate modules

**Do**: Secure API keys for external services, validate module inputs

```python
import weaviate
from weaviate.auth import AuthApiKey
import os

# Secure OpenAI module configuration
"""
services:
  weaviate:
    environment:
      # Module configuration
      ENABLE_MODULES: 'text2vec-openai,generative-openai'
      DEFAULT_VECTORIZER_MODULE: 'text2vec-openai'

      # API key from secret management
      OPENAI_APIKEY: '${OPENAI_API_KEY}'  # From secrets manager

      # Rate limiting for API calls
      OPENAI_ORGANIZATION: '${OPENAI_ORG_ID}'
"""

# Client configuration with module headers
client = weaviate.connect_to_custom(
    http_host=os.environ["WEAVIATE_HOST"],
    http_port=8080,
    http_secure=True,
    grpc_host=os.environ["WEAVIATE_GRPC_HOST"],
    grpc_port=50051,
    grpc_secure=True,
    auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
    headers={
        "X-OpenAI-Api-Key": os.environ["OPENAI_API_KEY"]
    }
)

# Collection with secure vectorizer config
from weaviate.classes.config import Configure, Property, DataType

client.collections.create(
    name="Documents",
    vectorizer_config=Configure.Vectorizer.text2vec_openai(
        model="text-embedding-3-small",
        vectorize_collection_name=False  # Don't leak collection names
    ),
    properties=[
        Property(
            name="content",
            data_type=DataType.TEXT,
            vectorize_property_name=False,  # Don't vectorize field names
            tokenization=wvc.config.Tokenization.WORD
        ),
        Property(
            name="tenant_id",
            data_type=DataType.TEXT,
            skip_vectorization=True  # Never send to external API
        ),
        Property(
            name="internal_id",
            data_type=DataType.TEXT,
            skip_vectorization=True  # Sensitive metadata
        )
    ]
)

# Validate content before vectorization
def secure_insert(collection, tenant_id: str, content: str, metadata: dict):
    """Insert with content validation."""
    # Size limits to prevent API abuse
    if len(content) > 50000:
        raise ValueError("Content exceeds maximum length")

    # Sanitize content sent to external vectorizer
    sanitized_content = sanitize_for_vectorization(content)

    with collection.with_tenant(tenant_id) as tenant_collection:
        tenant_collection.data.insert(
            properties={
                "content": sanitized_content,
                "tenant_id": tenant_id,
                **metadata
            }
        )

def sanitize_for_vectorization(content: str) -> str:
    """Remove sensitive patterns before sending to external API."""
    import re

    # Remove potential PII patterns
    patterns = [
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),      # SSN
        (r'\b\d{16}\b', '[CARD]'),                  # Credit card
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]')
    ]

    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)

    return content
```

**Don't**: Expose API keys or send sensitive data to external vectorizers

```python
# VULNERABLE: Hardcoded API key
"""
OPENAI_APIKEY: 'sk-proj-abc123xyz'
"""

# VULNERABLE: API key in client code
client = weaviate.connect_to_custom(
    http_host="weaviate.example.com",
    headers={
        "X-OpenAI-Api-Key": "sk-proj-abc123xyz"  # Leaked in code
    }
)

# VULNERABLE: Sending PII to external vectorizer
collection.data.insert(
    properties={
        "content": f"SSN: {ssn}, Name: {name}",  # Sent to OpenAI
        "tenant_id": tenant_id
    }
)

# VULNERABLE: No content size limits
def insert_document(collection, content):
    # Attacker can send huge content to exhaust API quota
    collection.data.insert(properties={"content": content})
```

**Why**: External vectorization modules send data to third-party APIs. Exposed API keys can be abused for unauthorized usage. Sensitive data sent to external services may be logged or retained by the provider.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-798, CWE-200 (Exposure of Sensitive Information)

---

## Rule: Kubernetes Deployment Security

**Level**: `strict`

**When**: Deploying Weaviate on Kubernetes

**Do**: Implement network policies, RBAC, and secure pod configuration

```yaml
# Network Policy - Restrict Weaviate access
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: weaviate-network-policy
  namespace: weaviate
spec:
  podSelector:
    matchLabels:
      app: weaviate
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow only from application pods
    - from:
        - namespaceSelector:
            matchLabels:
              name: application
          podSelector:
            matchLabels:
              role: weaviate-client
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 50051
    # Allow cluster internal traffic for replication
    - from:
        - podSelector:
            matchLabels:
              app: weaviate
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 50051
  egress:
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
    # Allow S3 for backups (if using AWS)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443

---
# RBAC - Least privilege for Weaviate service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: weaviate
  namespace: weaviate

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: weaviate-role
  namespace: weaviate
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: weaviate-rolebinding
  namespace: weaviate
subjects:
  - kind: ServiceAccount
    name: weaviate
roleRef:
  kind: Role
  name: weaviate-role
  apiGroup: rbac.authorization.k8s.io

---
# Secure Pod configuration
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: weaviate
  namespace: weaviate
spec:
  template:
    spec:
      serviceAccountName: weaviate
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: weaviate
          image: cr.weaviate.io/semitechnologies/weaviate:latest
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              memory: "8Gi"
              cpu: "4"
            requests:
              memory: "4Gi"
              cpu: "2"
          env:
            - name: AUTHENTICATION_APIKEY_ENABLED
              value: "true"
            - name: AUTHENTICATION_APIKEY_ALLOWED_KEYS
              valueFrom:
                secretKeyRef:
                  name: weaviate-secrets
                  key: api-key
            - name: AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED
              value: "false"
          volumeMounts:
            - name: data
              mountPath: /var/lib/weaviate
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: encrypted-gp3
        resources:
          requests:
            storage: 100Gi

---
# Secret for API keys (should be managed by external secrets operator)
apiVersion: v1
kind: Secret
metadata:
  name: weaviate-secrets
  namespace: weaviate
type: Opaque
stringData:
  api-key: "${WEAVIATE_API_KEY}"  # Inject from secrets manager
```

**Don't**: Deploy with default settings, no network policies, or excessive permissions

```yaml
# VULNERABLE: No network policy - accessible from anywhere
apiVersion: v1
kind: Service
metadata:
  name: weaviate
spec:
  type: LoadBalancer  # Exposed to internet without protection

---
# VULNERABLE: Running as root with excessive privileges
spec:
  containers:
    - name: weaviate
      securityContext:
        privileged: true
        runAsUser: 0  # Root

---
# VULNERABLE: No resource limits - enables DoS
spec:
  containers:
    - name: weaviate
      # No resource limits

---
# VULNERABLE: Secrets in plain ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: weaviate-config
data:
  AUTHENTICATION_APIKEY_ALLOWED_KEYS: "my-secret-key"  # Exposed
```

**Why**: Kubernetes misconfigurations are a leading cause of cloud breaches. Without network policies, any pod can access Weaviate. Running as root allows container escapes. Missing resource limits enable denial of service.

**Refs**: OWASP A05:2025 (Security Misconfiguration), CWE-250 (Execution with Unnecessary Privileges), CWE-732

---

## Rule: Replication Security

**Level**: `warning`

**When**: Configuring Weaviate cluster replication

**Do**: Secure inter-node communication, authenticate cluster membership

```python
# Weaviate cluster configuration with security
"""
services:
  weaviate-node-1:
    image: cr.weaviate.io/semitechnologies/weaviate:latest
    environment:
      CLUSTER_HOSTNAME: 'node1'
      CLUSTER_GOSSIP_BIND_PORT: '7100'
      CLUSTER_DATA_BIND_PORT: '7101'

      # TLS for inter-node communication
      CLUSTER_TLS_ENABLED: 'true'
      CLUSTER_TLS_CERT: '/certs/node.crt'
      CLUSTER_TLS_KEY: '/certs/node.key'
      CLUSTER_TLS_CA: '/certs/ca.crt'

      # Authentication required for cluster join
      CLUSTER_AUTH_TOKEN: '${CLUSTER_AUTH_TOKEN}'

      # Replication configuration
      REPLICATION_FACTOR: '3'

      # Standard auth
      AUTHENTICATION_APIKEY_ENABLED: 'true'
      AUTHENTICATION_APIKEY_ALLOWED_KEYS: '${WEAVIATE_API_KEY}'
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: 'false'
    volumes:
      - ./certs:/certs:ro
"""

# Python client - Configure collection with replication
import weaviate.classes as wvc
from weaviate.classes.config import Configure

client.collections.create(
    name="ReplicatedDocs",
    vectorizer_config=Configure.Vectorizer.none(),
    replication_config=Configure.replication(
        factor=3  # 3 copies across cluster
    ),
    sharding_config=Configure.sharding(
        virtual_per_physical=128,
        desired_count=3
    ),
    properties=[
        wvc.config.Property(name="content", data_type=wvc.config.DataType.TEXT),
        wvc.config.Property(name="tenant_id", data_type=wvc.config.DataType.TEXT)
    ]
)

# Monitor replication health
def check_replication_health(client, collection_name: str):
    """Verify replication is healthy and consistent."""
    import structlog
    logger = structlog.get_logger()

    # Get cluster status
    nodes = client.cluster.get_nodes_status()

    unhealthy = [n for n in nodes if n.status != "HEALTHY"]
    if unhealthy:
        logger.warning(
            "unhealthy_nodes",
            nodes=[n.name for n in unhealthy]
        )
        return False

    # Verify collection is replicated correctly
    config = client.collections.get(collection_name).config.get()
    expected_factor = config.replication_config.factor

    # Check shard distribution
    shards = client.collections.get(collection_name).shards()
    for shard in shards:
        if len(shard.replicas) < expected_factor:
            logger.error(
                "insufficient_replicas",
                shard=shard.name,
                expected=expected_factor,
                actual=len(shard.replicas)
            )
            return False

    return True

# Secure node join verification
def verify_cluster_membership(client, expected_nodes: list):
    """Verify only expected nodes are in cluster."""
    nodes = client.cluster.get_nodes_status()
    node_names = {n.name for n in nodes}
    expected = set(expected_nodes)

    unexpected = node_names - expected
    if unexpected:
        raise SecurityError(f"Unexpected nodes in cluster: {unexpected}")

    missing = expected - node_names
    if missing:
        raise AvailabilityError(f"Expected nodes missing: {missing}")

    return True
```

**Don't**: Use unencrypted cluster communication or allow unauthenticated node joins

```yaml
# VULNERABLE: No TLS for cluster communication
CLUSTER_TLS_ENABLED: 'false'  # Plaintext replication traffic

# VULNERABLE: No cluster authentication
# Any node can join the cluster
CLUSTER_AUTH_TOKEN: ''

# VULNERABLE: Cluster ports exposed externally
ports:
  - "7100:7100"  # Gossip port on host
  - "7101:7101"  # Data port on host
```

```python
# VULNERABLE: No replication health monitoring
def query(collection, query_vector):
    # Query without checking cluster health
    # May return stale or inconsistent results
    return collection.query.near_vector(near_vector=query_vector)
```

**Why**: Unencrypted cluster traffic can be intercepted to steal data or inject malicious updates. Without authentication, attackers can join rogue nodes to the cluster. Unhealthy replication leads to data loss or inconsistency.

**Refs**: OWASP A02:2025 (Cryptographic Failures), OWASP A07:2025 (Identification and Authentication Failures), CWE-319, CWE-306

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 security rules |

---

## Additional Resources

- [Weaviate Security Documentation](https://weaviate.io/developers/weaviate/configuration/authentication)
- [Weaviate Kubernetes Deployment](https://weaviate.io/developers/weaviate/installation/kubernetes)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Vector Store Security Core Rules](../../_core/vector-store-security.md)
