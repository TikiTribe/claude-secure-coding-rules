# Milvus Security Rules

Security rules for self-hosted Milvus vector database deployments.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| RBAC Enablement | `strict` | All requests accepted regardless of user or role |
| Connection Security | `strict` | Data interception, unauthorized access |
| Mutual TLS | `strict` | Unauthenticated client access to gRPC port |
| Collection Isolation | `strict` | Cross-tenant data leakage |
| Partition Isolation Trade-offs | `warning` | expr filter bypass, weaker tenant boundary |
| Partition Security | `warning` | Unauthorized partition access |
| Etcd Metadata Store Security | `warning` | Credential theft, collection enumeration |
| MinIO/S3 Storage Access Control | `warning` | Vector segment exfiltration via object storage |
| GPU Resource Security | `warning` | Resource exhaustion, isolation bypass |
| Index Configuration Security | `warning` | DoS via resource exhaustion |
| Expression Filter Injection | `strict` | Filter bypass, data exfiltration |
| Bulk Insert Security | `warning` | Resource exhaustion, data integrity |
| Attu Dashboard Security | `strict` | Administrative access compromise |

---

## Rule: RBAC Enablement

**Level**: `strict`

**When**: Deploying any self-hosted Milvus instance

**Do**: Enable authorization in `milvus.yaml` before the instance accepts traffic, then create roles and grant privileges using pymilvus RBAC primitives

```yaml
# milvus.yaml — authorization is OFF by default; this line must be present
common:
  security:
    authorizationEnabled: true   # REQUIRED: default is false
    # TLS mode is set separately; see the Mutual TLS rule
    tlsMode: 1   # 1 = one-way TLS; 2 = mTLS
```

```python
from pymilvus import connections, utility, Role
import os

def bootstrap_milvus_rbac():
    """
    Run once after enabling authorizationEnabled: true.
    Creates application roles with least-privilege grants.
    """
    connections.connect(
        alias="admin",
        uri=os.environ["MILVUS_URI"],
        token=os.environ["MILVUS_ADMIN_TOKEN"],
        secure=True,
        server_pem_path=os.environ["MILVUS_SERVER_CERT"],
    )

    # --- reader role: query only ---
    reader = Role("reader", using="admin")
    reader.create()
    # Grant Search and Query on every collection in the default database
    reader.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="Search",
    )
    reader.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="Query",
    )

    # --- writer role: insert + flush ---
    writer = Role("writer", using="admin")
    writer.create()
    writer.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="Insert",
    )
    writer.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="Flush",
    )

    # --- collection-admin role: DDL on owned collection only ---
    col_admin = Role("collection_admin", using="admin")
    col_admin.create()
    col_admin.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="CreateCollection",
    )
    col_admin.grant_privilege(
        object_type="Collection",
        object_name="*",
        privilege="DropCollection",
    )

    # Assign application service accounts to roles
    reader.add_user(os.environ["MILVUS_READER_USER"])
    writer.add_user(os.environ["MILVUS_WRITER_USER"])
    col_admin.add_user(os.environ["MILVUS_ADMIN_USER"])

    utility.disconnect("admin")


def verify_rbac_enabled():
    """Fail fast if authorization is off — skip all access-control rules otherwise."""
    connections.connect(
        alias="probe",
        uri=os.environ["MILVUS_URI"],
        secure=True,
    )
    try:
        # An unauthenticated listing of roles succeeds only when auth is disabled
        Role("_probe_role", using="probe").create()
        # If we reach here, auth is disabled — hard stop
        raise RuntimeError(
            "Milvus authorizationEnabled is false. "
            "Set common.security.authorizationEnabled: true in milvus.yaml and restart."
        )
    except Exception as exc:
        if "authorizationEnabled" in str(exc):
            raise
        # Expected: permission denied when auth is on
    finally:
        utility.disconnect("probe")
```

**Don't**: Deploy Milvus without enabling authorization — access-control rules in application code are decorative when the server accepts every request

```python
# VULNERABLE: authorizationEnabled not set (defaults to false)
# Any client that can reach port 19530 has full admin access.

# VULNERABLE: placeholder permission check with no server-enforced grants
def check_partition_permission(user_id, collection, action):
    return auth_service.check_permission(user_id, ...)
# auth_service is application-layer only; Milvus ignores it entirely.
```

**Why**: Milvus self-hosted ships with `common.security.authorizationEnabled: false`. Every access-control pattern in this file — role checks, collection isolation, partition guards — relies on the server enforcing RBAC. Without the server flag, Milvus accepts unauthenticated requests from any client on the network.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures), CWE-284, CWE-306

---

## Rule: Connection Security

**Level**: `strict`

**When**: Establishing connections to Milvus clusters

**Do**: Configure TLS encryption, enable authentication, use token management with rotation

```python
from pymilvus import connections, utility
import os

def connect_milvus_secure():
    """Establish secure connection to Milvus with TLS and auth."""
    connections.connect(
        alias="default",
        host=os.environ["MILVUS_HOST"],
        port=os.environ.get("MILVUS_PORT", "19530"),
        user=os.environ["MILVUS_USER"],
        password=os.environ["MILVUS_PASSWORD"],
        secure=True,                                         # Enable TLS
        server_pem_path=os.environ["MILVUS_SERVER_CERT"],   # Verify server identity
        server_name=os.environ["MILVUS_SERVER_NAME"],
        timeout=30,
    )

    if not utility.has_collection("_health_check"):
        print("Connected to Milvus securely")

    return connections.get_connection_addr("default")


def connect_with_token():
    """Connect using token authentication (Milvus 2.3+)."""
    connections.connect(
        alias="default",
        uri=os.environ["MILVUS_URI"],
        token=os.environ["MILVUS_TOKEN"],   # From secret management
        secure=True,
        server_pem_path=os.environ["MILVUS_SERVER_CERT"],
    )


class MilvusConnectionPool:
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections

    def get_connection(self):
        """Get connection with health validation."""
        try:
            utility.list_collections()
            return connections.get_connection_addr("default")
        except Exception:
            self._reconnect()
            return connections.get_connection_addr("default")

    def _reconnect(self):
        connections.disconnect("default")
        connect_milvus_secure()
```

**Don't**: Use unencrypted connections or hardcode credentials

```python
# VULNERABLE: No TLS, no authentication
connections.connect(host="milvus.internal", port="19530")

# VULNERABLE: Hardcoded credentials
connections.connect(host="milvus.example.com", user="admin", password="admin123", secure=False)

# VULNERABLE: TLS enabled but no server cert — susceptible to MITM
connections.connect(host=os.environ["MILVUS_HOST"], secure=True)
```

**Why**: Unencrypted Milvus connections expose vector data, queries, and credentials to network interception. Without authentication, any network access allows full database control. Missing certificate validation enables man-in-the-middle attacks.

**Refs**: OWASP A02:2025 (Cryptographic Failures), OWASP A07:2025 (Identification and Authentication Failures), CWE-319, CWE-798

---

## Rule: Mutual TLS

**Level**: `strict`

**When**: Operating self-hosted Milvus where clients must be authenticated at the transport layer

**Do**: Set `tlsMode: 2` in `milvus.yaml` and supply client certificate parameters in `connections.connect()`

```yaml
# milvus.yaml — mutual TLS (both sides present certificates)
common:
  security:
    tlsMode: 2            # 0 = off, 1 = one-way, 2 = mutual TLS
    serverPemPath: /tls/server.pem
    serverKeyPath: /tls/server.key
    caPemPath: /tls/ca.pem    # CA that signed client certs
```

```python
from pymilvus import connections
import os

def connect_mtls():
    """
    Mutual TLS: the server verifies the client certificate in addition to
    the client verifying the server certificate.  Requires tlsMode: 2 in
    milvus.yaml and a CA-signed client cert/key pair.
    """
    connections.connect(
        alias="default",
        host=os.environ["MILVUS_HOST"],
        port=os.environ.get("MILVUS_PORT", "19530"),
        user=os.environ["MILVUS_USER"],
        password=os.environ["MILVUS_PASSWORD"],
        secure=True,
        # Server identity
        server_pem_path=os.environ["MILVUS_SERVER_CERT"],
        server_name=os.environ["MILVUS_SERVER_NAME"],
        # Client identity — required for mTLS (tlsMode: 2)
        client_pem_path=os.environ["MILVUS_CLIENT_CERT"],
        client_key_path=os.environ["MILVUS_CLIENT_KEY"],
    )
```

**Don't**: Rely on one-way TLS alone for high-assurance environments — any credential-holding client can authenticate regardless of machine identity

```python
# VULNERABLE: one-way TLS only; tlsMode: 1 in milvus.yaml
# Any client that holds a valid username/password and can reach port 19530
# is accepted, regardless of whether it is a trusted machine.
connections.connect(
    host=os.environ["MILVUS_HOST"],
    secure=True,
    server_pem_path=os.environ["MILVUS_SERVER_CERT"],
    # No client_pem_path / client_key_path
)
```

**Why**: One-way TLS verifies the server but not the client. With mTLS (`tlsMode: 2`) the Milvus gRPC layer rejects connections from any machine that cannot present a certificate signed by the trusted CA, eliminating stolen-credential replay from untrusted hosts.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-295, CWE-319

---

## Rule: Collection Isolation

**Level**: `strict`

**When**: Storing vectors from multiple tenants or applications

**Do**: Create separate collections per tenant with validated naming conventions

```python
from pymilvus import Collection, CollectionSchema, FieldSchema, DataType, utility
import re

TENANT_COLLECTION_PATTERN = re.compile(r'^tenant_[a-zA-Z0-9_]{1,64}_vectors$')

def get_tenant_collection_name(tenant_id: str) -> str:
    """Generate and validate tenant collection name."""
    if not re.match(r'^[a-zA-Z0-9_]{1,64}$', tenant_id):
        raise ValueError(f"Invalid tenant_id format: {tenant_id}")

    collection_name = f"tenant_{tenant_id}_vectors"

    if not TENANT_COLLECTION_PATTERN.match(collection_name):
        raise ValueError(f"Invalid collection name generated: {collection_name}")

    return collection_name


def create_tenant_collection(tenant_id: str, dimension: int = 1536):
    """Create isolated collection for tenant."""
    collection_name = get_tenant_collection_name(tenant_id)

    if utility.has_collection(collection_name):
        raise ValueError(f"Collection for tenant {tenant_id} already exists")

    fields = [
        FieldSchema(name="id", dtype=DataType.VARCHAR, is_primary=True, max_length=128),
        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=dimension),
        FieldSchema(name="tenant_id", dtype=DataType.VARCHAR, max_length=64),
        FieldSchema(name="doc_id", dtype=DataType.VARCHAR, max_length=256),
        FieldSchema(name="content", dtype=DataType.VARCHAR, max_length=65535),
        FieldSchema(name="created_at", dtype=DataType.INT64),
    ]

    schema = CollectionSchema(
        fields=fields,
        description=f"Vector collection for tenant {tenant_id}",
        enable_dynamic_field=False,   # Disable dynamic fields for security
    )

    collection = Collection(name=collection_name, schema=schema)
    collection.create_index("embedding", {
        "metric_type": "COSINE",
        "index_type": "IVF_FLAT",
        "params": {"nlist": 1024},
    })

    return collection


def get_tenant_collection(tenant_id: str) -> Collection:
    """Get collection for tenant with existence validation."""
    collection_name = get_tenant_collection_name(tenant_id)

    if not utility.has_collection(collection_name):
        raise PermissionError(f"Tenant {tenant_id} not provisioned or unauthorized")

    return Collection(collection_name)


def insert_tenant_vectors(tenant_id: str, vectors: list):
    """Insert vectors into tenant-specific collection."""
    collection = get_tenant_collection(tenant_id)

    for vec in vectors:
        if vec.get("tenant_id") != tenant_id:
            raise ValueError("Vector tenant_id mismatch")

    collection.insert(vectors)
    collection.flush()
```

**Don't**: Mix tenant data in shared collections or use predictable collection names

```python
# VULNERABLE: All tenants in one collection — filter bypass exposes all data
def store_vector(tenant_id, embedding, content):
    collection = Collection("shared_vectors")
    collection.insert([{"embedding": embedding, "content": content, "tenant_id": tenant_id}])

# VULNERABLE: Predictable names enable enumeration
def get_collection(tenant_id):
    return Collection(tenant_id)

# VULNERABLE: No validation on tenant access
def query_tenant(collection_name, query_vector):
    return Collection(collection_name).search(query_vector)
```

**Why**: Shared collections rely on filter enforcement which can be bypassed. Separate collections provide database-level isolation. Predictable naming enables enumeration attacks.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Partition Isolation Trade-offs

**Level**: `warning`

**When**: Choosing between `partition_key_field` multi-tenancy and collection-per-tenant isolation

**Do**: Understand the security boundary each pattern provides and choose collection-per-tenant for strict isolation

```python
from pymilvus import Collection, CollectionSchema, FieldSchema, DataType

# PATTERN A — partition_key_field (Milvus 2.2.9+)
# Milvus automatically routes documents into internal partitions based on the field value.
# Simpler to operate: one collection, no manual partition management.
# WEAKER isolation: all tenant data shares the same collection; partition routing
# is a performance optimisation, not a security boundary.

def create_shared_collection_with_partition_key(dimension: int = 1536):
    """
    Use partition_key_field only when ALL tenants are equally trusted
    (e.g., internal business units, not external customers).
    """
    fields = [
        FieldSchema(name="id", dtype=DataType.VARCHAR, is_primary=True, max_length=128),
        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=dimension),
        FieldSchema(
            name="tenant_id",
            dtype=DataType.VARCHAR,
            max_length=64,
            is_partition_key=True,   # Routes to internal partition by value
        ),
        FieldSchema(name="content", dtype=DataType.VARCHAR, max_length=65535),
    ]
    schema = CollectionSchema(fields=fields, enable_dynamic_field=False)
    return Collection(name="shared_with_pk", schema=schema)


# PATTERN B — collection-per-tenant (recommended for external tenants)
# Hard isolation at the collection level; RBAC grants are scoped per collection.
# An expr injection in tenant A's query cannot read tenant B's collection.

# Bypass risk with partition_key_field:
# An attacker who controls the expr filter can omit or override the tenant_id
# predicate and retrieve documents from other tenants' partitions:
#
#   expr = 'content like "%secret%"'   # No tenant_id filter — reads all partitions
#
# With collection-per-tenant the attacker would need a separate RBAC grant to
# open a different collection, which the server enforces independently of expr.

ISOLATION_GUIDANCE = {
    "partition_key_field": {
        "use_when": "Tenants are equally trusted (internal teams, same organisation)",
        "avoid_when": "External customers, regulated data, different trust levels",
        "bypass_risk": "expr filter without tenant_id predicate reads all partitions",
    },
    "collection_per_tenant": {
        "use_when": "External tenants, strict data isolation required, regulated data",
        "advantage": "Server-enforced RBAC boundary; expr injection cannot cross tenants",
        "trade_off": "More operational overhead; schema changes must be applied per collection",
    },
}


def enforce_tenant_filter(tenant_id: str, user_expr: str) -> str:
    """
    When partition_key_field is unavoidable, always prepend the tenant predicate
    and validate it cannot be removed by expression injection.
    """
    if not tenant_id or not tenant_id.replace("_", "").isalnum():
        raise ValueError("Invalid tenant_id")

    tenant_clause = f'tenant_id == "{tenant_id}"'

    if user_expr:
        combined = f'({tenant_clause}) && ({user_expr})'
    else:
        combined = tenant_clause

    # Verify tenant clause survived construction
    if tenant_clause not in combined:
        raise ValueError("Tenant isolation predicate was removed during expression build")

    return combined
```

**Don't**: Use `partition_key_field` for external tenants and assume Milvus enforces the partition boundary at query time

```python
# VULNERABLE: partition_key_field treated as a security boundary
# An expr filter that omits tenant_id reads across all internal partitions.

def search_tenant_data(collection, tenant_id, query_vector, user_filter):
    # If user_filter = 'content like "%confidential%"' with no tenant_id,
    # Milvus searches all partitions regardless of partition_key routing.
    results = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=10,
        expr=user_filter,   # tenant_id not enforced in expr
    )
    return results
```

**Why**: `partition_key_field` is a performance routing mechanism, not a security boundary. An expr filter that omits the tenant predicate scans all internal partitions. Collection-per-tenant with RBAC grants is the only pattern where the server independently enforces the isolation boundary.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Partition Security

**Level**: `warning`

**When**: Using Milvus partitions for data organisation within collections

**Do**: Validate partition keys, implement access-control checks before partition operations

```python
from pymilvus import Collection, Partition
import re

ALLOWED_PARTITION_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,128}$')


def validate_partition_name(partition_name: str) -> bool:
    """Validate partition name format."""
    if not ALLOWED_PARTITION_PATTERN.match(partition_name):
        raise ValueError(f"Invalid partition name: {partition_name}")

    if partition_name.startswith("_"):
        raise ValueError("Cannot access internal partitions")

    return True


def create_partition_secure(collection: Collection, partition_name: str, user_id: str):
    """Create partition with access control."""
    validate_partition_name(partition_name)

    if not check_partition_permission(user_id, collection.name, "create"):
        raise PermissionError("User not authorized to create partitions")

    if collection.has_partition(partition_name):
        raise ValueError(f"Partition {partition_name} already exists")

    partition = Partition(collection, partition_name)

    audit_log.info(
        "partition_created",
        collection=collection.name,
        partition=partition_name,
        user_id=user_id,
    )

    return partition


def search_in_partition(
    collection: Collection,
    partition_names: list,
    query_vector: list,
    user_id: str,
    top_k: int = 10,
):
    """Search within specific partitions with access validation."""
    for name in partition_names:
        validate_partition_name(name)

        if not collection.has_partition(name):
            raise ValueError(f"Partition {name} does not exist")

        if not check_partition_permission(user_id, collection.name, "search", name):
            raise PermissionError(f"User not authorized for partition {name}")

    return collection.search(
        data=[query_vector],
        anns_field="embedding",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=top_k,
        partition_names=partition_names,
    )


def check_partition_permission(user_id: str, collection: str, action: str, partition: str = None) -> bool:
    """Check user permission for partition operations via your authorisation layer."""
    return auth_service.check_permission(user_id, f"{collection}:{partition}:{action}")
```

**Don't**: Allow unrestricted partition access or skip validation

```python
# VULNERABLE: No partition name validation
def create_partition(collection, user_partition_name):
    Partition(collection, user_partition_name)

# VULNERABLE: No access control
def search_partitions(collection, partition_names, query):
    return collection.search(data=[query], partition_names=partition_names)

# VULNERABLE: Exposes internal partitions
def list_all_partitions(collection):
    return collection.partitions
```

**Why**: Partitions can contain sensitive data subsets. Without access control, users can access partitions they should not reach. Invalid partition names can cause errors or access internal system partitions.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-20

---

## Rule: Etcd Metadata Store Security

**Level**: `warning`

**When**: Deploying self-hosted Milvus, which uses etcd as its metadata store

**Do**: Enable etcd authentication, restrict port 2379 to Milvus pods only, and configure etcd with role-based access

```bash
# Step 1: Enable etcd root authentication
etcdctl user add root --new-user-password="${ETCD_ROOT_PASSWORD}"
etcdctl auth enable

# Step 2: Create a dedicated Milvus user with least-privilege access
etcdctl --user="root:${ETCD_ROOT_PASSWORD}" user add milvus --new-user-password="${ETCD_MILVUS_PASSWORD}"
etcdctl --user="root:${ETCD_ROOT_PASSWORD}" role add milvus-role
etcdctl --user="root:${ETCD_ROOT_PASSWORD}" role grant-permission milvus-role readwrite "/by-dev/" --prefix
etcdctl --user="root:${ETCD_ROOT_PASSWORD}" user grant-role milvus milvus-role

# Step 3: Test access is restricted (this should fail)
etcdctl --user="milvus:${ETCD_MILVUS_PASSWORD}" get /other-prefix/ --prefix
```

```yaml
# milvus.yaml — connect Milvus to authenticated etcd
etcd:
  endpoints:
    - etcd.milvus-namespace.svc.cluster.local:2379   # Internal DNS only
  username: milvus
  password: "${ETCD_MILVUS_PASSWORD}"     # Sourced from Kubernetes Secret
  ssl:
    enabled: true
    tlsCert: /tls/etcd-client.pem
    tlsKey: /tls/etcd-client.key
    tlsCACert: /tls/etcd-ca.pem
```

```yaml
# Kubernetes NetworkPolicy — etcd port accessible only from Milvus pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: etcd-milvus-only
  namespace: milvus
spec:
  podSelector:
    matchLabels:
      app: etcd
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: milvus
      ports:
        - port: 2379
          protocol: TCP
        - port: 2380
          protocol: TCP
```

**Don't**: Leave etcd exposed with authentication disabled — every collection schema, segment location, and user credential is readable by any network peer

```bash
# VULNERABLE: etcd default state — no authentication, port 2379 reachable
# An attacker on the same network can enumerate all Milvus metadata:
etcdctl get "" --prefix   # Returns all keys including user credentials and segment locations
```

**Why**: Milvus stores collection schemas, segment file locations, user accounts, and RBAC definitions in etcd. Without authentication, port 2379 gives any network peer full read/write access to the metadata layer. An attacker can enumerate tenants, map segment files in MinIO, disable RBAC, or corrupt collection metadata — all without touching the Milvus gRPC port.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A02:2025 (Cryptographic Failures), CWE-284, CWE-306

---

## Rule: MinIO/S3 Storage Access Control

**Level**: `warning`

**When**: Deploying self-hosted Milvus with MinIO or S3 as the object-store backend

**Do**: Use a dedicated IAM user with a least-privilege bucket policy, enable SSL, and encrypt data at rest

```yaml
# milvus.yaml — scoped MinIO credentials, SSL required
minio:
  address: minio.milvus-namespace.svc.cluster.local
  port: 9000
  accessKeyID: "${MINIO_MILVUS_ACCESS_KEY}"     # Dedicated user, not root
  secretAccessKey: "${MINIO_MILVUS_SECRET_KEY}"
  useSSL: true              # Encrypts in-transit object traffic
  bucketName: milvus-vectors
  rootPath: files           # Scope writes to this prefix
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": ["arn:aws:iam:::user/milvus-svc"]},
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::milvus-vectors",
        "arn:aws:s3:::milvus-vectors/*"
      ]
    }
  ]
}
```

```bash
# MinIO — create dedicated user and apply policy (run as MinIO admin)
mc alias set local http://minio:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}"
mc admin user add local milvus-svc "${MINIO_MILVUS_SECRET_KEY}"
mc admin policy create local milvus-policy /tmp/milvus-bucket-policy.json
mc admin policy attach local milvus-policy --user milvus-svc

# Enable server-side encryption at rest (MinIO KES)
mc encrypt set sse-s3 local/milvus-vectors

# Verify bucket is not publicly accessible
mc anonymous get local/milvus-vectors   # Should return "Access Denied"
```

```python
import os

def verify_minio_tls():
    """Fail fast if MinIO connection is not using SSL."""
    endpoint = os.environ["MINIO_ENDPOINT"]
    if not endpoint.startswith("https://"):
        raise RuntimeError(
            "MINIO_ENDPOINT must use HTTPS. Set minio.useSSL: true in milvus.yaml."
        )
```

**Don't**: Use root MinIO credentials or skip encryption — a single leaked key gives full access to all vector segments

```yaml
# VULNERABLE: Root credentials with no bucket restriction
minio:
  accessKeyID: minioadmin       # Root user has all-bucket access
  secretAccessKey: minioadmin
  useSSL: false                 # Object traffic sent in cleartext
```

```bash
# VULNERABLE: Bucket publicly readable — no authentication required
mc anonymous set download local/milvus-vectors
```

**Why**: Milvus writes all vector segments and index files to MinIO/S3. An attacker who obtains the MinIO credentials bypasses Milvus RBAC entirely and reads raw vector segments directly from object storage. Using root credentials extends that blast radius to every bucket. Disabling SSL exposes segment data and credentials in transit. Encryption at rest protects stored segments if storage media is compromised.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A02:2025 (Cryptographic Failures), CWE-284, CWE-311, CWE-798

---

## Rule: GPU Resource Security

**Level**: `warning`

**When**: Deploying Milvus with GPU acceleration in Kubernetes or shared environments

**Do**: Set memory limits, configure GPU isolation, implement resource quotas

```yaml
# milvus.yaml — GPU memory bounds
gpu:
  enabled: true
  initMemSize: 1024   # Initial GPU memory pool (MB)
  maxMemSize: 4096    # Maximum GPU memory (MB) — prevents exhaustion

queryNode:
  resources:
    limits:
      nvidia.com/gpu: 1
      memory: "8Gi"
      cpu: "4"
    requests:
      nvidia.com/gpu: 1
      memory: "4Gi"
      cpu: "2"

indexNode:
  resources:
    limits:
      nvidia.com/gpu: 1
      memory: "16Gi"
    requests:
      memory: "8Gi"
```

```yaml
# Kubernetes GPU isolation with resource quotas
apiVersion: v1
kind: ResourceQuota
metadata:
  name: milvus-gpu-quota
  namespace: milvus
spec:
  hard:
    requests.nvidia.com/gpu: "2"
    limits.nvidia.com/gpu: "2"
    requests.memory: "32Gi"
    limits.memory: "64Gi"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: milvus-limits
  namespace: milvus
spec:
  limits:
    - type: Container
      default:
        nvidia.com/gpu: "1"
        memory: "8Gi"
      defaultRequest:
        memory: "4Gi"
      max:
        nvidia.com/gpu: "1"
        memory: "16Gi"
```

```python
def check_gpu_resources():
    """Monitor GPU resource usage and alert before exhaustion."""
    metrics = get_milvus_metrics()
    gpu_memory_used = metrics.get("gpu_memory_used_bytes", 0)
    gpu_memory_total = metrics.get("gpu_memory_total_bytes", 1)
    utilization = gpu_memory_used / gpu_memory_total

    if utilization > 0.9:
        alert_ops_team("GPU memory utilization critical", utilization)
        raise ResourceWarning("GPU resources near exhaustion")

    return utilization
```

**Don't**: Deploy GPU Milvus without resource limits or isolation

```yaml
# VULNERABLE: No GPU memory limits — one workload can exhaust shared GPU
gpu:
  enabled: true
  # No maxMemSize
```

**Why**: GPU resources are expensive and shared. Without limits, a single operation can exhaust GPU memory and cause service disruption for all tenants. GPU isolation in Kubernetes prevents cross-pod resource interference.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Rule: Index Configuration Security

**Level**: `warning`

**When**: Creating or modifying indexes on Milvus collections

**Do**: Validate index parameters, set resource limits, use appropriate index types

```python
from pymilvus import Collection

ALLOWED_INDEX_TYPES = {
    "FLAT": {"max_vectors": 100000},
    "IVF_FLAT": {"max_nlist": 4096, "max_vectors": 10000000},
    "IVF_SQ8": {"max_nlist": 4096, "max_vectors": 50000000},
    "IVF_PQ": {"max_nlist": 4096, "max_m": 64},
    "HNSW": {"max_M": 64, "max_efConstruction": 512},
    "ANNOY": {"max_n_trees": 1024},
}

ALLOWED_METRICS = {"L2", "IP", "COSINE"}


def validate_index_params(index_type: str, params: dict, metric_type: str):
    if index_type not in ALLOWED_INDEX_TYPES:
        raise ValueError(f"Index type {index_type} not allowed")

    if metric_type not in ALLOWED_METRICS:
        raise ValueError(f"Metric type {metric_type} not allowed")

    limits = ALLOWED_INDEX_TYPES[index_type]

    if index_type in ("IVF_FLAT", "IVF_SQ8"):
        nlist = params.get("nlist", 1024)
        if nlist > limits["max_nlist"]:
            raise ValueError(f"nlist {nlist} exceeds maximum {limits['max_nlist']}")

    elif index_type == "HNSW":
        M = params.get("M", 16)
        efConstruction = params.get("efConstruction", 200)
        if M > limits["max_M"]:
            raise ValueError(f"M {M} exceeds maximum {limits['max_M']}")
        if efConstruction > limits["max_efConstruction"]:
            raise ValueError("efConstruction exceeds maximum")

    return True


def create_index_secure(
    collection: Collection,
    field_name: str,
    index_type: str,
    params: dict,
    metric_type: str = "COSINE",
):
    validate_index_params(index_type, params, metric_type)

    num_entities = collection.num_entities
    limits = ALLOWED_INDEX_TYPES[index_type]

    if "max_vectors" in limits and num_entities > limits["max_vectors"]:
        raise ValueError(
            f"Collection has {num_entities} vectors, exceeds {index_type} limit of {limits['max_vectors']}"
        )

    collection.create_index(
        field_name,
        {"metric_type": metric_type, "index_type": index_type, "params": params},
    )

    audit_log.info("index_created", collection=collection.name, field=field_name, index_type=index_type)
```

**Don't**: Allow arbitrary index parameters or skip validation

```python
# VULNERABLE: User-controlled index parameters
def create_index(collection, user_params):
    collection.create_index("embedding", user_params)

# VULNERABLE: Excessive resource allocation
collection.create_index("embedding", {
    "index_type": "HNSW",
    "params": {"M": 256, "efConstruction": 4096},   # Causes high memory usage and timeouts
})
```

**Why**: Malicious index parameters can cause resource exhaustion, service degradation, or denial of service. Inappropriate index types for collection size waste resources and degrade performance.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-20 (Improper Input Validation)

---

## Rule: Expression Filter Injection

**Level**: `strict`

**When**: Constructing boolean expressions for Milvus queries with user input

**Do**: Validate filter fields, escape values, use parameterized expression building

```python
from pymilvus import Collection
import re

ALLOWED_FILTER_FIELDS = {"category", "status", "date", "source", "doc_type", "priority"}


def sanitize_string_value(value: str) -> str:
    """Sanitize string value for Milvus expression."""
    if len(value) > 1000:
        raise ValueError("Filter value too long")

    escaped = value.replace('\\', '\\\\').replace('"', '\\"')

    dangerous_patterns = ['||', '&&', '()', '/*', '*/', '--']
    for pattern in dangerous_patterns:
        if pattern in escaped:
            raise ValueError("Invalid characters in filter value")

    return escaped


def build_safe_expression(tenant_id: str, user_filters: dict) -> str:
    """Build Milvus boolean expression safely."""
    expressions = []

    # ALWAYS include tenant filter — non-negotiable
    safe_tenant = sanitize_string_value(tenant_id)
    expressions.append(f'tenant_id == "{safe_tenant}"')

    for field, value in user_filters.items():
        if field not in ALLOWED_FILTER_FIELDS:
            continue

        if isinstance(value, str):
            safe_value = sanitize_string_value(value)
            expressions.append(f'{field} == "{safe_value}"')
        elif isinstance(value, bool):
            expressions.append(f'{field} == {str(value).lower()}')
        elif isinstance(value, (int, float)):
            if not -1e15 < value < 1e15:
                raise ValueError(f"Numeric value out of range: {value}")
            expressions.append(f'{field} == {value}')
        elif isinstance(value, list):
            if len(value) > 100:
                raise ValueError("Too many values in IN clause")
            if all(isinstance(v, str) for v in value):
                safe_values = [f'"{sanitize_string_value(v)}"' for v in value]
                expressions.append(f'{field} in [{", ".join(safe_values)}]')
            elif all(isinstance(v, (int, float)) for v in value):
                expressions.append(f'{field} in {value}')
        elif isinstance(value, dict):
            for op, op_value in value.items():
                op_map = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
                if op in op_map:
                    expressions.append(f'{field} {op_map[op]} {op_value}')
                elif op == "like":
                    safe_pattern = sanitize_string_value(str(op_value))
                    expressions.append(f'{field} like "{safe_pattern}"')

    return " && ".join(expressions) if expressions else ""


def search_with_safe_filter(
    collection: Collection,
    tenant_id: str,
    query_vector: list,
    user_filters: dict,
    top_k: int = 10,
):
    """Search with validated expression filter."""
    expr = build_safe_expression(tenant_id, user_filters)

    results = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=min(top_k, 100),
        expr=expr,
        output_fields=["doc_id", "content", "tenant_id"],
    )

    validated_results = []
    for hits in results:
        for hit in hits:
            if hit.entity.get("tenant_id") == tenant_id:
                validated_results.append(hit)
            else:
                audit_log.error(
                    "tenant_leak_detected",
                    expected=tenant_id,
                    actual=hit.entity.get("tenant_id"),
                )

    return validated_results
```

**Don't**: Construct expressions with string interpolation or trust user input

```python
# VULNERABLE: Direct string interpolation
def search_vectors(collection, category, query_vector):
    expr = f'category == "{category}"'   # Injection: ' || tenant_id != "x" || category == '
    return collection.search(data=[query_vector], expr=expr)

# VULNERABLE: No field validation — any field accessible
def build_filter(user_input):
    return " && ".join(f'{field} == "{value}"' for field, value in user_input.items())

# VULNERABLE: User controls entire expression
def search(collection, user_expr, query_vector):
    return collection.search(data=[query_vector], expr=user_expr)
```

**Why**: Milvus boolean expressions can be manipulated to bypass tenant isolation, access unauthorized data, or cause denial of service. String interpolation without sanitization is the primary attack vector.

**Refs**: OWASP A03:2025 (Injection), CWE-89, CWE-943

---

## Rule: Bulk Insert Security

**Level**: `warning`

**When**: Performing bulk inserts into Milvus collections

**Do**: Validate data before insert, enforce size limits, implement rate limiting

```python
from pymilvus import Collection, utility
import hashlib, os

MAX_BULK_INSERT_ROWS = 100000
MAX_VECTOR_DIMENSION = 4096
MAX_STRING_FIELD_LENGTH = 65535
MAX_BULK_INSERT_SIZE_MB = 512


def validate_bulk_insert_data(data: list, collection: Collection, tenant_id: str) -> list:
    """Validate bulk insert data before insertion."""
    if len(data) > MAX_BULK_INSERT_ROWS:
        raise ValueError(f"Bulk insert exceeds maximum {MAX_BULK_INSERT_ROWS} rows")

    schema = collection.schema
    field_map = {field.name: field for field in schema.fields}
    validated_data = []

    for i, row in enumerate(data):
        validated_row = {}
        for field_name, value in row.items():
            if field_name not in field_map:
                continue
            field = field_map[field_name]
            if field.dtype.name == "FLOAT_VECTOR":
                if len(value) > MAX_VECTOR_DIMENSION:
                    raise ValueError(f"Row {i}: Vector dimension exceeds maximum")
                validated_row[field_name] = value
            elif field.dtype.name == "VARCHAR":
                if len(str(value)) > min(field.max_length, MAX_STRING_FIELD_LENGTH):
                    raise ValueError(f"Row {i}: String field too long")
                validated_row[field_name] = str(value)[:field.max_length]
            elif field.dtype.name in ("INT64", "INT32", "INT16", "INT8"):
                validated_row[field_name] = int(value)
            elif field.dtype.name in ("FLOAT", "DOUBLE"):
                validated_row[field_name] = float(value)
            else:
                validated_row[field_name] = value

        if "tenant_id" in field_map:
            validated_row["tenant_id"] = tenant_id

        validated_data.append(validated_row)

    return validated_data


def bulk_insert_secure(collection: Collection, data: list, tenant_id: str, user_id: str):
    """Perform bulk insert with security validation."""
    if not check_bulk_insert_rate_limit(tenant_id):
        raise RateLimitError("Bulk insert rate limit exceeded")

    validated_data = validate_bulk_insert_data(data, collection, tenant_id)

    estimated_size = len(str(validated_data))
    if estimated_size > MAX_BULK_INSERT_SIZE_MB * 1024 * 1024:
        raise ValueError(f"Bulk insert size exceeds {MAX_BULK_INSERT_SIZE_MB}MB limit")

    batch_id = hashlib.sha256(f"{tenant_id}:{user_id}:{len(data)}".encode()).hexdigest()[:16]
    result = collection.insert(validated_data)
    collection.flush()

    audit_log.info(
        "bulk_insert",
        tenant_id=tenant_id,
        user_id=user_id,
        batch_id=batch_id,
        row_count=len(validated_data),
        insert_ids=result.primary_keys[:10],
    )

    return {"batch_id": batch_id, "inserted_count": len(validated_data), "primary_keys": result.primary_keys}


def bulk_insert_from_file(collection: Collection, file_path: str, tenant_id: str, user_id: str):
    """Bulk insert from file with path traversal and size checks."""
    safe_path = os.path.abspath(file_path)
    allowed_dir = os.path.abspath("/data/uploads")

    if not safe_path.startswith(allowed_dir):
        raise ValueError("Invalid file path")

    file_size = os.path.getsize(safe_path)
    if file_size > MAX_BULK_INSERT_SIZE_MB * 1024 * 1024:
        raise ValueError(f"File size exceeds {MAX_BULK_INSERT_SIZE_MB}MB limit")

    task_id = utility.do_bulk_insert(collection_name=collection.name, files=[safe_path])

    audit_log.info(
        "bulk_insert_file",
        tenant_id=tenant_id,
        user_id=user_id,
        task_id=task_id,
        file_size=file_size,
    )

    return task_id
```

**Don't**: Allow unlimited bulk inserts or skip validation

```python
# VULNERABLE: No size limits
def bulk_insert(collection, data):
    collection.insert(data)

# VULNERABLE: Path traversal in file bulk insert
def bulk_insert_file(collection, user_file_path):
    utility.do_bulk_insert(collection_name=collection.name, files=[user_file_path])
```

**Why**: Bulk inserts can exhaust memory, disk, or CPU resources causing denial of service. Without validation, malformed data can corrupt collections. Unvalidated file paths enable path traversal to unauthorized files.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-20 (Improper Input Validation), CWE-22 (Path Traversal)

---

## Rule: Attu Dashboard Security

**Level**: `strict`

**When**: Deploying Attu (Milvus GUI) for administration

**Do**: Enable authentication, restrict network access, use HTTPS, audit access

```yaml
# Docker Compose with security settings
version: '3.8'
services:
  attu:
    image: zilliz/attu:latest
    environment:
      - MILVUS_URL=https://milvus:19530
      - AUTH_ENABLED=true
      - ATTU_LOG_LEVEL=info
      - SSL_ENABLED=true
      - SSL_CERT_PATH=/certs/server.crt
      - SSL_KEY_PATH=/certs/server.key
    ports:
      - "127.0.0.1:8000:3000"   # Bind to localhost only
    volumes:
      - ./certs:/certs:ro
    networks:
      - internal
    user: "1000:1000"
    read_only: true
    security_opt:
      - no-new-privileges:true
networks:
  internal:
    internal: true
```

```yaml
# Kubernetes NetworkPolicy — Attu reachable only from internal admin network
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: attu-network-policy
  namespace: milvus
spec:
  podSelector:
    matchLabels:
      app: attu
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 3000
          protocol: TCP
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: milvus
      ports:
        - port: 19530
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: attu
spec:
  type: ClusterIP   # Not LoadBalancer — internal only
  ports:
    - port: 3000
  selector:
    app: attu
```

**Don't**: Expose Attu publicly or without authentication

```yaml
# VULNERABLE: Publicly exposed, no authentication
services:
  attu:
    image: zilliz/attu:latest
    environment:
      - AUTH_ENABLED=false
    ports:
      - "8000:3000"   # All interfaces
```

**Why**: Attu provides full administrative access to Milvus — data deletion, collection management, configuration. Public exposure allows attackers to browse data, modify collections, or delete entire databases.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures), CWE-306 (Missing Authentication)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-15 | Initial release with 8 Milvus security rules |
| 2.0 | 2026-05-26 | Added RBAC enablement, mTLS, partition isolation trade-offs, etcd auth, MinIO/S3 access control |

---

## Additional Resources

- [Milvus Security Overview](https://milvus.io/docs/security_overview.md)
- [Milvus Authentication](https://milvus.io/docs/authenticate.md)
- [Milvus TLS Configuration](https://milvus.io/docs/tls.md)
- [Milvus RBAC](https://milvus.io/docs/rbac.md)
- [etcd Authentication](https://etcd.io/docs/v3.5/op-guide/authentication/)
- [MinIO Identity and Access Management](https://min.io/docs/minio/linux/administration/identity-access-management.html)
- [Attu Documentation](https://github.com/zilliztech/attu)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
