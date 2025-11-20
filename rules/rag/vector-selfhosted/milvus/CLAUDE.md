# Milvus Security Rules

Security rules for Milvus vector database deployments.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Connection Security | `strict` | Data interception, unauthorized access |
| Collection Isolation | `strict` | Cross-tenant data leakage |
| Partition Security | `warning` | Unauthorized partition access |
| GPU Resource Security | `warning` | Resource exhaustion, isolation bypass |
| Index Configuration Security | `warning` | DoS via resource exhaustion |
| Expression Filter Injection | `strict` | Filter bypass, data exfiltration |
| Bulk Insert Security | `warning` | Resource exhaustion, data integrity |
| Attu Dashboard Security | `strict` | Administrative access compromise |

---

## Rule: Connection Security

**Level**: `strict`

**When**: Establishing connections to Milvus clusters

**Do**: Configure TLS encryption, enable authentication, use token management with rotation

```python
from pymilvus import connections, utility
import os

# Secure connection with TLS and authentication
def connect_milvus_secure():
    """Establish secure connection to Milvus with TLS and auth."""
    connections.connect(
        alias="default",
        host=os.environ["MILVUS_HOST"],
        port=os.environ.get("MILVUS_PORT", "19530"),
        user=os.environ["MILVUS_USER"],
        password=os.environ["MILVUS_PASSWORD"],
        secure=True,  # Enable TLS
        server_pem_path=os.environ.get("MILVUS_SERVER_CERT"),
        server_name=os.environ.get("MILVUS_SERVER_NAME"),
        # Connection timeout
        timeout=30
    )

    # Verify connection
    if not utility.has_collection("_health_check"):
        print("Connected to Milvus securely")

    return connections.get_connection_addr("default")

# Token-based authentication (Milvus 2.3+)
def connect_with_token():
    """Connect using token authentication."""
    connections.connect(
        alias="default",
        uri=os.environ["MILVUS_URI"],
        token=os.environ["MILVUS_TOKEN"],  # From secret management
        secure=True
    )

# Connection pooling with health checks
class MilvusConnectionPool:
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self._connections = []

    def get_connection(self):
        """Get connection with health validation."""
        # Verify connection is still valid
        try:
            utility.list_collections()
            return connections.get_connection_addr("default")
        except Exception:
            # Reconnect on failure
            self._reconnect()
            return connections.get_connection_addr("default")

    def _reconnect(self):
        """Re-establish connection securely."""
        connections.disconnect("default")
        connect_milvus_secure()
```

**Don't**: Use unencrypted connections or hardcode credentials

```python
# VULNERABLE: No TLS, hardcoded credentials
from pymilvus import connections

connections.connect(
    host="milvus.internal",
    port="19530"
    # No user/password - anonymous access
    # No secure=True - plaintext traffic
)

# VULNERABLE: Hardcoded credentials
connections.connect(
    host="milvus.example.com",
    user="admin",
    password="admin123",  # Exposed in code
    secure=False
)

# VULNERABLE: No certificate validation
connections.connect(
    host=os.environ["MILVUS_HOST"],
    secure=True
    # No server_pem_path - vulnerable to MITM
)
```

**Why**: Unencrypted Milvus connections expose vector data, queries, and credentials to network interception. Without authentication, any network access allows full database control. Missing certificate validation enables man-in-the-middle attacks.

**Refs**: OWASP A02:2025 (Cryptographic Failures), OWASP A07:2025 (Identification and Authentication Failures), CWE-319, CWE-798

---

## Rule: Collection Isolation

**Level**: `strict`

**When**: Storing vectors from multiple tenants or applications

**Do**: Create separate collections per tenant with validated naming conventions

```python
from pymilvus import Collection, CollectionSchema, FieldSchema, DataType, utility
import re

# Tenant collection naming with validation
TENANT_COLLECTION_PATTERN = re.compile(r'^tenant_[a-zA-Z0-9_]{1,64}_vectors$')

def get_tenant_collection_name(tenant_id: str) -> str:
    """Generate and validate tenant collection name."""
    # Validate tenant ID format
    if not re.match(r'^[a-zA-Z0-9_]{1,64}$', tenant_id):
        raise ValueError(f"Invalid tenant_id format: {tenant_id}")

    collection_name = f"tenant_{tenant_id}_vectors"

    # Double-check generated name
    if not TENANT_COLLECTION_PATTERN.match(collection_name):
        raise ValueError(f"Invalid collection name generated: {collection_name}")

    return collection_name

def create_tenant_collection(tenant_id: str, dimension: int = 1536):
    """Create isolated collection for tenant."""
    collection_name = get_tenant_collection_name(tenant_id)

    # Check if collection already exists
    if utility.has_collection(collection_name):
        raise ValueError(f"Collection for tenant {tenant_id} already exists")

    # Define schema with tenant metadata
    fields = [
        FieldSchema(name="id", dtype=DataType.VARCHAR, is_primary=True, max_length=128),
        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=dimension),
        FieldSchema(name="tenant_id", dtype=DataType.VARCHAR, max_length=64),  # Redundant for validation
        FieldSchema(name="doc_id", dtype=DataType.VARCHAR, max_length=256),
        FieldSchema(name="content", dtype=DataType.VARCHAR, max_length=65535),
        FieldSchema(name="created_at", dtype=DataType.INT64),
    ]

    schema = CollectionSchema(
        fields=fields,
        description=f"Vector collection for tenant {tenant_id}",
        enable_dynamic_field=False  # Disable dynamic fields for security
    )

    collection = Collection(name=collection_name, schema=schema)

    # Create index with resource limits
    index_params = {
        "metric_type": "COSINE",
        "index_type": "IVF_FLAT",
        "params": {"nlist": 1024}
    }
    collection.create_index("embedding", index_params)

    return collection

def get_tenant_collection(tenant_id: str) -> Collection:
    """Get collection for tenant with existence validation."""
    collection_name = get_tenant_collection_name(tenant_id)

    if not utility.has_collection(collection_name):
        raise PermissionError(f"Tenant {tenant_id} not provisioned or unauthorized")

    return Collection(collection_name)

# Example usage with tenant isolation
def insert_tenant_vectors(tenant_id: str, vectors: list):
    """Insert vectors into tenant-specific collection."""
    collection = get_tenant_collection(tenant_id)

    # Validate all vectors belong to this tenant
    for vec in vectors:
        if vec.get("tenant_id") != tenant_id:
            raise ValueError("Vector tenant_id mismatch")

    collection.insert(vectors)
    collection.flush()
```

**Don't**: Mix tenant data in shared collections or use predictable collection names

```python
# VULNERABLE: All tenants in one collection
def store_vector(tenant_id, embedding, content):
    collection = Collection("shared_vectors")
    collection.insert([{
        "embedding": embedding,
        "content": content,
        "tenant_id": tenant_id  # Only metadata separation
    }])

# VULNERABLE: Predictable/guessable collection names
def get_collection(tenant_id):
    return Collection(tenant_id)  # tenant_id directly as name

# VULNERABLE: No validation on tenant access
def query_tenant(collection_name, query_vector):
    collection = Collection(collection_name)  # Any collection accessible
    return collection.search(query_vector)
```

**Why**: Shared collections rely on filter enforcement which can be bypassed. Separate collections provide database-level isolation. Predictable naming enables enumeration attacks.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: Partition Security

**Level**: `warning`

**When**: Using Milvus partitions for data organization within collections

**Do**: Validate partition keys, implement access control checks before partition operations

```python
from pymilvus import Collection, Partition
import re

ALLOWED_PARTITION_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,128}$')

def validate_partition_name(partition_name: str) -> bool:
    """Validate partition name format."""
    if not ALLOWED_PARTITION_PATTERN.match(partition_name):
        raise ValueError(f"Invalid partition name: {partition_name}")

    # Prevent access to internal partitions
    if partition_name.startswith("_"):
        raise ValueError("Cannot access internal partitions")

    return True

def create_partition_secure(collection: Collection, partition_name: str, user_id: str):
    """Create partition with access control."""
    validate_partition_name(partition_name)

    # Check user has permission to create partitions
    if not check_partition_permission(user_id, collection.name, "create"):
        raise PermissionError("User not authorized to create partitions")

    if collection.has_partition(partition_name):
        raise ValueError(f"Partition {partition_name} already exists")

    partition = Partition(collection, partition_name)

    # Log partition creation
    audit_log.info(
        "partition_created",
        collection=collection.name,
        partition=partition_name,
        user_id=user_id
    )

    return partition

def search_in_partition(
    collection: Collection,
    partition_names: list,
    query_vector: list,
    user_id: str,
    top_k: int = 10
):
    """Search within specific partitions with access validation."""
    # Validate all partition names
    for name in partition_names:
        validate_partition_name(name)

        # Check partition exists
        if not collection.has_partition(name):
            raise ValueError(f"Partition {name} does not exist")

        # Check user access to partition
        if not check_partition_permission(user_id, collection.name, "search", name):
            raise PermissionError(f"User not authorized for partition {name}")

    # Perform search restricted to specified partitions
    results = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=top_k,
        partition_names=partition_names  # Restrict to validated partitions
    )

    return results

def check_partition_permission(user_id: str, collection: str, action: str, partition: str = None) -> bool:
    """Check user permission for partition operations."""
    # Implement based on your authorization system
    # Example: RBAC check
    return auth_service.check_permission(user_id, f"{collection}:{partition}:{action}")
```

**Don't**: Allow unrestricted partition access or skip validation

```python
# VULNERABLE: No partition name validation
def create_partition(collection, user_partition_name):
    Partition(collection, user_partition_name)  # User controls partition name

# VULNERABLE: No access control
def search_partitions(collection, partition_names, query):
    return collection.search(
        data=[query],
        partition_names=partition_names  # No authorization check
    )

# VULNERABLE: Access to internal partitions
def list_all_partitions(collection):
    return collection.partitions  # Exposes internal partitions
```

**Why**: Partitions can contain sensitive data subsets. Without access control, users can access partitions they shouldn't. Invalid partition names can cause errors or access internal system partitions.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-20

---

## Rule: GPU Resource Security

**Level**: `warning`

**When**: Deploying Milvus with GPU acceleration in Kubernetes or shared environments

**Do**: Set memory limits, configure GPU isolation, implement resource quotas

```python
# Milvus GPU configuration (milvus.yaml)
"""
gpu:
  enabled: true
  initMemSize: 1024  # Initial GPU memory pool (MB)
  maxMemSize: 4096   # Maximum GPU memory (MB) - prevents exhaustion

queryNode:
  resources:
    limits:
      nvidia.com/gpu: 1  # Limit GPU count
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
"""

# Kubernetes GPU isolation with resource quotas
"""
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
"""

# Application-level GPU resource monitoring
from pymilvus import utility

def check_gpu_resources():
    """Monitor GPU resource usage."""
    # Get system info including GPU stats
    info = utility.get_server_version()

    # Implement resource monitoring
    metrics = get_milvus_metrics()

    gpu_memory_used = metrics.get("gpu_memory_used_bytes", 0)
    gpu_memory_total = metrics.get("gpu_memory_total_bytes", 1)

    utilization = gpu_memory_used / gpu_memory_total

    if utilization > 0.9:
        alert_ops_team("GPU memory utilization critical", utilization)
        raise ResourceWarning("GPU resources near exhaustion")

    return utilization

def create_index_with_gpu_limits(collection, index_params: dict):
    """Create index with GPU resource awareness."""
    # Check available resources before heavy operation
    check_gpu_resources()

    # Set GPU-specific index parameters
    gpu_index_params = {
        "metric_type": index_params.get("metric_type", "L2"),
        "index_type": "GPU_IVF_FLAT",  # GPU-accelerated index
        "params": {
            "nlist": index_params.get("nlist", 1024),
            # Limit GPU memory for this index
        }
    }

    collection.create_index("embedding", gpu_index_params)
```

**Don't**: Deploy GPU Milvus without resource limits or isolation

```python
# VULNERABLE: No GPU memory limits
"""
# milvus.yaml - No limits
gpu:
  enabled: true
  # No maxMemSize - can exhaust GPU memory
"""

# VULNERABLE: Kubernetes without GPU quotas
"""
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: milvus
        resources: {}  # No limits - can consume all GPU resources
"""

# VULNERABLE: No resource monitoring
def create_index(collection, params):
    collection.create_index("embedding", params)  # No resource checks
```

**Why**: GPU resources are expensive and shared. Without limits, a single operation can exhaust GPU memory causing service disruption for all tenants. GPU isolation in K8s prevents cross-pod resource interference.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Rule: Index Configuration Security

**Level**: `warning`

**When**: Creating or modifying indexes on Milvus collections

**Do**: Validate index parameters, set resource limits, use appropriate index types

```python
from pymilvus import Collection

# Allowed index configurations with resource bounds
ALLOWED_INDEX_TYPES = {
    "FLAT": {"max_vectors": 100000},  # Small datasets only
    "IVF_FLAT": {"max_nlist": 4096, "max_vectors": 10000000},
    "IVF_SQ8": {"max_nlist": 4096, "max_vectors": 50000000},
    "IVF_PQ": {"max_nlist": 4096, "max_m": 64},
    "HNSW": {"max_M": 64, "max_efConstruction": 512},
    "ANNOY": {"max_n_trees": 1024},
}

ALLOWED_METRICS = {"L2", "IP", "COSINE"}

def validate_index_params(index_type: str, params: dict, metric_type: str):
    """Validate index configuration against security limits."""
    if index_type not in ALLOWED_INDEX_TYPES:
        raise ValueError(f"Index type {index_type} not allowed")

    if metric_type not in ALLOWED_METRICS:
        raise ValueError(f"Metric type {metric_type} not allowed")

    limits = ALLOWED_INDEX_TYPES[index_type]

    # Validate parameters against limits
    if index_type == "IVF_FLAT" or index_type == "IVF_SQ8":
        nlist = params.get("nlist", 1024)
        if nlist > limits["max_nlist"]:
            raise ValueError(f"nlist {nlist} exceeds maximum {limits['max_nlist']}")

    elif index_type == "HNSW":
        M = params.get("M", 16)
        efConstruction = params.get("efConstruction", 200)

        if M > limits["max_M"]:
            raise ValueError(f"M {M} exceeds maximum {limits['max_M']}")
        if efConstruction > limits["max_efConstruction"]:
            raise ValueError(f"efConstruction exceeds maximum")

    return True

def create_index_secure(
    collection: Collection,
    field_name: str,
    index_type: str,
    params: dict,
    metric_type: str = "COSINE"
):
    """Create index with validation and resource limits."""
    # Validate parameters
    validate_index_params(index_type, params, metric_type)

    # Check collection size for index type appropriateness
    num_entities = collection.num_entities
    limits = ALLOWED_INDEX_TYPES[index_type]

    if "max_vectors" in limits and num_entities > limits["max_vectors"]:
        raise ValueError(
            f"Collection has {num_entities} vectors, "
            f"exceeds {index_type} limit of {limits['max_vectors']}"
        )

    index_params = {
        "metric_type": metric_type,
        "index_type": index_type,
        "params": params
    }

    # Create index with monitoring
    collection.create_index(field_name, index_params)

    # Log index creation
    audit_log.info(
        "index_created",
        collection=collection.name,
        field=field_name,
        index_type=index_type,
        params=params
    )

# Example: Safe index creation
def setup_collection_index(collection: Collection, dimension: int):
    """Setup appropriate index based on collection characteristics."""
    num_entities = collection.num_entities

    if num_entities < 10000:
        # Small collection - use FLAT
        index_params = {"nlist": 128}
        index_type = "IVF_FLAT"
    elif num_entities < 1000000:
        # Medium collection - use IVF_FLAT
        index_params = {"nlist": 1024}
        index_type = "IVF_FLAT"
    else:
        # Large collection - use HNSW
        index_params = {"M": 32, "efConstruction": 256}
        index_type = "HNSW"

    create_index_secure(collection, "embedding", index_type, index_params)
```

**Don't**: Allow arbitrary index parameters or skip validation

```python
# VULNERABLE: User-controlled index parameters
def create_index(collection, user_params):
    collection.create_index("embedding", user_params)  # No validation

# VULNERABLE: Excessive resource allocation
collection.create_index("embedding", {
    "index_type": "HNSW",
    "params": {
        "M": 256,  # Excessive - causes high memory usage
        "efConstruction": 4096  # Can cause timeouts
    }
})

# VULNERABLE: No index type validation
def build_index(collection, index_type):
    collection.create_index("embedding", {"index_type": index_type})
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

# Allowed filter fields - whitelist approach
ALLOWED_FILTER_FIELDS = {"category", "status", "date", "source", "doc_type", "priority"}
ALLOWED_OPERATORS = {"==", "!=", ">", ">=", "<", "<=", "in", "not in", "like"}

def sanitize_string_value(value: str) -> str:
    """Sanitize string value for Milvus expression."""
    if len(value) > 1000:
        raise ValueError("Filter value too long")

    # Escape special characters
    # Milvus uses double quotes for strings
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')

    # Prevent expression injection
    dangerous_patterns = ['||', '&&', '()', '/*', '*/', '--']
    for pattern in dangerous_patterns:
        if pattern in escaped:
            raise ValueError(f"Invalid characters in filter value")

    return escaped

def build_safe_expression(tenant_id: str, user_filters: dict) -> str:
    """Build Milvus boolean expression safely."""
    expressions = []

    # ALWAYS include tenant filter - non-negotiable
    safe_tenant = sanitize_string_value(tenant_id)
    expressions.append(f'tenant_id == "{safe_tenant}"')

    for field, value in user_filters.items():
        # Validate field name
        if field not in ALLOWED_FILTER_FIELDS:
            continue  # Skip invalid fields

        # Build type-safe expression
        if isinstance(value, str):
            safe_value = sanitize_string_value(value)
            expressions.append(f'{field} == "{safe_value}"')

        elif isinstance(value, bool):
            expressions.append(f'{field} == {str(value).lower()}')

        elif isinstance(value, (int, float)):
            # Validate numeric range
            if not -1e15 < value < 1e15:
                raise ValueError(f"Numeric value out of range: {value}")
            expressions.append(f'{field} == {value}')

        elif isinstance(value, list):
            # IN expression
            if len(value) > 100:
                raise ValueError("Too many values in IN clause")

            if all(isinstance(v, str) for v in value):
                safe_values = [f'"{sanitize_string_value(v)}"' for v in value]
                expressions.append(f'{field} in [{", ".join(safe_values)}]')
            elif all(isinstance(v, (int, float)) for v in value):
                expressions.append(f'{field} in {value}')

        elif isinstance(value, dict):
            # Range expression: {"gt": 10, "lt": 100}
            for op, op_value in value.items():
                if op == "gt":
                    expressions.append(f'{field} > {op_value}')
                elif op == "gte":
                    expressions.append(f'{field} >= {op_value}')
                elif op == "lt":
                    expressions.append(f'{field} < {op_value}')
                elif op == "lte":
                    expressions.append(f'{field} <= {op_value}')
                elif op == "like":
                    safe_pattern = sanitize_string_value(str(op_value))
                    expressions.append(f'{field} like "{safe_pattern}"')

    return " && ".join(expressions) if expressions else ""

def search_with_safe_filter(
    collection: Collection,
    tenant_id: str,
    query_vector: list,
    user_filters: dict,
    top_k: int = 10
):
    """Search with validated expression filter."""
    # Build safe expression
    expr = build_safe_expression(tenant_id, user_filters)

    # Perform search
    results = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param={"metric_type": "COSINE", "params": {"nprobe": 10}},
        limit=min(top_k, 100),  # Enforce maximum
        expr=expr,
        output_fields=["doc_id", "content", "tenant_id"]
    )

    # Validate results contain correct tenant
    validated_results = []
    for hits in results:
        for hit in hits:
            if hit.entity.get("tenant_id") == tenant_id:
                validated_results.append(hit)
            else:
                # Log security incident
                audit_log.error(
                    "tenant_leak_detected",
                    expected=tenant_id,
                    actual=hit.entity.get("tenant_id")
                )

    return validated_results

# Query with safe expression
def query_with_safe_filter(
    collection: Collection,
    tenant_id: str,
    user_filters: dict,
    limit: int = 100
):
    """Query (non-vector) with validated expression."""
    expr = build_safe_expression(tenant_id, user_filters)

    return collection.query(
        expr=expr,
        output_fields=["id", "doc_id", "content"],
        limit=min(limit, 1000)
    )
```

**Don't**: Construct expressions with string interpolation or trust user input

```python
# VULNERABLE: Direct string interpolation
def search_vectors(collection, category, query_vector):
    # Attacker can inject: category = '" || tenant_id != "attacker" || category == "'
    expr = f'category == "{category}"'
    return collection.search(data=[query_vector], expr=expr)

# VULNERABLE: No field validation
def build_filter(user_input):
    expressions = []
    for field, value in user_input.items():
        expressions.append(f'{field} == "{value}"')  # Any field allowed
    return " && ".join(expressions)

# VULNERABLE: No value sanitization
def query_by_status(collection, status):
    expr = f'status == "{status}"'  # status could contain injection
    return collection.query(expr=expr)

# VULNERABLE: User controls entire expression
def search(collection, user_expr, query_vector):
    return collection.search(data=[query_vector], expr=user_expr)
```

**Why**: Milvus boolean expressions can be manipulated through injection attacks to bypass tenant isolation, access unauthorized data, or cause denial of service. String interpolation without sanitization is the primary attack vector.

**Refs**: OWASP A03:2025 (Injection), CWE-89, CWE-943

---

## Rule: Bulk Insert Security

**Level**: `warning`

**When**: Performing bulk inserts into Milvus collections

**Do**: Validate data before insert, enforce size limits, implement rate limiting

```python
from pymilvus import Collection, utility
import hashlib

# Bulk insert limits
MAX_BULK_INSERT_ROWS = 100000
MAX_VECTOR_DIMENSION = 4096
MAX_STRING_FIELD_LENGTH = 65535
MAX_BULK_INSERT_SIZE_MB = 512

def validate_bulk_insert_data(
    data: list,
    collection: Collection,
    tenant_id: str
) -> list:
    """Validate bulk insert data before insertion."""
    if len(data) > MAX_BULK_INSERT_ROWS:
        raise ValueError(f"Bulk insert exceeds maximum {MAX_BULK_INSERT_ROWS} rows")

    # Get collection schema for validation
    schema = collection.schema
    field_map = {field.name: field for field in schema.fields}

    validated_data = []

    for i, row in enumerate(data):
        validated_row = {}

        for field_name, value in row.items():
            if field_name not in field_map:
                continue  # Skip unknown fields

            field = field_map[field_name]

            # Validate by field type
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

        # Enforce tenant ID
        if "tenant_id" in field_map:
            validated_row["tenant_id"] = tenant_id

        validated_data.append(validated_row)

    return validated_data

def bulk_insert_secure(
    collection: Collection,
    data: list,
    tenant_id: str,
    user_id: str
):
    """Perform bulk insert with security validation."""
    # Check rate limits
    if not check_bulk_insert_rate_limit(tenant_id):
        raise RateLimitError("Bulk insert rate limit exceeded")

    # Validate data
    validated_data = validate_bulk_insert_data(data, collection, tenant_id)

    # Estimate size
    estimated_size = len(str(validated_data))
    if estimated_size > MAX_BULK_INSERT_SIZE_MB * 1024 * 1024:
        raise ValueError(f"Bulk insert size exceeds {MAX_BULK_INSERT_SIZE_MB}MB limit")

    # Generate batch ID for tracking
    batch_id = hashlib.sha256(f"{tenant_id}:{user_id}:{len(data)}".encode()).hexdigest()[:16]

    # Perform insert
    result = collection.insert(validated_data)

    # Flush to persist
    collection.flush()

    # Audit log
    audit_log.info(
        "bulk_insert",
        tenant_id=tenant_id,
        user_id=user_id,
        batch_id=batch_id,
        row_count=len(validated_data),
        insert_ids=result.primary_keys[:10]  # Log first 10 IDs
    )

    return {
        "batch_id": batch_id,
        "inserted_count": len(validated_data),
        "primary_keys": result.primary_keys
    }

def check_bulk_insert_rate_limit(tenant_id: str) -> bool:
    """Check if tenant has exceeded bulk insert rate limits."""
    # Implement based on your rate limiting system
    # Example: Redis-based rate limiting
    key = f"bulk_insert:{tenant_id}"
    current = redis_client.incr(key)

    if current == 1:
        redis_client.expire(key, 3600)  # 1 hour window

    return current <= 10  # 10 bulk inserts per hour

# File-based bulk insert security
def bulk_insert_from_file(
    collection: Collection,
    file_path: str,
    tenant_id: str,
    user_id: str
):
    """Bulk insert from file with security checks."""
    import os

    # Validate file path (prevent path traversal)
    safe_path = os.path.abspath(file_path)
    allowed_dir = os.path.abspath("/data/uploads")

    if not safe_path.startswith(allowed_dir):
        raise ValueError("Invalid file path")

    # Check file size
    file_size = os.path.getsize(safe_path)
    if file_size > MAX_BULK_INSERT_SIZE_MB * 1024 * 1024:
        raise ValueError(f"File size exceeds {MAX_BULK_INSERT_SIZE_MB}MB limit")

    # Use Milvus bulk insert with validation
    task_id = utility.do_bulk_insert(
        collection_name=collection.name,
        files=[safe_path]
    )

    audit_log.info(
        "bulk_insert_file",
        tenant_id=tenant_id,
        user_id=user_id,
        task_id=task_id,
        file_size=file_size
    )

    return task_id
```

**Don't**: Allow unlimited bulk inserts or skip validation

```python
# VULNERABLE: No size limits
def bulk_insert(collection, data):
    collection.insert(data)  # No limit on data size

# VULNERABLE: No data validation
def bulk_insert_raw(collection, user_data):
    collection.insert(user_data)  # Trust all user data

# VULNERABLE: No rate limiting
def bulk_insert(collection, tenant_id, data):
    while data:
        batch = data[:10000]
        collection.insert(batch)  # No rate limiting
        data = data[10000:]

# VULNERABLE: Path traversal in file bulk insert
def bulk_insert_file(collection, user_file_path):
    utility.do_bulk_insert(
        collection_name=collection.name,
        files=[user_file_path]  # User controls path
    )
```

**Why**: Bulk inserts can exhaust memory, disk, or CPU resources causing denial of service. Without validation, malformed data can corrupt collections. Unvalidated file paths enable access to unauthorized files.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-20 (Improper Input Validation), CWE-22 (Path Traversal)

---

## Rule: Attu Dashboard Security

**Level**: `strict`

**When**: Deploying Attu (Milvus GUI) for administration

**Do**: Enable authentication, restrict network access, use HTTPS, audit access

```python
# Attu deployment with security configuration

# Docker Compose with security settings
"""
version: '3.8'
services:
  attu:
    image: zilliz/attu:latest
    environment:
      # Authentication
      - MILVUS_URL=https://milvus:19530
      - AUTH_ENABLED=true
      - ATTU_LOG_LEVEL=info

      # TLS configuration
      - SSL_ENABLED=true
      - SSL_CERT_PATH=/certs/server.crt
      - SSL_KEY_PATH=/certs/server.key

    ports:
      - "127.0.0.1:8000:3000"  # Bind to localhost only

    volumes:
      - ./certs:/certs:ro

    networks:
      - internal  # Internal network only

    # Security context
    user: "1000:1000"  # Non-root user
    read_only: true
    security_opt:
      - no-new-privileges:true

networks:
  internal:
    internal: true  # No external access
"""

# Kubernetes with network policies
"""
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
  # Only allow from specific admin IPs
  - from:
    - ipBlock:
        cidr: 10.0.0.0/8  # Internal network only
    ports:
    - port: 3000
      protocol: TCP
  egress:
  # Only allow to Milvus
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
  type: ClusterIP  # Not LoadBalancer - internal only
  ports:
  - port: 3000
  selector:
    app: attu
"""

# Nginx reverse proxy with authentication
"""
server {
    listen 443 ssl;
    server_name attu.internal.company.com;

    ssl_certificate /etc/ssl/certs/attu.crt;
    ssl_certificate_key /etc/ssl/private/attu.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Basic auth or OAuth2 proxy
    auth_basic "Attu Admin";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Alternative: OAuth2 proxy
    # auth_request /oauth2/auth;

    # Access logging for audit
    access_log /var/log/nginx/attu_access.log combined;

    # IP whitelist
    allow 10.0.0.0/8;
    deny all;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Security headers
        add_header X-Frame-Options "DENY";
        add_header X-Content-Type-Options "nosniff";
        add_header Content-Security-Policy "default-src 'self'";
    }
}
"""

# Audit logging for Attu access
def log_attu_access(user: str, action: str, details: dict):
    """Log administrative actions through Attu."""
    audit_log.info(
        "attu_admin_action",
        user=user,
        action=action,
        timestamp=datetime.utcnow().isoformat(),
        ip_address=details.get("ip"),
        collection=details.get("collection"),
        operation_details=details
    )

# Health check for Attu security
def check_attu_security():
    """Verify Attu security configuration."""
    issues = []

    # Check if exposed externally
    # Check TLS enabled
    # Check authentication enabled
    # Check network policies

    return issues
```

**Don't**: Expose Attu publicly or without authentication

```python
# VULNERABLE: Publicly exposed Attu
"""
docker run -p 0.0.0.0:8000:3000 zilliz/attu
# Accessible from internet without auth
"""

# VULNERABLE: No authentication
"""
services:
  attu:
    image: zilliz/attu:latest
    environment:
      - AUTH_ENABLED=false  # Anyone can access
    ports:
      - "8000:3000"  # All interfaces
"""

# VULNERABLE: HTTP without TLS
"""
server {
    listen 80;  # No encryption
    location / {
        proxy_pass http://attu:3000;
    }
}
"""

# VULNERABLE: LoadBalancer exposing to internet
"""
apiVersion: v1
kind: Service
metadata:
  name: attu
spec:
  type: LoadBalancer  # Public IP
  ports:
  - port: 3000
"""
```

**Why**: Attu provides full administrative access to Milvus including data deletion, collection management, and configuration. Public exposure allows attackers to browse data, modify collections, or delete entire databases.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures), CWE-306 (Missing Authentication)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-15 | Initial release with 8 Milvus security rules |

---

## Additional Resources

- [Milvus Security Overview](https://milvus.io/docs/security_overview.md)
- [Milvus Authentication](https://milvus.io/docs/authenticate.md)
- [Milvus TLS Configuration](https://milvus.io/docs/tls.md)
- [Milvus RBAC](https://milvus.io/docs/rbac.md)
- [Attu Documentation](https://github.com/zilliztech/attu)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
