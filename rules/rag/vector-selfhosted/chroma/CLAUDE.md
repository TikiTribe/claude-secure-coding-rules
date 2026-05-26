# CLAUDE.md - Chroma and Vespa Security Rules

Security rules for Chroma vector database and Vespa search platform in self-hosted RAG applications.

## Rule: Chroma Persistence Security

**Level**: `strict`

**When**: Configuring Chroma persistent storage

**Do**: Validate paths and set restrictive directory permissions
```python
import chromadb
from chromadb.config import Settings
import os
import stat

def create_secure_chroma_client(persist_directory: str):
    # Validate path - prevent traversal
    abs_path = os.path.abspath(persist_directory)
    allowed_base = os.path.abspath("/var/lib/chroma")

    if not abs_path.startswith(allowed_base):
        raise ValueError(f"Persistence directory must be under {allowed_base}")

    # Create with restrictive permissions
    os.makedirs(abs_path, mode=0o700, exist_ok=True)

    # Verify permissions
    current_mode = os.stat(abs_path).st_mode
    if current_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("Directory has excessive permissions")

    client = chromadb.PersistentClient(
        path=abs_path,
        settings=Settings(
            anonymized_telemetry=False,
            allow_reset=False  # Prevent accidental data loss
        )
    )
    return client

# Secure usage
client = create_secure_chroma_client("/var/lib/chroma/app_data")
```

**Don't**: Use user-controlled paths or permissive directories
```python
import chromadb

# VULNERABLE: Path traversal possible
user_input = request.args.get("db_path")
client = chromadb.PersistentClient(path=user_input)  # Attacker: "../../etc/passwd"

# VULNERABLE: World-readable directory
client = chromadb.PersistentClient(path="/tmp/chroma_data")
```

**Why**: Path traversal enables attackers to read/write arbitrary files. Permissive directories expose vector data and embeddings to unauthorized users.

**Refs**: OWASP A01:2025 Broken Access Control, CWE-22 Path Traversal, CWE-284 Improper Access Control

---

## Rule: Chroma Client-Server Authentication

**Level**: `strict`

**When**: Running Chroma in client-server mode

**Do**: Configure authentication via environment variables or `chroma.yaml`, and use TLS-terminated connections

Chroma 0.5.x removed the old `Settings()` server kwargs. Auth is now configured server-side through env vars or the `chroma.yaml` config file; the Python client only sets client-side headers or a client auth provider.

```bash
# Server-side: Token authentication (chroma.yaml or env vars)
# Option A — environment variables passed to the chroma server process
export CHROMA_SERVER_AUTHN_PROVIDER="chromadb.auth.token_authn.TokenAuthenticationServerProvider"
export CHROMA_SERVER_AUTHN_CREDENTIALS="s3cr3t-tok3n"          # single static token
# Or use a credentials file instead:
# export CHROMA_SERVER_AUTHN_CREDENTIALS_FILE="/etc/chroma/tokens.json"

# Option B — chroma.yaml (preferred for production)
# chroma_server_authn_provider: chromadb.auth.token_authn.TokenAuthenticationServerProvider
# chroma_server_authn_credentials_file: /etc/chroma/tokens.json

# Server-side: HTTP Basic authentication variant
# export CHROMA_SERVER_AUTHN_PROVIDER="chromadb.auth.basic_authn.BasicAuthenticationServerProvider"
# export CHROMA_SERVER_AUTHN_CREDENTIALS_FILE="/etc/chroma/htpasswd"
```

```python
import chromadb
import os

# Client — Token auth (matches TokenAuthenticationServerProvider on server)
def create_authenticated_client_token() -> chromadb.HttpClient:
    auth_token = os.environ.get("CHROMA_AUTH_TOKEN")
    if not auth_token:
        raise ValueError("CHROMA_AUTH_TOKEN environment variable required")

    client = chromadb.HttpClient(
        host="chroma.internal",
        port=8000,
        ssl=True,   # TLS terminated at reverse proxy; use ssl=True here
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    client.heartbeat()  # Fail fast on bad credentials
    return client

# Client — Basic auth (matches BasicAuthenticationServerProvider on server)
from chromadb.config import Settings

def create_authenticated_client_basic() -> chromadb.HttpClient:
    client = chromadb.HttpClient(
        host="chroma.internal",
        port=8000,
        ssl=True,
        settings=Settings(
            chroma_client_auth_provider="chromadb.auth.basic_authn.BasicAuthClientProvider",
            chroma_client_auth_credentials="user:password"  # load from env in practice
        )
    )
    client.heartbeat()
    return client
```

**Don't**: Run server mode without authentication
```python
import chromadb

# VULNERABLE: No authentication - anyone can access
client = chromadb.HttpClient(host="0.0.0.0", port=8000)

# VULNERABLE: Exposed to network without TLS
client = chromadb.HttpClient(
    host="chroma-server.example.com",
    port=8000,
    ssl=False  # Credentials sent in plaintext
)
```

**Why**: Unauthenticated Chroma servers expose all vector data to network attackers. Without TLS, credentials and data are intercepted via MITM attacks.

**Refs**: OWASP A01:2025 Broken Access Control, OWASP A07:2025 Authentication Failures, CWE-306 Missing Authentication

---

## Rule: Chroma Collection Isolation

**Level**: `warning`

**When**: Managing multi-tenant data in Chroma

**Do**: Implement tenant isolation with collection naming and access controls
```python
import chromadb
import hashlib
import re

class SecureCollectionManager:
    def __init__(self, client: chromadb.Client):
        self.client = client

    def get_tenant_collection(self, tenant_id: str, collection_name: str):
        # Validate tenant ID format
        if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
            raise ValueError("Invalid tenant ID format")

        # Validate collection name
        if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', collection_name):
            raise ValueError("Invalid collection name format")

        # Create namespaced collection name
        namespace = hashlib.sha256(tenant_id.encode()).hexdigest()[:16]
        full_name = f"{namespace}_{collection_name}"

        return self.client.get_or_create_collection(
            name=full_name,
            metadata={"tenant_id": tenant_id}
        )

    def query_tenant_collection(self, tenant_id: str, collection_name: str,
                                 query_embeddings, n_results: int = 10):
        collection = self.get_tenant_collection(tenant_id, collection_name)

        # Enforce result limits
        safe_n_results = min(n_results, 100)

        return collection.query(
            query_embeddings=query_embeddings,
            n_results=safe_n_results
        )

# Usage
manager = SecureCollectionManager(client)
collection = manager.get_tenant_collection("tenant_123", "documents")
```

**Don't**: Allow direct collection access without tenant validation
```python
# VULNERABLE: No tenant isolation
collection_name = request.args.get("collection")
collection = client.get_collection(collection_name)  # Cross-tenant access

# VULNERABLE: Predictable collection names
collection = client.get_collection(f"user_{user_id}_docs")  # Enumerable
```

**Why**: Without isolation, tenants can access each other's vector data. Predictable naming enables enumeration attacks against other users' collections.

**Refs**: OWASP A01:2025 Broken Access Control, CWE-284 Improper Access Control, CWE-639 IDOR

---

## Rule: Chroma Embedding Function Security

**Level**: `warning`

**When**: Using custom embedding functions

**Do**: Validate and sandbox custom embedding functions
```python
import chromadb
from chromadb.utils import embedding_functions
import numpy as np

class SecureEmbeddingFunction:
    def __init__(self, base_function):
        self.base_function = base_function
        self.max_input_length = 8192
        self.expected_dimension = 384

    def __call__(self, input_texts: list[str]) -> list[list[float]]:
        # Validate inputs
        validated_texts = []
        for text in input_texts:
            if not isinstance(text, str):
                raise TypeError("Input must be string")
            if len(text) > self.max_input_length:
                text = text[:self.max_input_length]
            validated_texts.append(text)

        # Generate embeddings
        embeddings = self.base_function(validated_texts)

        # Validate outputs
        for emb in embeddings:
            if len(emb) != self.expected_dimension:
                raise ValueError(f"Invalid embedding dimension: {len(emb)}")
            if not all(isinstance(x, (int, float)) for x in emb):
                raise TypeError("Embedding must contain only numbers")
            if any(np.isnan(x) or np.isinf(x) for x in emb):
                raise ValueError("Embedding contains NaN or Inf")

        return embeddings

# Wrap standard function with validation
base_ef = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)
secure_ef = SecureEmbeddingFunction(base_ef)

collection = client.create_collection(
    name="secure_docs",
    embedding_function=secure_ef
)
```

**Don't**: Use unvalidated custom embedding functions
```python
# VULNERABLE: No input validation
def custom_embedding(texts):
    # Could process malicious inputs of any size
    return model.encode(texts)

# VULNERABLE: No output validation - could inject malformed data
collection = client.create_collection(
    name="docs",
    embedding_function=custom_embedding
)
```

**Why**: Malicious inputs to embedding functions can cause DoS (memory exhaustion) or model exploitation. Invalid embeddings corrupt the vector index.

**Refs**: OWASP LLM06:2025 Sensitive Information Disclosure, CWE-20 Improper Input Validation

---

## Rule: Chroma Migration Security

**Level**: `warning`

**When**: Migrating Chroma databases or upgrading versions

**Do**: Validate migrations and maintain backups
```python
import chromadb
import shutil
import os
from datetime import datetime

class SecureMigrationManager:
    def __init__(self, data_path: str, backup_path: str):
        self.data_path = data_path
        self.backup_path = backup_path

    def backup_before_migration(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(self.backup_path, f"backup_{timestamp}")

        # Create backup with same permissions
        shutil.copytree(
            self.data_path,
            backup_dir,
            dirs_exist_ok=False
        )

        # Verify backup integrity
        original_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, files in os.walk(self.data_path)
            for f in files
        )
        backup_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, files in os.walk(backup_dir)
            for f in files
        )

        if original_size != backup_size:
            raise RuntimeError("Backup verification failed")

        return backup_dir

    def migrate_with_validation(self):
        # Backup first
        backup_dir = self.backup_before_migration()

        try:
            # Perform migration
            client = chromadb.PersistentClient(path=self.data_path)

            # Validate collections still accessible
            collections = client.list_collections()
            for coll in collections:
                # Test query capability
                coll.peek(limit=1)

            print(f"Migration successful. Backup at: {backup_dir}")

        except Exception as e:
            # Restore from backup
            shutil.rmtree(self.data_path)
            shutil.copytree(backup_dir, self.data_path)
            raise RuntimeError(f"Migration failed, restored from backup: {e}")

# Usage
migration = SecureMigrationManager(
    "/var/lib/chroma/data",
    "/var/lib/chroma/backups"
)
migration.migrate_with_validation()
```

**Don't**: Perform migrations without backups or validation
```python
# VULNERABLE: No backup before migration
client = chromadb.PersistentClient(path="/var/lib/chroma/data")
# If migration fails, data is lost

# VULNERABLE: No validation after migration
# Corrupted collections go undetected
```

**Why**: Failed migrations can corrupt vector databases, causing permanent data loss. Without validation, corruption propagates to production queries.

**Refs**: CWE-284 Improper Access Control, NIST SSDF PW.8 Test Executable Code

---

## Rule: Vespa Application Package Security

**Level**: `strict`

**When**: Configuring Vespa application packages

**Do**: Validate services.xml and restrict network exposure
```xml
<!-- services.xml - secure configuration -->
<?xml version="1.0" encoding="utf-8" ?>
<services version="1.0">
  <container id="default" version="1.0">
    <!-- Bind to internal network only -->
    <http>
      <server id="default" port="8080">
        <binding>http://*:8080/</binding>
      </server>
      <!-- Enable TLS -->
      <server id="tls" port="8443">
        <ssl>
          <private-key-file>/etc/vespa/tls/key.pem</private-key-file>
          <certificate-file>/etc/vespa/tls/cert.pem</certificate-file>
          <ca-certificates-file>/etc/vespa/tls/ca.pem</ca-certificates-file>
          <client-authentication>need</client-authentication>
        </ssl>
      </server>
    </http>

    <!-- Access control -->
    <access-control>
      <exclude>
        <binding>http://*/state/v1/*</binding>
      </exclude>
    </access-control>

    <search/>
    <document-api/>
  </container>

  <content id="content" version="1.0">
    <redundancy>2</redundancy>
    <documents>
      <document type="document" mode="index"/>
    </documents>
  </content>
</services>
```

**Don't**: Deploy with default insecure configurations
```xml
<!-- VULNERABLE: No TLS, exposed to all networks -->
<services version="1.0">
  <container id="default" version="1.0">
    <http>
      <server id="default" port="8080"/>
    </http>
    <search/>
    <document-api/>
  </container>
</services>
```

**Why**: Default Vespa configurations expose APIs without authentication. Attackers can query, modify, or delete all indexed data.

**Refs**: OWASP A01:2025 Broken Access Control, OWASP A05:2025 Security Misconfiguration, CWE-284

---

## Rule: Vespa YQL Query Security

**Level**: `strict`

**When**: Constructing YQL queries for Vespa

**Do**: Use parameterized queries and validate inputs
```python
import requests
from urllib.parse import quote

class SecureVespaClient:
    def __init__(self, endpoint: str, cert_path: str, key_path: str):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.cert = (cert_path, key_path)

    def search(self, user_query: str, doc_type: str, limit: int = 10):
        # Validate and sanitize inputs
        if not isinstance(user_query, str) or len(user_query) > 1000:
            raise ValueError("Invalid query")

        # Escape special YQL characters
        safe_query = self._escape_yql(user_query)

        # Validate document type against allowlist
        allowed_types = {"article", "product", "document"}
        if doc_type not in allowed_types:
            raise ValueError(f"Invalid document type: {doc_type}")

        # Enforce limit bounds
        safe_limit = min(max(1, limit), 100)

        # Construct parameterized query
        yql = f'select * from {doc_type} where userQuery() limit {safe_limit}'

        params = {
            "yql": yql,
            "query": safe_query,
            "type": "all",
            "ranking": "default"
        }

        response = self.session.get(
            f"{self.endpoint}/search/",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _escape_yql(self, text: str) -> str:
        # Escape YQL special characters
        special_chars = ['"', "'", "\\", ";", "(", ")", "{", "}"]
        for char in special_chars:
            text = text.replace(char, f"\\{char}")
        return text

# Usage
client = SecureVespaClient(
    "https://vespa.internal:8443",
    "/etc/vespa/client.crt",
    "/etc/vespa/client.key"
)
results = client.search("machine learning", "article", limit=20)
```

**Don't**: Concatenate user input into YQL queries
```python
# VULNERABLE: YQL injection
user_input = request.args.get("q")
yql = f'select * from doc where text contains "{user_input}"'
# Attacker input: '" or true or "'  -> returns all documents

# VULNERABLE: No type validation
doc_type = request.args.get("type")
yql = f'select * from {doc_type} where userQuery()'  # Can query any type
```

**Why**: YQL injection allows attackers to bypass access controls, extract unauthorized data, or modify queries to return all documents.

**Refs**: OWASP A03:2025 Injection, CWE-89 SQL Injection (analogous), CWE-943 Improper Neutralization

---

## Rule: Vespa Ranking Expression Security

**Level**: `warning`

**When**: Defining custom ranking expressions

**Do**: Validate and limit complexity of ranking expressions
```xml
<!-- schema/document.sd - secure ranking profile -->
schema document {
  document document {
    field title type string {
      indexing: summary | index
    }
    field embedding type tensor<float>(x[384]) {
      indexing: attribute
    }
  }

  <!-- Predefined ranking profiles only -->
  rank-profile semantic inherits default {
    inputs {
      query(query_embedding) tensor<float>(x[384])
    }

    first-phase {
      expression: closeness(field, embedding)
    }

    <!-- Limit computation to prevent DoS -->
    match-features {
      closeness(field, embedding)
    }

    <!-- Set timeouts -->
    num-threads-per-search: 2
  }

  <!-- Hybrid search with bounded complexity -->
  rank-profile hybrid inherits default {
    inputs {
      query(query_embedding) tensor<float>(x[384])
    }

    first-phase {
      expression: bm25(title) + closeness(field, embedding)
    }

    second-phase {
      expression: bm25(title) * 0.3 + closeness(field, embedding) * 0.7
      rerank-count: 100
    }
  }
}
```

**Don't**: Allow user-defined ranking expressions
```python
# VULNERABLE: User-controlled ranking expression
user_ranking = request.args.get("ranking")
params = {
    "yql": "select * from doc where userQuery()",
    "ranking.features.query(custom)": user_ranking  # DoS vector
}

# VULNERABLE: Unbounded ranking computation
# rank-profile with no limits can exhaust resources
```

**Why**: Complex or malicious ranking expressions can cause CPU exhaustion and DoS. User-controlled expressions may access unauthorized fields.

**Refs**: OWASP A01:2025 Broken Access Control, CWE-400 Uncontrolled Resource Consumption

---

## Rule: Chroma Metadata Filter Injection

**Level**: `strict`

**When**: Building `where`-clause metadata filters from user-supplied input

**Do**: Allowlist field names and pin operators before passing filters to Chroma
```python
import chromadb
from typing import Any

# Allowlisted filterable fields and the operators each may use.
# Anything not in this map is rejected before it reaches Chroma.
ALLOWED_FILTER_FIELDS: dict[str, set[str]] = {
    "tenant_id": {"$eq"},
    "doc_type":  {"$eq", "$in"},
    "year":      {"$eq", "$gt", "$gte", "$lt", "$lte"},
}

def build_safe_where(raw_filters: dict[str, Any]) -> dict:
    """Validate and reconstruct a Chroma where-clause from user input."""
    safe: dict[str, Any] = {}
    for field, condition in raw_filters.items():
        if field not in ALLOWED_FILTER_FIELDS:
            raise ValueError(f"Filter field not allowed: {field!r}")
        if not isinstance(condition, dict) or len(condition) != 1:
            raise ValueError(f"Malformed condition for {field!r}")
        operator, value = next(iter(condition.items()))
        if operator not in ALLOWED_FILTER_FIELDS[field]:
            raise ValueError(f"Operator {operator!r} not allowed for {field!r}")
        # Value is passed as-is; Chroma handles parameterisation internally.
        safe[field] = {operator: value}
    return safe

def query_with_safe_filter(collection: chromadb.Collection,
                            query_embeddings: list,
                            raw_filters: dict) -> dict:
    where = build_safe_where(raw_filters)
    return collection.query(query_embeddings=query_embeddings,
                            n_results=10,
                            where=where)
```

**Don't**: Pass user-supplied filter dicts directly to Chroma
```python
# VULNERABLE: attacker supplies {"$or": [...]} or unknown fields
where = request.json.get("filters")
results = collection.query(query_embeddings=embeddings, where=where)
```

**Why**: Chroma's `where` DSL supports `$and`/`$or` logical operators. An attacker who controls the filter dict can bypass tenant scoping or trigger unintended cross-collection reads.

**Refs**: OWASP A01:2025 Broken Access Control, OWASP A03:2025 Injection, CWE-943 Improper Neutralization of Special Elements in Data Query Logic

---

## Rule: Chroma Backend Selection and Security Trade-offs

**Level**: `warning`

**When**: Choosing between Chroma's SQLite (default) and PostgreSQL backends

**Do**: Use PostgreSQL for multi-process or production deployments; lock down SQLite for single-process use
```bash
# PostgreSQL backend — required for concurrent writers and network deployments
export CHROMA_DB_IMPL=chromadb.db.impl.grpc.client.GrpcClient
# Or configure via chroma.yaml:
# database:
#   provider: chromadb.db.impl.postgres.PostgresDB
#   settings:
#     host: "postgres.internal"
#     port: 5432
#     database: "chromadb"
#     user: "chroma_app"          # least-privilege role
#     password: "${CHROMA_PG_PASS}"  # inject from secrets manager
#     sslmode: "require"
```

```python
# SQLite — only acceptable for local single-process development.
# Enforce file permissions so other OS users cannot read the DB.
import os, stat, chromadb
from chromadb.config import Settings

db_path = "/var/lib/chroma/local.db"
os.makedirs(os.path.dirname(db_path), mode=0o700, exist_ok=True)
client = chromadb.PersistentClient(
    path=os.path.dirname(db_path),
    settings=Settings(anonymized_telemetry=False)
)
# Verify no world-readable bits after creation
mode = os.stat(db_path).st_mode if os.path.exists(db_path) else 0
assert not (mode & (stat.S_IRWXG | stat.S_IRWXO)), "SQLite file is world-accessible"
```

**Don't**: Use SQLite with multiple processes or expose it over a shared filesystem
```python
# VULNERABLE: concurrent writes to SQLite corrupt the database
# VULNERABLE: SQLite file on NFS/EFS readable by other tenants
client = chromadb.PersistentClient(path="/mnt/shared/chroma")
```

**Why**: SQLite has no row-level locking; concurrent writers cause corruption. A shared-filesystem path exposes the raw embedding store to any process with mount access.

**Refs**: OWASP A05:2025 Security Misconfiguration, CWE-362 Race Condition, CWE-284 Improper Access Control

---

## Rule: Chroma CORS Configuration

**Level**: `strict`

**When**: Running Chroma server with browser-facing clients

**Do**: Set `CHROMA_SERVER_CORS_ALLOW_ORIGINS` to an explicit allowlist; never use wildcard
```bash
# Production: explicit origin allowlist
export CHROMA_SERVER_CORS_ALLOW_ORIGINS='["https://app.example.com","https://admin.example.com"]'

# Or in chroma.yaml:
# chroma_server_cors_allow_origins:
#   - "https://app.example.com"
#   - "https://admin.example.com"
```

```python
# Verify CORS is not open before starting the server (pre-flight check)
import os, json

cors_env = os.environ.get("CHROMA_SERVER_CORS_ALLOW_ORIGINS", "[]")
origins = json.loads(cors_env)
for origin in origins:
    if origin == "*":
        raise EnvironmentError(
            "Wildcard CORS origin is forbidden in production. "
            "Set CHROMA_SERVER_CORS_ALLOW_ORIGINS to specific origins."
        )
if not origins:
    raise EnvironmentError(
        "CHROMA_SERVER_CORS_ALLOW_ORIGINS must be set before starting the server."
    )
```

**Don't**: Leave CORS unconfigured or use a wildcard
```bash
# VULNERABLE: wildcard allows any website to make credentialed requests
export CHROMA_SERVER_CORS_ALLOW_ORIGINS='["*"]'

# VULNERABLE: unset defaults vary by Chroma version and may open all origins
```

**Why**: An open CORS policy lets any malicious website make authenticated requests to the Chroma API from a victim's browser, enabling cross-site data exfiltration.

**Refs**: OWASP A05:2025 Security Misconfiguration, CWE-942 Permissive Cross-domain Policy

---

## Rule: Chroma Proxy-Layer Rate Limiting

**Level**: `warning`

**When**: Exposing Chroma server to internal services or the internet

**Do**: Enforce rate limits at the reverse-proxy layer; Chroma itself has no built-in rate limiter
```nginx
# nginx — limit_req_zone scoped per client IP
limit_req_zone $binary_remote_addr zone=chroma_api:10m rate=30r/m;

server {
    listen 443 ssl;
    server_name chroma.internal;

    ssl_certificate     /etc/nginx/tls/chroma.crt;
    ssl_certificate_key /etc/nginx/tls/chroma.key;

    location / {
        limit_req zone=chroma_api burst=10 nodelay;
        limit_req_status 429;

        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```yaml
# Envoy alternative — local rate-limit filter
http_filters:
  - name: envoy.filters.http.local_ratelimit
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
      stat_prefix: chroma_rate_limit
      token_bucket:
        max_tokens: 30
        tokens_per_fill: 30
        fill_interval: 60s
      filter_enabled:
        default_value:
          numerator: 100
          denominator: HUNDRED
      filter_enforced:
        default_value:
          numerator: 100
          denominator: HUNDRED
```

**Don't**: Expose Chroma directly without a rate-limiting proxy
```bash
# VULNERABLE: Chroma bound directly on a public or shared-service port
chroma run --host 0.0.0.0 --port 8000
# Any client can flood the API; embedding inference is CPU/GPU intensive.
```

**Why**: Vector search and embedding inference are computationally expensive. An unauthenticated or authenticated-but-unlimited client can exhaust CPU/GPU, causing denial of service for all other tenants.

**Refs**: OWASP A04:2025 Insecure Design, CWE-400 Uncontrolled Resource Consumption

---

## Rule: Chroma Data Directory Volume Encryption

**Level**: `warning`

**When**: Persisting Chroma data on disk in any environment

**Do**: Encrypt the Chroma data volume at rest using LUKS (Linux) or cloud-provider KMS-backed storage
```bash
# LUKS — encrypt a dedicated block device for Chroma data
cryptsetup luksFormat /dev/sdb --key-file /root/chroma-luks.key
cryptsetup luksOpen /dev/sdb chroma_data --key-file /root/chroma-luks.key
mkfs.ext4 /dev/mapper/chroma_data
mount /dev/mapper/chroma_data /var/lib/chroma

# Verify encryption before starting Chroma
if ! cryptsetup status chroma_data | grep -q "cipher:"; then
    echo "ERROR: volume not encrypted — refusing to start Chroma" >&2
    exit 1
fi
```

```bash
# AWS — EBS volume with KMS-managed key (set at volume creation or via Terraform)
# aws ec2 create-volume --encrypted --kms-key-id alias/chroma-key ...

# GCP — persistent disk with CMEK
# gcloud compute disks create chroma-disk --kek-key=... --kek-keyring=...

# Verify encryption tag is present before mounting in automation
aws ec2 describe-volumes --volume-ids $VOL_ID \
  --query 'Volumes[0].Encrypted' --output text | grep -q true || \
  { echo "Volume not encrypted"; exit 1; }
```

**Don't**: Store Chroma data on an unencrypted volume
```bash
# VULNERABLE: plain ext4 mount — raw embeddings readable if disk is stolen or snapshot leaked
mount /dev/sdb /var/lib/chroma
```

**Why**: Raw embedding vectors can be used to reconstruct training data or queries (embedding inversion attacks). An unencrypted volume exposed through a cloud snapshot, disk theft, or misconfigured storage policy leaks the entire index.

**Refs**: OWASP A02:2025 Cryptographic Failures, NIST AI RMF MS-2.5 Data Security, CWE-311 Missing Encryption of Sensitive Data

---

## Additional Security Considerations

### Chroma Telemetry
Disable telemetry in production to prevent data leakage:
```python
settings = Settings(anonymized_telemetry=False)
```

### Vespa Monitoring
Secure metrics endpoints:
```xml
<admin version="2.0">
  <metrics>
    <consumer id="default">
      <metric-set id="vespa"/>
    </consumer>
  </metrics>
</admin>
```

### Network Segmentation
- Run Chroma/Vespa on internal networks only
- Use mTLS for all service-to-service communication
- Implement network policies in Kubernetes deployments

### Backup Encryption
Encrypt backups at rest:
```bash
# Encrypt Chroma backup
tar -czf - /var/lib/chroma | gpg --symmetric --cipher-algo AES256 > chroma_backup.tar.gz.gpg
```
