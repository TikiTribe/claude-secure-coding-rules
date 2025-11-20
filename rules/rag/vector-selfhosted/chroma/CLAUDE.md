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

**Do**: Configure authentication and TLS for server connections
```python
import chromadb
from chromadb.config import Settings
import ssl

# Server-side configuration with auth
server_settings = Settings(
    chroma_server_auth_provider="chromadb.auth.token.TokenAuthServerProvider",
    chroma_server_auth_credentials_file="/etc/chroma/tokens.json",
    chroma_server_auth_token_transport_header="Authorization",
    chroma_server_ssl_enabled=True,
    chroma_server_ssl_certfile="/etc/chroma/server.crt",
    chroma_server_ssl_keyfile="/etc/chroma/server.key"
)

# Client-side with authentication
def create_authenticated_client():
    auth_token = os.environ.get("CHROMA_AUTH_TOKEN")
    if not auth_token:
        raise ValueError("CHROMA_AUTH_TOKEN environment variable required")

    client = chromadb.HttpClient(
        host="chroma.internal",
        port=8000,
        ssl=True,
        headers={"Authorization": f"Bearer {auth_token}"}
    )

    # Verify connection
    try:
        client.heartbeat()
    except Exception as e:
        raise ConnectionError(f"Failed to authenticate with Chroma: {e}")

    return client

client = create_authenticated_client()
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

**Refs**: OWASP LLM06 Sensitive Information Disclosure, CWE-20 Improper Input Validation

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
