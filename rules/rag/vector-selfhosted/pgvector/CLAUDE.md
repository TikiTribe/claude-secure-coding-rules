# pgvector Security Rules

Security rules for PostgreSQL pgvector extension implementations.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Connection Security | `strict` | Data interception, credential exposure |
| SQL Injection Prevention | `strict` | Vector data exfiltration, data manipulation |
| Row-Level Security | `strict` | Cross-tenant data leakage |
| pg_hba.conf Authentication | `strict` | Unauthorized access, weak credential storage |
| Partition by tenant_id | `strict` | Cross-tenant data leakage, planner bypass |
| Index Security | `warning` | Performance degradation, DoS |
| Extension Security | `warning` | Privilege escalation |
| Backup Security | `strict` | Data exposure in backups |
| Performance Limits | `warning` | Resource exhaustion |

---

## Rule: Connection Security

**Level**: `strict`

**When**: Establishing connections to PostgreSQL with pgvector

**Do**: Use SSL mode `verify-full`, environment-based credentials, and connection pooling with timeouts

```python
# psycopg2 - Secure connection with certificate verification
import psycopg2
import os

conn = psycopg2.connect(
    host=os.environ["PGVECTOR_HOST"],
    port=os.environ.get("PGVECTOR_PORT", "5432"),
    database=os.environ["PGVECTOR_DATABASE"],
    user=os.environ["PGVECTOR_USER"],
    password=os.environ["PGVECTOR_PASSWORD"],
    sslmode="verify-full",
    sslrootcert="/path/to/ca.crt",
    sslcert="/path/to/client.crt",
    sslkey="/path/to/client.key",
    connect_timeout=10,
    application_name="vector_service"
)

# asyncpg - Async connection with SSL
import asyncpg
import ssl

ssl_context = ssl.create_default_context(cafile="/path/to/ca.crt")
ssl_context.load_cert_chain("/path/to/client.crt", "/path/to/client.key")

conn = await asyncpg.connect(
    host=os.environ["PGVECTOR_HOST"],
    port=int(os.environ.get("PGVECTOR_PORT", "5432")),
    database=os.environ["PGVECTOR_DATABASE"],
    user=os.environ["PGVECTOR_USER"],
    password=os.environ["PGVECTOR_PASSWORD"],
    ssl=ssl_context,
    timeout=10
)

# Connection pooling with asyncpg
pool = await asyncpg.create_pool(
    host=os.environ["PGVECTOR_HOST"],
    database=os.environ["PGVECTOR_DATABASE"],
    user=os.environ["PGVECTOR_USER"],
    password=os.environ["PGVECTOR_PASSWORD"],
    ssl=ssl_context,
    min_size=5,
    max_size=20,
    max_inactive_connection_lifetime=300,
    command_timeout=30
)
```

**Don't**: Use unencrypted connections, hardcode credentials, or skip certificate verification

```python
# VULNERABLE: Hardcoded credentials, no SSL
conn = psycopg2.connect(
    host="db.example.com",
    database="vectors",
    user="admin",
    password="password123",  # Exposed in code
    sslmode="disable"  # Plaintext traffic
)

# VULNERABLE: SSL without verification
conn = psycopg2.connect(
    host=os.environ["PGVECTOR_HOST"],
    password=os.environ["PGVECTOR_PASSWORD"],
    sslmode="require"  # Encrypted but no certificate verification
)

# VULNERABLE: No connection timeout
conn = psycopg2.connect(
    host=os.environ["PGVECTOR_HOST"],
    password=os.environ["PGVECTOR_PASSWORD"]
    # No timeout - can hang indefinitely
)
```

**Why**: Unencrypted connections expose vector data and queries to network interception. Hardcoded credentials leak through version control and logs. Without certificate verification, connections are vulnerable to MITM attacks. Missing timeouts can cause resource exhaustion.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-319, CWE-798, CWE-295

---

## Rule: SQL Injection Prevention

**Level**: `strict`

**When**: Constructing queries with user-provided filters, vector data, or metadata

**Do**: Always use parameterized queries for all vector operations

```python
# Parameterized vector similarity search
def secure_vector_search(conn, query_vector: list, tenant_id: str, top_k: int = 10):
    """Secure vector similarity search with parameterized queries."""
    with conn.cursor() as cur:
        # All values passed as parameters
        cur.execute("""
            SELECT id, content, metadata,
                   embedding <-> %s::vector AS distance
            FROM vectors
            WHERE tenant_id = %s
            ORDER BY distance
            LIMIT %s
        """, (query_vector, tenant_id, top_k))
        return cur.fetchall()

# Parameterized upsert with metadata
def secure_upsert(conn, vector_id: str, embedding: list, content: str,
                  tenant_id: str, metadata: dict):
    """Secure vector upsert with parameterized queries."""
    import json

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO vectors (id, embedding, content, tenant_id, metadata)
            VALUES (%s, %s::vector, %s, %s, %s::jsonb)
            ON CONFLICT (id) DO UPDATE SET
                embedding = EXCLUDED.embedding,
                content = EXCLUDED.content,
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
        """, (vector_id, embedding, content, tenant_id, json.dumps(metadata)))
    conn.commit()

# Parameterized filter with validated operators
ALLOWED_OPERATORS = {'=', '>', '<', '>=', '<=', 'LIKE', 'IN'}
ALLOWED_FIELDS = {'category', 'status', 'created_at', 'source'}

def secure_filtered_search(conn, query_vector: list, tenant_id: str,
                           filters: dict, top_k: int = 10):
    """Vector search with validated and parameterized filters."""
    base_query = """
        SELECT id, content, metadata,
               embedding <-> %s::vector AS distance
        FROM vectors
        WHERE tenant_id = %s
    """
    params = [query_vector, tenant_id]

    # Build safe filter conditions
    for field, condition in filters.items():
        if field not in ALLOWED_FIELDS:
            raise ValueError(f"Invalid filter field: {field}")

        if isinstance(condition, dict):
            op = condition.get('op', '=').upper()
            if op not in ALLOWED_OPERATORS:
                raise ValueError(f"Invalid operator: {op}")

            value = condition.get('value')
            # Use %s placeholder, never string interpolation
            base_query += f" AND {field} {op} %s"
            params.append(value)
        else:
            base_query += f" AND {field} = %s"
            params.append(condition)

    base_query += " ORDER BY distance LIMIT %s"
    params.append(top_k)

    with conn.cursor() as cur:
        cur.execute(base_query, params)
        return cur.fetchall()

# asyncpg parameterized query
async def async_vector_search(pool, query_vector: list, tenant_id: str):
    """Async vector search with parameterized query."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, content, metadata,
                   embedding <-> $1::vector AS distance
            FROM vectors
            WHERE tenant_id = $2
            ORDER BY distance
            LIMIT $3
        """, query_vector, tenant_id, 10)
        return rows
```

**Don't**: Use string interpolation or concatenation for query construction

```python
# VULNERABLE: String interpolation in vector query
def vulnerable_search(conn, query_vector, tenant_id):
    query = f"""
        SELECT * FROM vectors
        WHERE tenant_id = '{tenant_id}'
        ORDER BY embedding <-> '{query_vector}'::vector
        LIMIT 10
    """
    # Attacker can inject: tenant_id = "' OR '1'='1"
    cur.execute(query)

# VULNERABLE: String concatenation for filters
def vulnerable_filter(conn, field, value):
    query = "SELECT * FROM vectors WHERE " + field + " = '" + value + "'"
    # Attacker controls field and value
    cur.execute(query)

# VULNERABLE: Unvalidated table/column names
def vulnerable_dynamic_query(conn, table_name, column_name, value):
    query = f"SELECT * FROM {table_name} WHERE {column_name} = %s"
    # Attacker can inject table/column names
    cur.execute(query, (value,))

# VULNERABLE: Format string injection
def vulnerable_format(conn, query_vector, filters):
    query = "SELECT * FROM vectors WHERE metadata @> '%(filters)s'" % {
        'filters': json.dumps(filters)
    }
    cur.execute(query)
```

**Why**: SQL injection in vector operations can bypass tenant isolation, exfiltrate embeddings and metadata, modify or delete vector data, and execute arbitrary SQL commands. Parameterized queries prevent injection by separating code from data.

**Refs**: OWASP A03:2025 (Injection), CWE-89, CWE-943

---

## Rule: Row-Level Security

**Level**: `strict`

**When**: Implementing multi-tenancy with pgvector

**Do**: Enable RLS with policies that enforce tenant isolation at the database level

```python
# Schema setup with RLS
RLS_SETUP_SQL = """
-- Create vectors table with tenant isolation
CREATE TABLE IF NOT EXISTS vectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    embedding vector(1536) NOT NULL,
    content TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create index for tenant + vector searches
CREATE INDEX IF NOT EXISTS idx_vectors_tenant
    ON vectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_vectors_embedding
    ON vectors USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- Enable Row-Level Security
ALTER TABLE vectors ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owner too
ALTER TABLE vectors FORCE ROW LEVEL SECURITY;

-- Policy: Users can only access their tenant's vectors
CREATE POLICY tenant_isolation_policy ON vectors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Create application role with limited permissions
CREATE ROLE vector_app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON vectors TO vector_app_role;
"""

# Application code with tenant context
class SecurePgVectorStore:
    def __init__(self, conn):
        self.conn = conn

    def set_tenant_context(self, tenant_id: str):
        """Set tenant context for RLS enforcement."""
        # Validate tenant_id format
        import uuid
        try:
            uuid.UUID(tenant_id)
        except ValueError:
            raise ValueError("Invalid tenant_id format")

        with self.conn.cursor() as cur:
            # Set session variable for RLS
            cur.execute(
                "SELECT set_config('app.current_tenant', %s, false)",
                (tenant_id,)
            )

    def query_vectors(self, tenant_id: str, query_vector: list, top_k: int = 10):
        """Query vectors with RLS enforcement."""
        # Set tenant context - RLS will filter automatically
        self.set_tenant_context(tenant_id)

        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, tenant_id, content, metadata,
                       embedding <-> %s::vector AS distance
                FROM vectors
                ORDER BY distance
                LIMIT %s
            """, (query_vector, top_k))

            results = cur.fetchall()

            # Defense in depth: verify tenant_id on every row (index 1)
            for row in results:
                if str(row[1]) != tenant_id:
                    # This should never happen with proper RLS
                    raise SecurityError("RLS policy bypass detected")

            return results

    def upsert_vector(self, tenant_id: str, vector_id: str, embedding: list,
                      content: str, metadata: dict):
        """Insert vector with RLS enforcement."""
        self.set_tenant_context(tenant_id)

        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO vectors (id, tenant_id, embedding, content, metadata)
                VALUES (%s, %s, %s::vector, %s, %s::jsonb)
                ON CONFLICT (id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    content = EXCLUDED.content,
                    metadata = EXCLUDED.metadata,
                    updated_at = NOW()
            """, (vector_id, tenant_id, embedding, content,
                  json.dumps(metadata)))
        self.conn.commit()

# Per-tenant schema isolation (alternative approach)
def create_tenant_schema(conn, tenant_id: str):
    """Create isolated schema per tenant."""
    import re

    # Validate tenant_id for schema name safety
    if not re.match(r'^[a-z0-9_]{1,63}$', tenant_id):
        raise ValueError("Invalid tenant_id format for schema name")

    schema_name = f"tenant_{tenant_id}"

    with conn.cursor() as cur:
        # Create schema
        cur.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")

        # Create vectors table in tenant schema
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {schema_name}.vectors (
                id UUID PRIMARY KEY,
                embedding vector(1536) NOT NULL,
                content TEXT,
                metadata JSONB
            )
        """)
    conn.commit()
```

**Don't**: Rely solely on application-level filtering or skip RLS for convenience

```python
# VULNERABLE: Application-level filtering only
def vulnerable_query(conn, tenant_id, query_vector):
    with conn.cursor() as cur:
        # No RLS - queries all tenants, filters client-side
        cur.execute("""
            SELECT * FROM vectors
            WHERE tenant_id = %s
            ORDER BY embedding <-> %s::vector
            LIMIT 10
        """, (tenant_id, query_vector))
        # What if tenant_id validation is bypassed elsewhere?
        return cur.fetchall()

# VULNERABLE: RLS disabled for "performance"
"""
ALTER TABLE vectors DISABLE ROW LEVEL SECURITY;
-- "We'll handle it in the application"
"""

# VULNERABLE: Superuser bypasses RLS
conn = psycopg2.connect(
    user="postgres",  # Superuser bypasses RLS
    password=os.environ["POSTGRES_PASSWORD"]
)

# VULNERABLE: Missing WITH CHECK clause
"""
CREATE POLICY bad_policy ON vectors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
    -- Missing WITH CHECK - allows inserting into other tenants
"""
```

**Why**: Application-level filtering can be bypassed through bugs, injection, or misconfiguration. RLS enforces tenant isolation at the database level, providing defense in depth. Without RLS, a single vulnerability can expose all tenant data.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: pg_hba.conf Authentication

**Level**: `strict`

**When**: Configuring PostgreSQL host-based authentication for pgvector deployments

**Do**: Require `scram-sha-256` for all host entries, restrict CIDR ranges, and reject `trust` or `md5`

```conf
# pg_hba.conf — secure configuration for pgvector deployments

# TYPE  DATABASE    USER            ADDRESS         METHOD

# Local unix-socket connections for superuser maintenance only
local   all         postgres                        peer
local   all         all                             reject

# Application user: scram-sha-256 required, narrow CIDR
host    vectordb    vector_app      10.0.1.0/24     scram-sha-256
host    vectordb    vector_app      10.0.2.0/24     scram-sha-256

# Replication — dedicated user, CIDR-restricted
host    replication replicator      10.0.1.5/32     scram-sha-256

# Reject everything else, including 0.0.0.0/0 catch-alls
host    all         all             0.0.0.0/0       reject
host    all         all             ::/0            reject
```

```python
# Programmatic validation: audit pg_hba.conf entries before deployment
import re
from pathlib import Path

FORBIDDEN_METHODS = {"trust", "md5", "password"}
FORBIDDEN_CIDRS = {"0.0.0.0/0", "::/0"}

def audit_pg_hba(hba_path: str) -> list[str]:
    """Return list of policy violations found in pg_hba.conf."""
    violations = []
    path = Path(hba_path)

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        # host/hostssl/hostnossl entries: TYPE DB USER ADDRESS METHOD
        if parts[0] in {"host", "hostssl", "hostnossl"} and len(parts) >= 5:
            address = parts[3]
            method = parts[4]

            if method in FORBIDDEN_METHODS:
                violations.append(
                    f"line {lineno}: method '{method}' forbidden — use scram-sha-256"
                )
            if address in FORBIDDEN_CIDRS:
                violations.append(
                    f"line {lineno}: CIDR '{address}' too broad — restrict to deployment subnet"
                )

    return violations
```

**Don't**: Use `trust`, `md5`, or unrestricted CIDRs in host entries

```conf
# VULNERABLE: trust allows passwordless access
host    all         all             10.0.0.0/8      trust

# VULNERABLE: md5 is cryptographically weak, vulnerable to offline cracking
host    vectordb    vector_app      0.0.0.0/0       md5

# VULNERABLE: open CIDR means any host can attempt authentication
host    all         all             0.0.0.0/0       scram-sha-256
```

**Why**: `trust` grants unconditional access to any connecting host with no password required. `md5` is a broken hash; rainbow tables and offline cracking are trivial. A wide CIDR (0.0.0.0/0) turns every internet-connected machine into a potential attacker. Combining `scram-sha-256` with narrow CIDRs ensures only legitimate application hosts can authenticate, and credentials are never transmitted in a form susceptible to offline attack.

**Refs**: OWASP A07:2025 (Identification and Authentication Failures), CWE-287, CWE-326, PostgreSQL docs §21.1

---

## Rule: Partition by tenant_id

**Level**: `strict`

**When**: Designing pgvector tables for multi-tenant deployments

**Do**: Declare `PARTITION BY LIST (tenant_id)` so the planner prunes partitions per query and physical data is isolated per tenant

```sql
-- Partitioned vectors table — one partition per tenant
CREATE TABLE vectors (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    embedding   vector(1536) NOT NULL,
    content     TEXT,
    metadata    JSONB       DEFAULT '{}',
    created_at  TIMESTAMP   DEFAULT NOW(),
    updated_at  TIMESTAMP   DEFAULT NOW()
) PARTITION BY LIST (tenant_id);

-- Each tenant gets a dedicated partition
-- Run once per onboarded tenant
CREATE TABLE vectors_tenant_11111111_1111_1111_1111_111111111111
    PARTITION OF vectors
    FOR VALUES IN ('11111111-1111-1111-1111-111111111111');

CREATE TABLE vectors_tenant_22222222_2222_2222_2222_222222222222
    PARTITION OF vectors
    FOR VALUES IN ('22222222-2222-2222-2222-222222222222');

-- Index per partition (created automatically for each child table)
CREATE INDEX ON vectors USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX ON vectors (tenant_id);

-- RLS still required; partitioning is defense-in-depth, not a substitute
ALTER TABLE vectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE vectors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_policy ON vectors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
```

```python
# Programmatic tenant partition creation
import re
import uuid

def provision_tenant_partition(conn, tenant_id: str) -> None:
    """Create a dedicated partition for a newly onboarded tenant."""
    try:
        uuid.UUID(tenant_id)
    except ValueError:
        raise ValueError(f"Invalid tenant_id UUID: {tenant_id!r}")

    # Derive a safe partition table name from the UUID
    safe_suffix = tenant_id.replace("-", "_")
    partition_name = f"vectors_tenant_{safe_suffix}"

    # Validate derived name against strict pattern before interpolation
    if not re.fullmatch(r"vectors_tenant_[0-9a-f_]{35}", partition_name):
        raise ValueError(f"Partition name failed safety check: {partition_name!r}")

    with conn.cursor() as cur:
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name}
                PARTITION OF vectors
                FOR VALUES IN (%s)
        """, (tenant_id,))
    conn.commit()

# Query: planner automatically prunes to the matching partition
async def tenant_vector_search(pool, tenant_id: str, query_vector: list,
                                top_k: int = 10) -> list:
    """Vector search that benefits from partition pruning."""
    async with pool.acquire() as conn:
        # Set tenant context for RLS
        await conn.execute(
            "SELECT set_config('app.current_tenant', $1, false)", tenant_id
        )
        # The WHERE tenant_id = $2 clause enables partition pruning;
        # only the matching child table is scanned.
        return await conn.fetch("""
            SELECT id, tenant_id, content, metadata,
                   embedding <-> $1::vector AS distance
            FROM vectors
            WHERE tenant_id = $2
            ORDER BY distance
            LIMIT $3
        """, query_vector, tenant_id, top_k)
```

**Don't**: Store all tenants in a single unpartitioned table and rely solely on a `WHERE tenant_id = ?` clause

```sql
-- RISKY: single table, no partitioning
-- Planner must scan the full index across all tenants.
-- A planner bug, misconfigured RLS, or missing WHERE clause
-- exposes every tenant's data in one sequential scan.
CREATE TABLE vectors (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    embedding vector(1536) NOT NULL,
    content   TEXT
);
```

**Why**: Partitioning enforces physical data isolation beyond what RLS alone provides. The planner prunes all non-matching partitions before scanning, so a missing or incorrect tenant filter cannot accidentally touch another tenant's rows at the storage level. Performance improves because each partition's HNSW/IVFFlat index covers only one tenant's vectors, reducing index size and improving recall accuracy at a given `ef_search`.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, PostgreSQL docs §5.11 (Table Partitioning)

---

## Rule: Index Security

**Level**: `warning`

**When**: Configuring pgvector indexes (ivfflat, hnsw)

**Do**: Choose appropriate index type for security/performance trade-offs, configure maintenance settings

```python
# Index configuration based on security requirements
INDEX_CONFIGS = {
    "high_security": {
        # HNSW: Better for smaller datasets, more consistent performance
        "type": "hnsw",
        "params": "m = 16, ef_construction = 64",
        "maintenance_work_mem": "1GB",
        "ef_search": 40  # Lower for tighter control
    },
    "balanced": {
        # IVFFlat: Good for larger datasets
        "type": "ivfflat",
        "lists": 100,
        "probes": 10,
        "maintenance_work_mem": "2GB"
    },
    "high_performance": {
        "type": "hnsw",
        "params": "m = 32, ef_construction = 128",
        "maintenance_work_mem": "4GB",
        "ef_search": 100
    }
}

def create_secure_index(conn, config_name: str = "balanced"):
    """Create index with security-conscious configuration."""
    config = INDEX_CONFIGS[config_name]

    with conn.cursor() as cur:
        # Set maintenance memory for index building
        cur.execute(f"SET maintenance_work_mem = '{config['maintenance_work_mem']}'")

        if config["type"] == "hnsw":
            cur.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_vectors_hnsw
                ON vectors USING hnsw (embedding vector_cosine_ops)
                WITH ({config['params']})
            """)
        else:  # ivfflat
            cur.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_vectors_ivfflat
                ON vectors USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = {config['lists']})
            """)
    conn.commit()

def set_search_params(conn, config_name: str = "balanced"):
    """Set search parameters for security/performance balance."""
    config = INDEX_CONFIGS[config_name]

    with conn.cursor() as cur:
        if config["type"] == "hnsw":
            # Lower ef_search = faster but less accurate
            cur.execute(f"SET hnsw.ef_search = {config.get('ef_search', 40)}")
        else:
            # Lower probes = faster but less accurate
            cur.execute(f"SET ivfflat.probes = {config.get('probes', 10)}")

# Index maintenance scheduling
MAINTENANCE_SQL = """
-- Reindex to maintain performance and prevent bloat
REINDEX INDEX CONCURRENTLY idx_vectors_ivfflat;

-- Analyze for query planner optimization
ANALYZE vectors;

-- Vacuum to reclaim space
VACUUM ANALYZE vectors;
"""

def schedule_index_maintenance(conn):
    """Schedule regular index maintenance."""
    # Run during low-traffic periods
    with conn.cursor() as cur:
        cur.execute("REINDEX INDEX CONCURRENTLY idx_vectors_ivfflat")
        cur.execute("ANALYZE vectors")
```

**Don't**: Use default settings without consideration or skip index maintenance

```python
# RISKY: No index for large tables
# Full table scans expose timing side channels and cause DoS
cur.execute("""
    SELECT * FROM vectors
    ORDER BY embedding <-> %s::vector
    LIMIT 10
""", (query_vector,))  # Sequential scan on millions of rows

# RISKY: Overly permissive search parameters
cur.execute("SET ivfflat.probes = 1000")  # Searches almost all lists
cur.execute("SET hnsw.ef_search = 1000")  # Very slow queries

# RISKY: Never maintaining indexes
# Index bloat degrades performance and can cause DoS
```

**Why**: Index configuration affects query timing consistency (timing attacks), resource usage (DoS), and data access patterns. Poor maintenance leads to degraded performance and potential availability issues.

**Refs**: CWE-400 (Resource Exhaustion), CWE-208 (Observable Timing Discrepancy)

---

## Rule: Extension Security

**Level**: `warning`

**When**: Installing and managing the pgvector extension

**Do**: Install extension as superuser only, verify extension integrity, limit extension permissions

```sql
-- Install pgvector extension (superuser only)
-- First verify the extension source is trusted

-- Check available extensions and their versions
SELECT * FROM pg_available_extensions WHERE name = 'vector';

-- Install extension in dedicated schema
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS vector SCHEMA extensions;

-- Verify extension installation
SELECT extname, extversion, extnamespace::regnamespace
FROM pg_extension
WHERE extname = 'vector';

-- Grant usage to application role (not ownership)
GRANT USAGE ON SCHEMA extensions TO vector_app_role;

-- Limit function execution
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA extensions FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA extensions TO vector_app_role;
```

```python
# Application code to verify extension
def verify_pgvector_extension(conn):
    """Verify pgvector extension is properly installed."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT extversion
            FROM pg_extension
            WHERE extname = 'vector'
        """)
        result = cur.fetchone()

        if not result:
            raise RuntimeError("pgvector extension not installed")

        version = result[0]
        min_version = "0.5.0"  # Minimum secure version

        if version < min_version:
            raise RuntimeError(f"pgvector version {version} is below minimum {min_version}")

        return version
```

**Don't**: Allow untrusted users to install extensions or use outdated versions

```sql
-- DANGEROUS: Allow non-superuser to create extensions
GRANT CREATE ON DATABASE vectordb TO app_user;
-- app_user could install malicious extensions

-- DANGEROUS: Using extension from untrusted source
CREATE EXTENSION vector FROM untrusted_source;

-- DANGEROUS: Not updating vulnerable versions
-- Old pgvector versions may have security issues
```

**Why**: PostgreSQL extensions run with database privileges and can access all data. Malicious or vulnerable extensions can compromise the entire database. Only trusted extensions should be installed by database administrators.

**Refs**: CWE-829 (Inclusion of Untrusted Functionality), CWE-269 (Improper Privilege Management)

---

## Rule: Backup Security

**Level**: `strict`

**When**: Creating backups of pgvector databases

**Do**: Encrypt backups, secure WAL archiving, verify backup integrity

```bash
#!/bin/bash
# Encrypted pg_dump backup

# Set variables
BACKUP_DIR="/secure/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/vectors_${TIMESTAMP}.sql"
ENCRYPTED_FILE="${BACKUP_FILE}.gpg"

# Create backup with compression
PGPASSWORD="${PGVECTOR_PASSWORD}" pg_dump \
    -h "${PGVECTOR_HOST}" \
    -U "${PGVECTOR_USER}" \
    -d "${PGVECTOR_DATABASE}" \
    --format=custom \
    --compress=9 \
    --file="${BACKUP_FILE}"

# Encrypt backup
gpg --encrypt \
    --recipient "${BACKUP_GPG_KEY}" \
    --output "${ENCRYPTED_FILE}" \
    "${BACKUP_FILE}"

# Generate checksum
sha256sum "${ENCRYPTED_FILE}" > "${ENCRYPTED_FILE}.sha256"

# Remove unencrypted backup
shred -u "${BACKUP_FILE}"

# Upload to secure storage (example: S3 with server-side encryption)
aws s3 cp "${ENCRYPTED_FILE}" "s3://${BACKUP_BUCKET}/vectors/" \
    --sse aws:kms \
    --sse-kms-key-id "${KMS_KEY_ID}"
```

```python
# Python backup with encryption
import subprocess
import hashlib
from cryptography.fernet import Fernet

def create_encrypted_backup(config: dict) -> str:
    """Create encrypted backup of pgvector database."""
    import tempfile
    import os

    # Create temporary file for unencrypted backup
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_path = tmp.name

    try:
        # Run pg_dump
        result = subprocess.run([
            "pg_dump",
            "-h", config["host"],
            "-U", config["user"],
            "-d", config["database"],
            "--format=custom",
            "--compress=9",
            "-f", temp_path
        ], env={
            **os.environ,
            "PGPASSWORD": config["password"]
        }, check=True, capture_output=True)

        # Read backup data
        with open(temp_path, "rb") as f:
            backup_data = f.read()

        # Encrypt with Fernet
        key = os.environ["BACKUP_ENCRYPTION_KEY"].encode()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(backup_data)

        # Calculate checksum
        checksum = hashlib.sha256(encrypted_data).hexdigest()

        # Write encrypted backup
        backup_path = f"/backups/vectors_{config['database']}_{checksum[:8]}.enc"
        with open(backup_path, "wb") as f:
            f.write(encrypted_data)

        # Log backup event
        audit_log.info(
            "backup_created",
            database=config["database"],
            path=backup_path,
            checksum=checksum,
            size=len(encrypted_data)
        )

        return backup_path, checksum

    finally:
        # Securely delete temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

def restore_encrypted_backup(backup_path: str, expected_checksum: str, config: dict):
    """Restore encrypted backup with integrity verification."""
    import tempfile

    # Read encrypted backup
    with open(backup_path, "rb") as f:
        encrypted_data = f.read()

    # Verify checksum
    actual_checksum = hashlib.sha256(encrypted_data).hexdigest()
    if actual_checksum != expected_checksum:
        raise IntegrityError(f"Backup checksum mismatch: {actual_checksum} != {expected_checksum}")

    # Decrypt
    key = os.environ["BACKUP_ENCRYPTION_KEY"].encode()
    fernet = Fernet(key)
    backup_data = fernet.decrypt(encrypted_data)

    # Restore to temporary file and pg_restore
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(backup_data)
        temp_path = tmp.name

    try:
        subprocess.run([
            "pg_restore",
            "-h", config["host"],
            "-U", config["user"],
            "-d", config["database"],
            "--clean",
            "--if-exists",
            temp_path
        ], env={
            **os.environ,
            "PGPASSWORD": config["password"]
        }, check=True)

        audit_log.info("backup_restored", backup_path=backup_path)

    finally:
        os.remove(temp_path)
```

```sql
-- WAL archiving configuration (postgresql.conf)
archive_mode = on
archive_command = 'gpg --encrypt --recipient backup@company.com -o /archive/%f.gpg %p'
wal_level = replica

-- Point-in-time recovery with encrypted archives
-- restore_command = 'gpg --decrypt /archive/%f.gpg > %p'
```

**Don't**: Store unencrypted backups or skip integrity verification

```bash
# VULNERABLE: Unencrypted backup
pg_dump -d vectordb > /backups/vectors.sql
# Plaintext backup with all vector data

# VULNERABLE: No integrity verification on restore
pg_restore -d vectordb /backups/vectors.backup
# Could restore tampered backup

# VULNERABLE: Backups in public location
pg_dump -d vectordb > /tmp/backup.sql
chmod 644 /tmp/backup.sql
# World-readable backup
```

**Why**: pgvector backups contain all embeddings and metadata, potentially including sensitive information. Unencrypted backups can be exfiltrated or tampered with. Integrity verification prevents restoring malicious backups.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, CWE-312

---

## Rule: Performance Limits

**Level**: `warning`

**When**: Configuring query performance parameters to prevent resource exhaustion

**Do**: Set appropriate limits for probes, ef_search, and query timeouts

```python
# Configure safe performance limits
def configure_performance_limits(conn, environment: str = "production"):
    """Set performance limits based on environment."""

    limits = {
        "production": {
            "statement_timeout": "30s",
            "ivfflat_probes": 10,
            "hnsw_ef_search": 40,
            "work_mem": "256MB",
            "max_parallel_workers": 2
        },
        "development": {
            "statement_timeout": "60s",
            "ivfflat_probes": 20,
            "hnsw_ef_search": 100,
            "work_mem": "512MB",
            "max_parallel_workers": 4
        }
    }

    config = limits.get(environment, limits["production"])

    with conn.cursor() as cur:
        # Query timeout to prevent long-running queries
        cur.execute(f"SET statement_timeout = '{config['statement_timeout']}'")

        # IVFFlat probes limit
        cur.execute(f"SET ivfflat.probes = {config['ivfflat_probes']}")

        # HNSW ef_search limit
        cur.execute(f"SET hnsw.ef_search = {config['hnsw_ef_search']}")

        # Memory limits
        cur.execute(f"SET work_mem = '{config['work_mem']}'")

        # Parallel query limits
        cur.execute(f"SET max_parallel_workers_per_gather = {config['max_parallel_workers']}")

# Query with resource limits
class RateLimitedVectorStore:
    def __init__(self, conn, max_requests_per_minute: int = 100):
        self.conn = conn
        self.rate_limiter = RateLimiter(max_requests_per_minute)

    def query(self, tenant_id: str, query_vector: list, top_k: int = 10):
        """Query with rate limiting and resource controls."""
        # Rate limiting
        if not self.rate_limiter.allow():
            raise RateLimitError("Too many requests")

        # Limit top_k to prevent large result sets
        top_k = min(top_k, 100)

        # Validate vector dimensions
        if len(query_vector) != 1536:
            raise ValueError(f"Invalid vector dimension: {len(query_vector)}")

        with self.conn.cursor() as cur:
            # Set query-specific timeout
            cur.execute("SET LOCAL statement_timeout = '10s'")

            cur.execute("""
                SELECT id, content, embedding <-> %s::vector AS distance
                FROM vectors
                WHERE tenant_id = %s
                ORDER BY distance
                LIMIT %s
            """, (query_vector, tenant_id, top_k))

            return cur.fetchall()

# Monitor query performance
def log_slow_queries(conn, threshold_ms: int = 1000):
    """Enable logging for slow vector queries."""
    with conn.cursor() as cur:
        cur.execute(f"""
            ALTER SYSTEM SET log_min_duration_statement = {threshold_ms};
            SELECT pg_reload_conf();
        """)
```

**Don't**: Allow unlimited query parameters or skip resource controls

```python
# VULNERABLE: User controls probes directly
def vulnerable_query(conn, query_vector, probes):
    with conn.cursor() as cur:
        # Attacker sets probes = 10000 for DoS
        cur.execute(f"SET ivfflat.probes = {probes}")
        cur.execute("SELECT * FROM vectors ORDER BY embedding <-> %s::vector",
                    (query_vector,))

# VULNERABLE: No top_k limit
def vulnerable_unlimited(conn, query_vector, top_k):
    # Attacker requests top_k = 1000000
    cur.execute("SELECT * FROM vectors ORDER BY embedding <-> %s::vector LIMIT %s",
                (query_vector, top_k))

# VULNERABLE: No query timeout
conn = psycopg2.connect(...)
# Default: no statement_timeout
# Malicious query can run indefinitely
```

**Why**: Unrestricted performance parameters enable denial of service attacks. High probes/ef_search values cause expensive queries. Large result sets consume memory and bandwidth. Query timeouts prevent resource exhaustion from complex searches.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation without Limits)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 security rules |
| 1.1 | 2026-05-26 | OWASP refs updated to 2025; added pg_hba.conf auth rule and partition-by-tenant_id rule; fixed RLS defense-in-depth column index |

---

## Additional Resources

- [pgvector GitHub Repository](https://github.com/pgvector/pgvector)
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL SSL Configuration](https://www.postgresql.org/docs/current/ssl-tcp.html)
- [PostgreSQL Table Partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)
- [PostgreSQL pg_hba.conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Core Vector Store Security Rules](../../_core/vector-store-security.md)
