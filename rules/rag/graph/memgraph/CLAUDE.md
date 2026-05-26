# CLAUDE.md - Memgraph Security Rules

Security rules for Memgraph graph database in RAG and AI applications.

**Prerequisites**: `rules/_core/rag-security.md`, `rules/_core/graph-database-security.md`

---

## Rule: Cypher Injection Prevention with Parameters

**Level**: `strict`

**When**: Executing any Cypher query with user-supplied data

**Do**: Use parameterized queries with gqlalchemy or neo4j driver
```python
from gqlalchemy import Memgraph

memgraph = Memgraph()

# Parameterized query - safe
def find_user(user_id: str):
    query = """
        MATCH (u:User {id: $user_id})
        RETURN u.name, u.email
    """
    results = memgraph.execute_and_fetch(query, {"user_id": user_id})
    return list(results)

# With neo4j driver
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687")
with driver.session() as session:
    result = session.run(
        "MATCH (n:Document) WHERE n.title = $title RETURN n",
        title=user_input
    )
```

**Don't**: Concatenate user input into Cypher queries
```python
# VULNERABLE - Cypher injection
def find_user_unsafe(user_id: str):
    query = f"MATCH (u:User {{id: '{user_id}'}}) RETURN u"
    return memgraph.execute_and_fetch(query)

# Attacker input: "' OR 1=1 WITH u MATCH (n) DETACH DELETE n //"
# Results in data destruction
```

**Why**: Cypher injection allows attackers to extract unauthorized data, modify graph structure, delete nodes/relationships, or bypass access controls. In-memory databases like Memgraph can lose all data if DELETE queries execute.

**Refs**: CWE-89 (Injection), OWASP A03:2025 (Injection), Memgraph Security Docs

---

## Rule: In-Memory Data Protection and Encryption

**Level**: `strict`

**When**: Storing sensitive data in Memgraph or configuring persistence

**Do**: Enable TLS for connections and encrypt sensitive properties
```python
from gqlalchemy import Memgraph
from cryptography.fernet import Fernet

# Enable TLS connection
memgraph = Memgraph(
    host="localhost",
    port=7687,
    encrypted=True,
    client_name="secure-app"
)

# Encrypt sensitive data before storage
cipher = Fernet(os.environ["ENCRYPTION_KEY"])

def store_sensitive_document(doc_id: str, content: str, pii_data: str):
    encrypted_pii = cipher.encrypt(pii_data.encode()).decode()
    query = """
        CREATE (d:Document {
            id: $doc_id,
            content: $content,
            pii_data: $encrypted_pii
        })
    """
    memgraph.execute(query, {
        "doc_id": doc_id,
        "content": content,
        "encrypted_pii": encrypted_pii
    })

# Configure Memgraph with TLS (memgraph.conf)
# --bolt-cert-file=/path/to/cert.pem
# --bolt-key-file=/path/to/key.pem
```

**Don't**: Store sensitive data unencrypted or use unencrypted connections
```python
# VULNERABLE - No encryption
memgraph = Memgraph(host="localhost", port=7687)

def store_user_unsafe(user_data: dict):
    query = f"""
        CREATE (u:User {{
            ssn: '{user_data["ssn"]}',
            credit_card: '{user_data["credit_card"]}'
        }})
    """
    memgraph.execute(query)
```

**Why**: Memgraph is an in-memory database; all data resides in RAM. Without encryption, memory dumps, network sniffing, or unauthorized access expose sensitive data. TLS protects data in transit; property encryption protects data at rest in memory.

**Refs**: CWE-311 (Missing Encryption), OWASP A02:2025 (Cryptographic Failures), NIST SP 800-111

---

## Rule: User Authentication and Role-Based Access

**Level**: `strict`

**When**: Configuring Memgraph access or connecting from applications

**Do**: Enable authentication with strong credentials and role-based permissions
```python
from gqlalchemy import Memgraph

# Connect with authentication
memgraph = Memgraph(
    host="localhost",
    port=7687,
    username=os.environ["MEMGRAPH_USER"],
    password=os.environ["MEMGRAPH_PASSWORD"],
    encrypted=True
)

# Create roles and users (admin operation)
def setup_rbac():
    # Create custom role with limited permissions
    memgraph.execute("CREATE ROLE reader")
    memgraph.execute("GRANT MATCH TO reader")
    memgraph.execute("DENY CREATE, DELETE, SET TO reader")

    # Create user with role
    memgraph.execute(
        "CREATE USER app_reader IDENTIFIED BY $password",
        {"password": generate_strong_password()}
    )
    memgraph.execute("SET ROLE FOR app_reader TO reader")

    # Label-based access control
    memgraph.execute("GRANT READ ON LABELS :PublicDoc TO reader")
    memgraph.execute("DENY READ ON LABELS :InternalDoc TO reader")

# Application connection with least privilege
app_memgraph = Memgraph(
    host="localhost",
    port=7687,
    username="app_reader",
    password=os.environ["APP_READER_PASSWORD"],
    encrypted=True
)
```

**Don't**: Use default credentials or disable authentication
```python
# VULNERABLE - No authentication
memgraph = Memgraph(host="localhost", port=7687)

# VULNERABLE - Hardcoded credentials
memgraph = Memgraph(
    host="localhost",
    port=7687,
    username="admin",
    password="admin123"  # Hardcoded weak password
)
```

**Why**: Memgraph Enterprise supports fine-grained RBAC. Without authentication, any network-accessible client can read/modify/delete all graph data. Role-based access ensures applications only access permitted labels and operations.

**Refs**: CWE-287 (Improper Authentication), OWASP A07:2025 (Identification and Authentication Failures)

---

## Rule: Streaming Data Security (Kafka, Pulsar Connectors)

**Level**: `strict`

**When**: Configuring Memgraph stream connectors for real-time data ingestion

**Do**: Secure stream connections with TLS, authentication, and input validation
```python
# Kafka stream with security (Cypher in Memgraph)
kafka_stream_query = """
    CREATE KAFKA STREAM documents
    TOPICS rag_documents
    TRANSFORM rag.transform_document
    BOOTSTRAP_SERVERS 'kafka.internal:9093'
    CONSUMER_GROUP 'memgraph-rag'
    CONFIGS {
        'security.protocol': 'SASL_SSL',
        'sasl.mechanism': 'SCRAM-SHA-512',
        'sasl.username': 'memgraph_consumer',
        'sasl.password': '$KAFKA_PASSWORD',
        'ssl.ca.location': '/certs/ca.pem'
    }
"""

# Transformation procedure with validation (Python MAGE module)
import mgp

@mgp.transformation
def transform_document(messages: mgp.Messages) -> mgp.Record(query=str, parameters=mgp.Map):
    result = []
    for msg in messages:
        try:
            payload = msg.payload().decode('utf-8')
            data = json.loads(payload)

            # Validate and sanitize input
            doc_id = validate_uuid(data.get('id'))
            content = sanitize_text(data.get('content', ''), max_length=10000)

            if not doc_id or not content:
                log_invalid_message(msg)
                continue

            result.append(mgp.Record(
                query="MERGE (d:Document {id: $id}) SET d.content = $content",
                parameters={"id": doc_id, "content": content}
            ))
        except Exception as e:
            log_error(f"Transform error: {e}")
    return result
```

**Don't**: Use unencrypted streams or skip input validation
```python
# VULNERABLE - No encryption, no auth
create_stream_query = """
    CREATE KAFKA STREAM docs
    TOPICS documents
    TRANSFORM rag.unsafe_transform
    BOOTSTRAP_SERVERS 'kafka:9092'
"""

# VULNERABLE - No input validation in transformation
@mgp.transformation
def unsafe_transform(messages: mgp.Messages):
    for msg in messages:
        data = json.loads(msg.payload())
        # Directly using untrusted data
        return mgp.Record(
            query=f"CREATE (d:Doc {{content: '{data['content']}'}})",
            parameters={}
        )
```

**Why**: Stream connectors continuously ingest data from external sources. Without TLS and authentication, attackers can intercept or inject malicious messages. Transformation procedures must validate all input to prevent Cypher injection and resource exhaustion.

**Refs**: CWE-319 (Cleartext Transmission), OWASP A08:2025 (Software and Data Integrity Failures)

---

## Rule: MAGE Algorithm Security (Graph Algorithms)

**Level**: `warning`

**When**: Using MAGE graph algorithms or custom query modules

**Do**: Validate inputs, set resource limits, and audit algorithm usage
```python
import mgp

# Custom MAGE procedure with security controls
@mgp.read_proc
def secure_pagerank(
    ctx: mgp.ProcCtx,
    label: str,
    max_iterations: mgp.Nullable[int] = 100,
    damping_factor: mgp.Nullable[float] = 0.85
) -> mgp.Record(node=mgp.Vertex, rank=float):

    # Validate inputs
    if max_iterations is None or max_iterations > 1000:
        max_iterations = 100  # Enforce reasonable limit

    if damping_factor is None or not (0 < damping_factor < 1):
        damping_factor = 0.85

    # Validate label exists and user has access
    allowed_labels = ["PublicDocument", "SharedNode"]
    if label not in allowed_labels:
        raise mgp.AbortError(f"Access denied for label: {label}")

    # Execute with resource awareness
    nodes = list(ctx.graph.vertices)
    if len(nodes) > 100000:
        raise mgp.AbortError("Graph too large for PageRank - use sampling")

    # Log algorithm execution for audit
    log_algorithm_usage(ctx, "pagerank", {"label": label, "nodes": len(nodes)})

    # Run algorithm...
    results = compute_pagerank(nodes, max_iterations, damping_factor)
    return results

# Calling secure algorithms from application
def get_important_documents(memgraph, label: str):
    # Use parameterized call
    query = """
        CALL rag.secure_pagerank($label, $max_iter, $damping)
        YIELD node, rank
        RETURN node.id, rank
        ORDER BY rank DESC
        LIMIT 10
    """
    return memgraph.execute_and_fetch(query, {
        "label": label,
        "max_iter": 100,
        "damping": 0.85
    })
```

**Don't**: Run algorithms without input validation or resource limits
```python
# VULNERABLE - No input validation or limits
@mgp.read_proc
def unsafe_pagerank(ctx: mgp.ProcCtx, iterations: int):
    # Attacker can set iterations=999999999
    nodes = list(ctx.graph.vertices)
    # No size check - can exhaust memory
    for i in range(iterations):
        # Expensive computation
        pass
```

**Why**: Graph algorithms can be computationally expensive. MAGE procedures execute in Memgraph's memory space. Unbounded iterations or large graph traversals cause resource exhaustion (CPU, memory), leading to denial of service or system crashes.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), MITRE ATLAS ML04

---

## Rule: Query Execution Limits (Memory, Time)

**Level**: `strict`

**When**: Configuring Memgraph or executing queries in production

**Do**: Set query memory and timeout limits in configuration and code
```python
# memgraph.conf - Server-side limits
# --query-execution-timeout-sec=30
# --memory-limit=8192  # MB

from gqlalchemy import Memgraph

memgraph = Memgraph()

# Set session-level limits
def execute_with_limits(query: str, params: dict, timeout_ms: int = 5000):
    # Set query timeout for this session
    memgraph.execute(f"SET QUERY EXECUTION TIMEOUT TO {timeout_ms}")

    try:
        results = memgraph.execute_and_fetch(query, params)
        return list(results)
    except Exception as e:
        if "timeout" in str(e).lower():
            log_query_timeout(query, params)
            raise QueryTimeoutError("Query exceeded time limit")
        raise

# Wrapper with memory-aware query execution
def safe_graph_query(query: str, params: dict, max_results: int = 1000):
    # Add LIMIT to prevent unbounded results
    if "LIMIT" not in query.upper():
        query = f"{query} LIMIT {max_results}"

    return execute_with_limits(query, params)

# Application usage
def search_documents(search_term: str):
    query = """
        MATCH (d:Document)
        WHERE d.content CONTAINS $term
        RETURN d.id, d.title
        LIMIT 100
    """
    return safe_graph_query(query, {"term": search_term})
```

**Don't**: Allow unbounded queries or skip resource limits
```python
# VULNERABLE - No limits
def search_all_unsafe(pattern: str):
    query = f"""
        MATCH (n)
        WHERE n.content CONTAINS '{pattern}'
        RETURN n
    """
    # Can return millions of nodes, exhausting memory
    return memgraph.execute_and_fetch(query)

# VULNERABLE - Expensive traversal without limits
def find_all_paths_unsafe(start_id: str, end_id: str):
    query = """
        MATCH path = (a)-[*]-(b)
        WHERE a.id = $start AND b.id = $end
        RETURN path
    """
    # Unbounded path length can exhaust resources
    return memgraph.execute_and_fetch(query, {
        "start": start_id, "end": end_id
    })
```

**Why**: As an in-memory database, Memgraph is vulnerable to memory exhaustion from large result sets or expensive traversals. Unbounded queries can crash the server, losing all data. Time limits prevent long-running queries from blocking resources.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), OWASP A05:2025 (Security Misconfiguration)

---

## Rule: Audit Logging Configuration

**Level**: `warning`

**When**: Deploying Memgraph in production environments

**Do**: Enable comprehensive audit logging with secure storage
```python
# memgraph.conf - Enable audit logging
# --audit-enabled=true
# --audit-buffer-size=10000
# --audit-buffer-flush-interval-ms=1000

# Configure audit log output (MAGE module)
import mgp
import json
from datetime import datetime

@mgp.read_proc
def configure_audit(ctx: mgp.ProcCtx) -> mgp.Record(status=str):
    # Set up audit log stream
    audit_config = """
        CREATE KAFKA STREAM audit_logs
        TOPICS memgraph_audit
        BOOTSTRAP_SERVERS 'kafka:9093'
        CONFIGS {
            'security.protocol': 'SASL_SSL'
        }
    """
    # Execute audit configuration...
    return mgp.Record(status="Audit logging configured")

# Application-level audit logging
class AuditLogger:
    def __init__(self, memgraph):
        self.memgraph = memgraph

    def log_query(self, user: str, query: str, params: dict, result_count: int):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": "QUERY",
            "query_hash": hash_query(query),  # Don't log full query with params
            "result_count": result_count,
            "client_ip": get_client_ip()
        }

        # Store in separate audit graph or external system
        self.memgraph.execute("""
            CREATE (a:AuditLog {
                timestamp: $ts,
                user: $user,
                action: $action,
                details: $details
            })
        """, {
            "ts": audit_entry["timestamp"],
            "user": audit_entry["user"],
            "action": audit_entry["action"],
            "details": json.dumps(audit_entry)
        })

    def log_admin_action(self, user: str, action: str, target: str):
        # Log privilege changes, user management, etc.
        pass

# Usage in application
audit = AuditLogger(memgraph)

def query_with_audit(user: str, query: str, params: dict):
    results = list(memgraph.execute_and_fetch(query, params))
    audit.log_query(user, query, params, len(results))
    return results
```

**Don't**: Disable audit logging or log sensitive data
```python
# VULNERABLE - No audit logging
# memgraph.conf
# --audit-enabled=false

# VULNERABLE - Logging sensitive parameters
def log_query_unsafe(query: str, params: dict):
    # Logs passwords, PII, etc.
    print(f"Query: {query}, Params: {params}")
```

**Why**: Audit logs provide forensic evidence for security incidents, compliance requirements, and access pattern analysis. Without logging, unauthorized access or data exfiltration goes undetected. Logs must not contain sensitive data (credentials, PII).

**Refs**: CWE-778 (Insufficient Logging), OWASP A09:2025 (Security Logging and Monitoring Failures)

---

## Rule: Replication and High Availability Security

**Level**: `warning`

**When**: Configuring Memgraph replication or clustering

**Do**: Secure replication channels with TLS and authentication
```python
# memgraph.conf for MAIN instance
# --replication-restore-state-on-startup=true
# --bolt-cert-file=/certs/server.pem
# --bolt-key-file=/certs/server.key

# Register REPLICA with TLS (execute on MAIN)
register_replica_query = """
    REGISTER REPLICA replica_1
    SYNC WITH TIMEOUT 10
    TO 'replica1.internal:10000'
    SSL {
        'enabled': true,
        'client_cert_file': '/certs/client.pem',
        'client_key_file': '/certs/client.key'
    }
"""

# Python application for secure replica management
from gqlalchemy import Memgraph

def setup_secure_replication(main_memgraph: Memgraph, replicas: list):
    # Verify we're connected to MAIN
    role = main_memgraph.execute_and_fetch("SHOW REPLICATION ROLE")
    if list(role)[0]["role"] != "main":
        raise SecurityError("Not connected to MAIN instance")

    for replica in replicas:
        # Validate replica hostname
        if not is_internal_hostname(replica["host"]):
            raise SecurityError(f"External replica not allowed: {replica['host']}")

        query = """
            REGISTER REPLICA $name
            SYNC WITH TIMEOUT $timeout
            TO $endpoint
        """
        main_memgraph.execute(query, {
            "name": replica["name"],
            "timeout": replica.get("timeout", 10),
            "endpoint": f"{replica['host']}:{replica['port']}"
        })

        log_replication_event("REGISTER", replica["name"])

# Monitor replication status
def check_replication_health(memgraph: Memgraph):
    replicas = memgraph.execute_and_fetch("SHOW REPLICAS")
    for replica in replicas:
        if replica["state"] != "ready":
            alert_replication_issue(replica["name"], replica["state"])

        # Check for replication lag
        if replica.get("behind") and replica["behind"] > 1000:
            alert_replication_lag(replica["name"], replica["behind"])
```

**Don't**: Use unencrypted replication or expose replication ports externally
```python
# VULNERABLE - No TLS for replication
register_query = """
    REGISTER REPLICA replica_1
    SYNC TO 'replica1:10000'
"""

# VULNERABLE - External/public replica
register_query = """
    REGISTER REPLICA external
    SYNC TO 'public-ip.example.com:10000'
"""

# VULNERABLE - No authentication on replication port
# memgraph.conf
# --replication-server-port=10000  # Exposed without auth
```

**Why**: Replication streams contain all graph data and transactions. Unencrypted replication exposes data to network sniffing. Unauthorized replica registration allows attackers to exfiltrate data or inject malicious transactions. Replication must use internal networks with TLS.

**Refs**: CWE-319 (Cleartext Transmission), CWE-306 (Missing Authentication), OWASP A05:2025 (Security Misconfiguration)

---

<!-- audit_trail:
- file: rules/rag/graph/memgraph/CLAUDE.md
  date: 2026-05-26
  auditor: p0.5
  status: failed
  defects:
    - id: D1
      description: >
        gqlalchemy TLS API incorrect. Memgraph(encrypted=True) is not a valid
        gqlalchemy constructor kwarg; that pattern belongs to the neo4j driver.
        gqlalchemy uses bolt+s:// URI or ca/cert/key SSL kwargs. Multiple rules
        show encrypted=True on gqlalchemy connections, which silently ignores TLS.
    - id: D2
      description: >
        pymgclient not mentioned. The file covers gqlalchemy and the neo4j driver
        but omits pymgclient, the other supported native Memgraph Python client.
        bolt+s:// TLS URI scheme is also absent from all application-level examples.
    - id: D3
      description: >
        LOAD CSV trust gap. No rule covers LOAD CSV with untrusted or
        user-supplied URLs, which can cause SSRF or load malicious data.
    - id: D4
      description: >
        Memgraph Lab UI auth not covered. No rule addresses Lab default
        credentials, unauthenticated Lab exposure, or network-isolation requirements
        for the web UI.
    - id: D5
      description: >
        OWASP LLM Top 10 2025 refs missing. No rule references the LLM Top 10;
        for a RAG-context file prompt-injection (LLM01:2025) and insecure output
        handling (LLM02:2025) are directly applicable.
    - id: D6
      description: >
        MAGE module trust gap. The MAGE rule covers resource limits but not
        module provenance: --query-modules-directory permissions, C shared-library
        signing, Python module source vetting, and restricting which modules load
        in production are all absent.
-->
