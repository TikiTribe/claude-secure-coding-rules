# Neo4j Security Rules

Security rules for Neo4j graph database implementations in RAG and knowledge graph systems.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Cypher Injection Prevention | `strict` | Query manipulation, data exfiltration |
| APOC Procedure Security | `strict` | Remote code execution, system compromise |
| Traversal Depth Limits | `strict` | Denial of service, resource exhaustion |
| Role-Based Access Control | `strict` | Unauthorized data access |
| GDS Algorithm Security | `warning` | Memory exhaustion, projection leakage |
| Vector Index Security | `warning` | Similarity search abuse, index corruption |
| Import/Export Security | `strict` | Data tampering, unauthorized exports |
| Bolt Connection Security | `strict` | Data interception, credential theft |

---

## Rule: Cypher Injection Prevention

**Level**: `strict`

**When**: Constructing Cypher queries with user-provided input

**Do**: Use parameterized queries for all user input, validate input patterns

```python
from neo4j import GraphDatabase
import re

# Secure Neo4j client with parameterized queries
class SecureNeo4jClient:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            encrypted=True,
            trust=neo4j.TRUST_SYSTEM_CA_SIGNED_CERTIFICATES
        )

    def find_similar_documents(self, embedding: list, tenant_id: str, top_k: int = 10):
        """Query with parameterized Cypher - SECURE."""
        # Validate inputs
        if not isinstance(top_k, int) or top_k < 1 or top_k > 100:
            raise ValueError("top_k must be between 1 and 100")

        if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
            raise ValueError("Invalid tenant_id format")

        with self.driver.session() as session:
            # Parameters are safely escaped by the driver
            result = session.run("""
                MATCH (d:Document {tenant_id: $tenant_id})
                WHERE d.embedding IS NOT NULL
                WITH d, gds.similarity.cosine(d.embedding, $embedding) AS score
                WHERE score > 0.7
                RETURN d.id AS id, d.content AS content, score
                ORDER BY score DESC
                LIMIT $top_k
            """, {
                "tenant_id": tenant_id,
                "embedding": embedding,
                "top_k": top_k
            })
            return [record.data() for record in result]

    def search_by_property(self, property_name: str, value: str, tenant_id: str):
        """Safe property search with allowlist validation."""
        # Allowlist of searchable properties
        ALLOWED_PROPERTIES = {"title", "category", "status", "created_date"}

        if property_name not in ALLOWED_PROPERTIES:
            raise ValueError(f"Property '{property_name}' not searchable")

        with self.driver.session() as session:
            # Property name is validated against allowlist
            # Value is parameterized
            query = f"""
                MATCH (d:Document {{tenant_id: $tenant_id}})
                WHERE d.{property_name} = $value
                RETURN d
            """
            result = session.run(query, {
                "tenant_id": tenant_id,
                "value": value
            })
            return [record["d"] for record in result]

    def create_relationship(self, from_id: str, to_id: str, rel_type: str, tenant_id: str):
        """Create relationship with strict validation."""
        # Validate relationship type against allowlist
        ALLOWED_REL_TYPES = {"REFERENCES", "SIMILAR_TO", "PART_OF", "AUTHORED_BY"}

        if rel_type not in ALLOWED_REL_TYPES:
            raise ValueError(f"Relationship type '{rel_type}' not allowed")

        # Validate IDs
        if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', from_id):
            raise ValueError("Invalid from_id format")
        if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', to_id):
            raise ValueError("Invalid to_id format")

        with self.driver.session() as session:
            result = session.run(f"""
                MATCH (a:Document {{id: $from_id, tenant_id: $tenant_id}})
                MATCH (b:Document {{id: $to_id, tenant_id: $tenant_id}})
                CREATE (a)-[r:{rel_type}]->(b)
                RETURN r
            """, {
                "from_id": from_id,
                "to_id": to_id,
                "tenant_id": tenant_id
            })
            return result.single()
```

**Don't**: Concatenate user input directly into Cypher queries

```python
# VULNERABLE: String concatenation allows injection
def find_documents(user_input):
    query = f"MATCH (d:Document) WHERE d.title = '{user_input}' RETURN d"
    # Attacker input: "' OR 1=1 WITH d MATCH (n) DETACH DELETE n //"
    return session.run(query)

# VULNERABLE: Unvalidated property names
def search_property(property_name, value):
    query = f"MATCH (d) WHERE d.{property_name} = $value RETURN d"
    # Attacker can inject: "id})-[:ADMIN]->() WITH d MATCH (n"
    return session.run(query, {"value": value})

# VULNERABLE: Dynamic label from user input
def find_by_label(label_name):
    query = f"MATCH (n:{label_name}) RETURN n"
    # Attacker can inject arbitrary labels and patterns
    return session.run(query)
```

**Why**: Cypher injection allows attackers to bypass access controls, exfiltrate data across tenants, modify or delete nodes/relationships, and potentially execute administrative commands. Unlike SQL, Cypher's pattern-matching syntax enables complex graph traversals that can expose entire connected datasets.

**Refs**: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic), OWASP A03:2021 (Injection), CWE-89

---

## Rule: APOC Procedure Security

**Level**: `strict`

**When**: Using APOC (Awesome Procedures on Cypher) extended procedures

**Do**: Whitelist only required procedures, disable dangerous ones, audit usage

```python
# neo4j.conf - Secure APOC configuration
"""
# Enable only specific APOC procedures
dbms.security.procedures.allowlist=apoc.meta.*,apoc.help,apoc.coll.*,apoc.text.*,apoc.map.*

# Block unrestricted procedures (require elevated privileges)
dbms.security.procedures.unrestricted=

# Disable dangerous procedures explicitly
# apoc.load.* - File system access
# apoc.periodic.* - Background jobs
# apoc.cypher.* - Dynamic query execution
# apoc.export.* - Data export

# Sandbox external file access
apoc.import.file.enabled=false
apoc.export.file.enabled=false
apoc.import.file.use_neo4j_config=true

# Restrict HTTP/HTTPS access
apoc.http.allow.* = false
"""

# Application-level APOC validation
class SecureAPOCClient:
    # Allowlist of safe APOC procedures
    ALLOWED_APOC = {
        "apoc.text.clean",
        "apoc.text.capitalize",
        "apoc.coll.toSet",
        "apoc.coll.sort",
        "apoc.map.merge",
        "apoc.meta.nodeTypeProperties",
        "apoc.help"
    }

    def __init__(self, driver):
        self.driver = driver

    def execute_safe_procedure(self, procedure_name: str, params: dict):
        """Execute only allowlisted APOC procedures."""
        if procedure_name not in self.ALLOWED_APOC:
            raise SecurityError(f"APOC procedure '{procedure_name}' not allowed")

        with self.driver.session() as session:
            result = session.run(
                f"CALL {procedure_name}($params) YIELD value RETURN value",
                {"params": params}
            )
            return [record["value"] for record in result]

    def validate_query_no_dangerous_apoc(self, query: str) -> bool:
        """Check query doesn't contain dangerous APOC calls."""
        DANGEROUS_PATTERNS = [
            r'apoc\.load\.',           # File system access
            r'apoc\.periodic\.',       # Background execution
            r'apoc\.cypher\.run',      # Dynamic query execution
            r'apoc\.export\.',         # Data export
            r'apoc\.import\.',         # Data import
            r'apoc\.do\.',             # Conditional execution
            r'apoc\.custom\.',         # Custom procedures
            r'apoc\.systemdb\.',       # System database access
            r'apoc\.trigger\.',        # Database triggers
            r'apoc\.log\.'             # Log access
        ]

        query_lower = query.lower()
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, query_lower):
                return False
        return True

    def audit_apoc_usage(self, query: str, user_id: str):
        """Log APOC procedure usage for audit."""
        apoc_calls = re.findall(r'apoc\.[a-zA-Z.]+', query.lower())
        if apoc_calls:
            audit_log.info(
                "apoc_usage",
                user_id=user_id,
                procedures=apoc_calls,
                query_hash=hashlib.sha256(query.encode()).hexdigest()
            )
```

**Don't**: Enable all APOC procedures or allow dynamic procedure execution

```python
# VULNERABLE: All APOC procedures enabled
# neo4j.conf: dbms.security.procedures.allowlist=apoc.*

# VULNERABLE: Allow file system access
# apoc.import.file.enabled=true
# apoc.export.file.enabled=true

# VULNERABLE: Execute arbitrary APOC from user input
def run_apoc(procedure_name, params):
    # Attacker can call apoc.cypher.run with arbitrary queries
    query = f"CALL {procedure_name}($params)"
    return session.run(query, {"params": params})

# VULNERABLE: Load external files
def load_user_file(file_path):
    # Attacker can access /etc/passwd or sensitive config
    query = "CALL apoc.load.json($path) YIELD value RETURN value"
    return session.run(query, {"path": file_path})
```

**Why**: APOC procedures extend Cypher with powerful capabilities including file system access, HTTP requests, dynamic query execution, and system administration. Unrestricted APOC access enables remote code execution, data exfiltration through external HTTP calls, and complete database compromise.

**Refs**: CWE-94 (Code Injection), CWE-78 (OS Command Injection), OWASP A03:2021 (Injection)

---

## Rule: Traversal Depth Limits

**Level**: `strict`

**When**: Executing graph traversal queries with variable-length patterns

**Do**: Enforce maximum traversal depth, result limits, and query timeouts

```python
from neo4j import GraphDatabase
import os

class SecureGraphTraversal:
    # Configuration limits
    MAX_TRAVERSAL_DEPTH = 5
    MAX_RESULTS = 1000
    QUERY_TIMEOUT_MS = 30000  # 30 seconds

    def __init__(self, driver):
        self.driver = driver

    def find_connected_documents(self, start_id: str, tenant_id: str,
                                  max_depth: int = 3, limit: int = 100):
        """Safe traversal with enforced limits."""
        # Enforce maximum depth
        if max_depth > self.MAX_TRAVERSAL_DEPTH:
            max_depth = self.MAX_TRAVERSAL_DEPTH

        # Enforce result limit
        if limit > self.MAX_RESULTS:
            limit = self.MAX_RESULTS

        with self.driver.session() as session:
            # Set transaction timeout
            result = session.run("""
                MATCH path = (start:Document {id: $start_id, tenant_id: $tenant_id})
                      -[*1..$max_depth]-(connected:Document {tenant_id: $tenant_id})
                WITH connected, length(path) AS depth
                RETURN DISTINCT connected.id AS id,
                       connected.title AS title,
                       depth
                ORDER BY depth
                LIMIT $limit
            """, {
                "start_id": start_id,
                "tenant_id": tenant_id,
                "max_depth": max_depth,
                "limit": limit
            },
            timeout=self.QUERY_TIMEOUT_MS / 1000  # Convert to seconds
            )
            return [record.data() for record in result]

    def find_shortest_path(self, from_id: str, to_id: str, tenant_id: str):
        """Find shortest path with safety limits."""
        with self.driver.session() as session:
            result = session.run("""
                MATCH path = shortestPath(
                    (a:Document {id: $from_id, tenant_id: $tenant_id})
                    -[*..5]-  // Hard limit on path length
                    (b:Document {id: $to_id, tenant_id: $tenant_id})
                )
                RETURN [node IN nodes(path) | node.id] AS path_ids,
                       length(path) AS path_length
            """, {
                "from_id": from_id,
                "to_id": to_id,
                "tenant_id": tenant_id
            },
            timeout=self.QUERY_TIMEOUT_MS / 1000
            )
            return result.single()

    def count_relationships(self, node_id: str, tenant_id: str):
        """Count relationships with result limiting."""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Document {id: $node_id, tenant_id: $tenant_id})-[r]-()
                WITH type(r) AS rel_type, count(*) AS count
                RETURN rel_type, count
                ORDER BY count DESC
                LIMIT 50
            """, {
                "node_id": node_id,
                "tenant_id": tenant_id
            })
            return [record.data() for record in result]

# neo4j.conf - Server-side limits
"""
# Query execution limits
db.transaction.timeout=30s
dbms.memory.transaction.total.max=1G
dbms.memory.transaction.max=256M

# Query plan cache
db.query_cache_size=1000

# Cypher planner configuration for better execution plans
cypher.min_replan_interval=10s
cypher.statistics_divergence_threshold=0.75
"""
```

**Don't**: Allow unbounded traversals or unlimited result sets

```python
# VULNERABLE: Unbounded traversal depth
def find_all_connected(start_id):
    # [*] means unlimited depth - can traverse entire graph
    query = "MATCH (s {id: $id})-[*]-(n) RETURN n"
    return session.run(query, {"id": start_id})

# VULNERABLE: No result limit
def get_relationships(node_id):
    # Could return millions of records
    query = "MATCH (n {id: $id})-[r]-() RETURN r"
    return session.run(query, {"id": node_id})

# VULNERABLE: No timeout
def complex_traversal(params):
    # Query could run indefinitely
    query = """
        MATCH path = (a)-[*]-(b)-[*]-(c)
        WHERE a.type = $type
        RETURN path
    """
    return session.run(query, params)

# VULNERABLE: User-controlled depth
def traverse_to_depth(start_id, user_depth):
    # Attacker sets depth = 999999
    query = f"MATCH (s {{id: $id}})-[*..{user_depth}]-(n) RETURN n"
    return session.run(query, {"id": start_id})
```

**Why**: Graph databases can contain highly connected data where unbounded traversals exponentially expand. A single malicious query with unbounded depth can consume all server memory and CPU, causing denial of service for all users. Even legitimate queries can accidentally trigger resource exhaustion.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits), OWASP A05:2021 (Security Misconfiguration)

---

## Rule: Role-Based Access Control

**Level**: `strict`

**When**: Managing access to Neo4j data across multiple users or services

**Do**: Implement database roles, node/relationship-level access controls, and tenant isolation

```python
# Neo4j RBAC configuration
"""
# neo4j.conf - Enable native auth
dbms.security.auth_enabled=true
dbms.security.auth_minimum_password_length=12

# Role-based access control
# Create roles in Cypher:

// Admin role - full access
CREATE ROLE admin;
GRANT ALL DATABASE PRIVILEGES ON DATABASE neo4j TO admin;

// Reader role - query only
CREATE ROLE reader;
GRANT MATCH {*} ON GRAPH neo4j TO reader;
GRANT TRAVERSE ON GRAPH neo4j TO reader;

// Writer role - read + write nodes/relationships
CREATE ROLE writer;
GRANT MATCH {*} ON GRAPH neo4j TO writer;
GRANT WRITE ON GRAPH neo4j TO writer;

// Tenant-specific roles
CREATE ROLE tenant_abc_reader;
GRANT MATCH {*} ON GRAPH neo4j NODE Document
    WHERE Document.tenant_id = 'abc' TO tenant_abc_reader;
GRANT TRAVERSE ON GRAPH neo4j RELATIONSHIP *
    WHERE relationship.tenant_id = 'abc' TO tenant_abc_reader;

// Create users with roles
CREATE USER query_service SET PASSWORD 'secure_password' SET PASSWORD CHANGE NOT REQUIRED;
GRANT ROLE reader TO query_service;

CREATE USER indexer_service SET PASSWORD 'secure_password' SET PASSWORD CHANGE NOT REQUIRED;
GRANT ROLE writer TO indexer_service;
"""

# Application-level RBAC enforcement
class RBACNeo4jClient:
    def __init__(self, driver, user_id: str, roles: list):
        self.driver = driver
        self.user_id = user_id
        self.roles = roles

    def _check_permission(self, action: str, resource: str):
        """Verify user has permission for action."""
        ROLE_PERMISSIONS = {
            "reader": {"read"},
            "writer": {"read", "write"},
            "admin": {"read", "write", "delete", "admin"}
        }

        user_permissions = set()
        for role in self.roles:
            user_permissions.update(ROLE_PERMISSIONS.get(role, set()))

        if action not in user_permissions:
            audit_log.warning(
                "permission_denied",
                user_id=self.user_id,
                action=action,
                resource=resource,
                roles=self.roles
            )
            raise PermissionError(f"User lacks {action} permission")

    def query_documents(self, tenant_id: str, query_vector: list):
        """Read operation with permission check."""
        self._check_permission("read", f"tenant:{tenant_id}")
        self._verify_tenant_access(tenant_id)

        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Document {tenant_id: $tenant_id})
                WHERE d.embedding IS NOT NULL
                RETURN d.id, d.title, d.content
                LIMIT 100
            """, {"tenant_id": tenant_id})

            audit_log.info(
                "document_query",
                user_id=self.user_id,
                tenant_id=tenant_id,
                action="read"
            )
            return [record.data() for record in result]

    def create_document(self, tenant_id: str, doc_data: dict):
        """Write operation with permission check."""
        self._check_permission("write", f"tenant:{tenant_id}")
        self._verify_tenant_access(tenant_id)

        with self.driver.session() as session:
            result = session.run("""
                CREATE (d:Document {
                    id: $id,
                    tenant_id: $tenant_id,
                    title: $title,
                    content: $content,
                    created_by: $user_id,
                    created_at: datetime()
                })
                RETURN d.id
            """, {
                **doc_data,
                "tenant_id": tenant_id,
                "user_id": self.user_id
            })

            audit_log.info(
                "document_created",
                user_id=self.user_id,
                tenant_id=tenant_id,
                doc_id=doc_data["id"]
            )
            return result.single()

    def delete_document(self, tenant_id: str, doc_id: str):
        """Delete operation with permission check."""
        self._check_permission("delete", f"tenant:{tenant_id}")
        self._verify_tenant_access(tenant_id)

        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Document {id: $doc_id, tenant_id: $tenant_id})
                DETACH DELETE d
                RETURN count(*) AS deleted
            """, {
                "doc_id": doc_id,
                "tenant_id": tenant_id
            })

            deleted = result.single()["deleted"]
            audit_log.info(
                "document_deleted",
                user_id=self.user_id,
                tenant_id=tenant_id,
                doc_id=doc_id,
                deleted=deleted
            )
            return deleted

    def _verify_tenant_access(self, tenant_id: str):
        """Verify user has access to tenant."""
        allowed_tenants = auth_service.get_user_tenants(self.user_id)
        if tenant_id not in allowed_tenants:
            raise PermissionError(f"User not authorized for tenant {tenant_id}")
```

**Don't**: Use shared credentials or grant excessive permissions

```python
# VULNERABLE: Single shared admin account
driver = GraphDatabase.driver(
    uri,
    auth=("neo4j", "admin123")  # Same creds everywhere
)

# VULNERABLE: All users have full access
# CREATE USER app SET PASSWORD 'password';
# GRANT ALL PRIVILEGES ON DATABASE neo4j TO app;

# VULNERABLE: No tenant isolation
def query_all_documents():
    # User can access all tenants
    query = "MATCH (d:Document) RETURN d"
    return session.run(query)

# VULNERABLE: No permission checks
def delete_document(doc_id):
    # Anyone can delete anything
    query = "MATCH (d {id: $id}) DETACH DELETE d"
    return session.run(query, {"id": doc_id})
```

**Why**: Without proper RBAC, compromised services can access or modify all data. Shared credentials make it impossible to audit actions or revoke specific access. Graph databases especially need fine-grained access control because relationships can expose data across logical boundaries.

**Refs**: OWASP A01:2021 (Broken Access Control), CWE-284 (Improper Access Control), CWE-732 (Incorrect Permission Assignment)

---

## Rule: GDS Algorithm Security

**Level**: `warning`

**When**: Using Neo4j Graph Data Science (GDS) library for analytics

**Do**: Set memory limits, secure projections, validate algorithm parameters

```python
# GDS security configuration and usage
class SecureGDSClient:
    # GDS resource limits
    MAX_NODE_COUNT = 1_000_000
    MAX_RELATIONSHIP_COUNT = 10_000_000
    MAX_MEMORY_ESTIMATION_GB = 8

    def __init__(self, driver):
        self.driver = driver

    def create_secure_projection(self, projection_name: str, tenant_id: str,
                                  node_labels: list, rel_types: list):
        """Create GDS projection with tenant isolation and limits."""
        # Validate projection name
        if not re.match(r'^[a-zA-Z0-9_]{1,64}$', projection_name):
            raise ValueError("Invalid projection name")

        # Allowlist of permitted node labels and relationship types
        ALLOWED_LABELS = {"Document", "Entity", "Concept", "Topic"}
        ALLOWED_REL_TYPES = {"REFERENCES", "SIMILAR_TO", "PART_OF", "RELATED_TO"}

        for label in node_labels:
            if label not in ALLOWED_LABELS:
                raise ValueError(f"Node label '{label}' not allowed for GDS")

        for rel_type in rel_types:
            if rel_type not in ALLOWED_REL_TYPES:
                raise ValueError(f"Relationship type '{rel_type}' not allowed for GDS")

        with self.driver.session() as session:
            # First estimate memory requirements
            estimate = session.run("""
                CALL gds.graph.project.estimate(
                    $labels,
                    $rel_types,
                    {nodeProperties: ['embedding'], relationshipProperties: []}
                )
                YIELD requiredMemory, nodeCount, relationshipCount
                RETURN requiredMemory, nodeCount, relationshipCount
            """, {
                "labels": node_labels,
                "rel_types": rel_types
            }).single()

            # Validate against limits
            if estimate["nodeCount"] > self.MAX_NODE_COUNT:
                raise ResourceError(
                    f"Projection exceeds node limit: {estimate['nodeCount']}"
                )

            if estimate["relationshipCount"] > self.MAX_RELATIONSHIP_COUNT:
                raise ResourceError(
                    f"Projection exceeds relationship limit: {estimate['relationshipCount']}"
                )

            # Create projection with tenant filter
            result = session.run("""
                CALL gds.graph.project.cypher(
                    $projection_name,
                    'MATCH (n) WHERE n.tenant_id = $tenant_id AND labels(n)[0] IN $labels RETURN id(n) AS id, n.embedding AS embedding',
                    'MATCH (a)-[r]->(b) WHERE a.tenant_id = $tenant_id AND b.tenant_id = $tenant_id AND type(r) IN $rel_types RETURN id(a) AS source, id(b) AS target',
                    {parameters: {tenant_id: $tenant_id, labels: $labels, rel_types: $rel_types}}
                )
                YIELD graphName, nodeCount, relationshipCount, projectMillis
                RETURN graphName, nodeCount, relationshipCount, projectMillis
            """, {
                "projection_name": f"{tenant_id}_{projection_name}",
                "tenant_id": tenant_id,
                "labels": node_labels,
                "rel_types": rel_types
            })

            projection_info = result.single()

            # Audit projection creation
            audit_log.info(
                "gds_projection_created",
                tenant_id=tenant_id,
                projection_name=projection_name,
                node_count=projection_info["nodeCount"],
                relationship_count=projection_info["relationshipCount"]
            )

            return projection_info

    def run_similarity_algorithm(self, projection_name: str, tenant_id: str,
                                  algorithm_params: dict = None):
        """Run similarity algorithm with resource limits."""
        full_projection = f"{tenant_id}_{projection_name}"

        # Default safe parameters
        safe_params = {
            "topK": min(algorithm_params.get("topK", 10), 100),
            "similarityCutoff": max(algorithm_params.get("similarityCutoff", 0.5), 0.1),
            "concurrency": min(algorithm_params.get("concurrency", 4), 8)
        }

        with self.driver.session() as session:
            result = session.run("""
                CALL gds.nodeSimilarity.stream($projection, {
                    topK: $topK,
                    similarityCutoff: $similarityCutoff,
                    concurrency: $concurrency
                })
                YIELD node1, node2, similarity
                RETURN gds.util.asNode(node1).id AS source,
                       gds.util.asNode(node2).id AS target,
                       similarity
                ORDER BY similarity DESC
                LIMIT 1000
            """, {
                "projection": full_projection,
                **safe_params
            })

            return [record.data() for record in result]

    def cleanup_projection(self, projection_name: str, tenant_id: str):
        """Clean up GDS projection after use."""
        full_projection = f"{tenant_id}_{projection_name}"

        with self.driver.session() as session:
            try:
                session.run(
                    "CALL gds.graph.drop($projection)",
                    {"projection": full_projection}
                )
                audit_log.info(
                    "gds_projection_dropped",
                    tenant_id=tenant_id,
                    projection_name=projection_name
                )
            except Exception as e:
                audit_log.error(
                    "gds_projection_drop_failed",
                    projection_name=full_projection,
                    error=str(e)
                )

# neo4j.conf - GDS memory limits
"""
# GDS memory configuration
gds.enterprise.allocation.size.modifier=0.8
gds.model.store.location=/var/lib/neo4j/gds-models

# Limit GDS memory pool
dbms.memory.heap.initial_size=4G
dbms.memory.heap.max_size=8G
"""
```

**Don't**: Allow unbounded GDS projections or arbitrary algorithm execution

```python
# VULNERABLE: No memory limits
def create_full_projection():
    # Projects entire graph - memory exhaustion risk
    query = """
        CALL gds.graph.project('full', '*', '*')
        YIELD graphName, nodeCount
        RETURN graphName, nodeCount
    """
    return session.run(query)

# VULNERABLE: User controls projection parameters
def run_user_algorithm(user_params):
    # Attacker can set concurrency=1000, exhaust resources
    query = f"""
        CALL gds.pageRank.stream('graph', {{
            maxIterations: {user_params['iterations']},
            concurrency: {user_params['concurrency']}
        }})
    """
    return session.run(query)

# VULNERABLE: No tenant isolation in projection
def create_shared_projection():
    # All tenants in same projection - data leakage
    query = "CALL gds.graph.project('shared', 'Document', 'SIMILAR_TO')"
    return session.run(query)
```

**Why**: GDS algorithms can consume significant memory and CPU. Unbounded projections can exhaust server resources, causing denial of service. Projections without tenant isolation expose data across boundaries. User-controlled parameters enable resource exhaustion attacks.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Rule: Vector Index Security

**Level**: `warning`

**When**: Using Neo4j vector indexes for similarity search

**Do**: Configure indexes securely, validate similarity parameters, enforce access controls

```python
# Secure vector index configuration and usage
class SecureVectorIndex:
    # Allowed similarity functions
    ALLOWED_SIMILARITY = {"cosine", "euclidean"}
    MAX_TOP_K = 100
    MIN_SIMILARITY_THRESHOLD = 0.5

    def __init__(self, driver):
        self.driver = driver

    def create_vector_index(self, index_name: str, dimensions: int = 1536):
        """Create vector index with validated configuration."""
        # Validate index name
        if not re.match(r'^[a-zA-Z0-9_]{1,64}$', index_name):
            raise ValueError("Invalid index name")

        # Validate dimensions
        if dimensions not in [384, 768, 1536, 3072]:
            raise ValueError("Invalid embedding dimensions")

        with self.driver.session() as session:
            session.run("""
                CREATE VECTOR INDEX $index_name IF NOT EXISTS
                FOR (d:Document) ON (d.embedding)
                OPTIONS {
                    indexConfig: {
                        `vector.dimensions`: $dimensions,
                        `vector.similarity_function`: 'cosine'
                    }
                }
            """, {
                "index_name": index_name,
                "dimensions": dimensions
            })

            audit_log.info(
                "vector_index_created",
                index_name=index_name,
                dimensions=dimensions
            )

    def vector_similarity_search(self, tenant_id: str, query_embedding: list,
                                  top_k: int = 10, min_score: float = 0.7):
        """Perform secure vector similarity search."""
        # Validate parameters
        if top_k > self.MAX_TOP_K:
            top_k = self.MAX_TOP_K

        if min_score < self.MIN_SIMILARITY_THRESHOLD:
            min_score = self.MIN_SIMILARITY_THRESHOLD

        # Validate embedding format
        if not isinstance(query_embedding, list) or len(query_embedding) == 0:
            raise ValueError("Invalid embedding format")

        with self.driver.session() as session:
            result = session.run("""
                CALL db.index.vector.queryNodes(
                    'document_embeddings',
                    $top_k,
                    $embedding
                )
                YIELD node, score
                WHERE node.tenant_id = $tenant_id AND score >= $min_score
                RETURN node.id AS id,
                       node.title AS title,
                       node.content AS content,
                       score
                ORDER BY score DESC
            """, {
                "tenant_id": tenant_id,
                "embedding": query_embedding,
                "top_k": top_k * 2,  # Over-fetch to account for tenant filter
                "min_score": min_score
            })

            results = [record.data() for record in result][:top_k]

            # Audit search
            audit_log.info(
                "vector_search",
                tenant_id=tenant_id,
                result_count=len(results),
                min_score=min_score
            )

            return results

    def hybrid_search(self, tenant_id: str, query_embedding: list,
                      keyword_filter: str = None, top_k: int = 10):
        """Combine vector and keyword search securely."""
        # Sanitize keyword filter
        if keyword_filter:
            # Remove dangerous characters
            keyword_filter = re.sub(r'[^\w\s]', '', keyword_filter)[:100]

        with self.driver.session() as session:
            result = session.run("""
                CALL db.index.vector.queryNodes(
                    'document_embeddings',
                    $top_k,
                    $embedding
                )
                YIELD node, score
                WHERE node.tenant_id = $tenant_id
                    AND ($keyword IS NULL OR
                         node.content CONTAINS $keyword OR
                         node.title CONTAINS $keyword)
                RETURN node.id AS id,
                       node.title AS title,
                       score
                ORDER BY score DESC
                LIMIT $top_k
            """, {
                "tenant_id": tenant_id,
                "embedding": query_embedding,
                "keyword": keyword_filter,
                "top_k": top_k
            })

            return [record.data() for record in result]
```

**Don't**: Allow unvalidated vector search parameters or skip tenant filtering

```python
# VULNERABLE: No tenant filter on vector search
def search_vectors(embedding, top_k):
    # Returns results from all tenants
    query = """
        CALL db.index.vector.queryNodes('embeddings', $top_k, $embedding)
        YIELD node, score
        RETURN node, score
    """
    return session.run(query, {"embedding": embedding, "top_k": top_k})

# VULNERABLE: User controls all parameters
def search(user_params):
    # Attacker can set top_k = 1000000
    query = f"""
        CALL db.index.vector.queryNodes(
            '{user_params["index"]}',  // Index name injection
            {user_params["top_k"]},
            $embedding
        )
    """
    return session.run(query, {"embedding": user_params["embedding"]})

# VULNERABLE: No similarity threshold
def get_similar(embedding):
    # Returns low-quality matches
    query = """
        CALL db.index.vector.queryNodes('embeddings', 1000, $embedding)
        YIELD node, score
        RETURN node  // No minimum score filter
    """
    return session.run(query, {"embedding": embedding})
```

**Why**: Vector indexes without proper access controls can leak data across tenants. Unvalidated parameters enable resource exhaustion through large result sets. Low similarity thresholds return irrelevant results that may expose sensitive information through statistical attacks.

**Refs**: CWE-200 (Information Exposure), CWE-400 (Uncontrolled Resource Consumption)

---

## Rule: Import/Export Security

**Level**: `strict`

**When**: Importing data into or exporting data from Neo4j

**Do**: Use signed dumps, encrypt exports, validate import sources, audit operations

```python
import hashlib
import subprocess
from cryptography.fernet import Fernet
from pathlib import Path

class SecureNeo4jBackup:
    def __init__(self, neo4j_home: str, backup_dir: str):
        self.neo4j_home = Path(neo4j_home)
        self.backup_dir = Path(backup_dir)
        self.encryption_key = os.environ["BACKUP_ENCRYPTION_KEY"]

    def create_encrypted_backup(self, database: str = "neo4j") -> dict:
        """Create encrypted and signed database backup."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{database}_{timestamp}"
        temp_backup = self.backup_dir / f"{backup_name}.dump"
        encrypted_backup = self.backup_dir / f"{backup_name}.dump.enc"

        try:
            # Create database dump
            subprocess.run([
                str(self.neo4j_home / "bin/neo4j-admin"),
                "database", "dump",
                database,
                f"--to-path={temp_backup}"
            ], check=True, capture_output=True)

            # Calculate checksum of original
            with open(temp_backup, "rb") as f:
                original_checksum = hashlib.sha256(f.read()).hexdigest()

            # Encrypt backup
            fernet = Fernet(self.encryption_key)
            with open(temp_backup, "rb") as f:
                encrypted_data = fernet.encrypt(f.read())

            with open(encrypted_backup, "wb") as f:
                f.write(encrypted_data)

            # Calculate encrypted checksum
            encrypted_checksum = hashlib.sha256(encrypted_data).hexdigest()

            # Create signature file
            signature = {
                "database": database,
                "timestamp": timestamp,
                "original_checksum": original_checksum,
                "encrypted_checksum": encrypted_checksum,
                "backup_path": str(encrypted_backup)
            }

            signature_path = encrypted_backup.with_suffix(".sig")
            with open(signature_path, "w") as f:
                json.dump(signature, f)

            # Remove unencrypted backup
            temp_backup.unlink()

            audit_log.info(
                "backup_created",
                database=database,
                backup_path=str(encrypted_backup),
                checksum=encrypted_checksum
            )

            return signature

        except subprocess.CalledProcessError as e:
            audit_log.error(
                "backup_failed",
                database=database,
                error=e.stderr.decode()
            )
            raise

    def restore_verified_backup(self, backup_path: str, signature_path: str,
                                 database: str = "neo4j"):
        """Restore backup with integrity verification."""
        backup_path = Path(backup_path)
        signature_path = Path(signature_path)

        # Load and verify signature
        with open(signature_path) as f:
            signature = json.load(f)

        # Verify encrypted checksum
        with open(backup_path, "rb") as f:
            encrypted_data = f.read()

        actual_checksum = hashlib.sha256(encrypted_data).hexdigest()
        if actual_checksum != signature["encrypted_checksum"]:
            audit_log.error(
                "backup_integrity_failure",
                expected=signature["encrypted_checksum"],
                actual=actual_checksum
            )
            raise IntegrityError("Backup checksum mismatch - possible tampering")

        # Decrypt backup
        fernet = Fernet(self.encryption_key)
        decrypted_data = fernet.decrypt(encrypted_data)

        # Verify original checksum
        original_checksum = hashlib.sha256(decrypted_data).hexdigest()
        if original_checksum != signature["original_checksum"]:
            raise IntegrityError("Decrypted data checksum mismatch")

        # Write decrypted backup temporarily
        temp_backup = self.backup_dir / f"restore_{database}.dump"
        with open(temp_backup, "wb") as f:
            f.write(decrypted_data)

        try:
            # Restore database
            subprocess.run([
                str(self.neo4j_home / "bin/neo4j-admin"),
                "database", "load",
                database,
                f"--from-path={temp_backup}",
                "--overwrite-destination=true"
            ], check=True, capture_output=True)

            audit_log.info(
                "backup_restored",
                database=database,
                backup_path=str(backup_path),
                checksum=actual_checksum
            )

        finally:
            # Clean up decrypted file
            temp_backup.unlink()

    def validate_import_source(self, import_path: str, expected_format: str):
        """Validate import file before processing."""
        import_path = Path(import_path)

        # Check file exists and is readable
        if not import_path.exists():
            raise FileNotFoundError(f"Import file not found: {import_path}")

        # Validate file size
        max_size = 1024 * 1024 * 1024  # 1GB
        if import_path.stat().st_size > max_size:
            raise ValueError(f"Import file exceeds size limit: {import_path}")

        # Validate file format
        if expected_format == "csv":
            # Basic CSV validation
            with open(import_path) as f:
                header = f.readline()
                if not header or len(header.split(",")) < 2:
                    raise ValueError("Invalid CSV format")

        elif expected_format == "json":
            with open(import_path) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON format")

        audit_log.info(
            "import_validated",
            import_path=str(import_path),
            format=expected_format,
            size=import_path.stat().st_size
        )

        return True

# neo4j.conf - Secure import settings
"""
# Restrict import directory
server.directories.import=/var/lib/neo4j/import

# Disable loading from arbitrary paths
dbms.security.allow_csv_import_from_file_urls=false
"""
```

**Don't**: Import from untrusted sources or export unencrypted backups

```python
# VULNERABLE: Unencrypted backup
def backup_database():
    subprocess.run([
        "neo4j-admin", "database", "dump", "neo4j",
        "--to-path=/backups/neo4j.dump"  # Plaintext backup
    ])

# VULNERABLE: No integrity verification
def restore_backup(backup_path):
    # Restore without verifying checksum
    subprocess.run([
        "neo4j-admin", "database", "load", "neo4j",
        f"--from-path={backup_path}"
    ])

# VULNERABLE: Import from user-provided path
def import_csv(user_path):
    # Path traversal attack: user_path = "../../etc/passwd"
    query = f"LOAD CSV FROM 'file:///{user_path}' AS row RETURN row"
    return session.run(query)

# VULNERABLE: Import from external URL
def import_from_url(url):
    # Attacker controls URL - can exfiltrate data via DNS
    query = f"LOAD CSV FROM '{url}' AS row CREATE (n:Data) SET n = row"
    return session.run(query)
```

**Why**: Unencrypted backups expose all graph data including embeddings, relationships, and metadata. Without integrity verification, attackers can tamper with backups to inject malicious nodes or modify access controls. Importing from untrusted sources enables code injection through crafted CSV/JSON files.

**Refs**: CWE-311 (Missing Encryption of Sensitive Data), CWE-354 (Improper Validation of Integrity Check Value), OWASP A02:2021 (Cryptographic Failures)

---

## Rule: Bolt Connection Security

**Level**: `strict`

**When**: Establishing connections to Neo4j using the Bolt protocol

**Do**: Use TLS encryption, strong authentication, connection pooling with limits

```python
from neo4j import GraphDatabase, basic_auth
import ssl

class SecureBoltConnection:
    def __init__(self):
        self.driver = None

    def connect(self, uri: str, user: str, password: str):
        """Establish secure Bolt connection with TLS and auth."""
        # Validate URI scheme
        if not uri.startswith(("bolt+s://", "neo4j+s://")):
            raise ValueError("Must use encrypted connection (bolt+s:// or neo4j+s://)")

        # Get credentials from environment
        user = os.environ.get("NEO4J_USER", user)
        password = os.environ.get("NEO4J_PASSWORD", password)

        if not password or len(password) < 12:
            raise ValueError("Password must be at least 12 characters")

        # Configure connection pool
        self.driver = GraphDatabase.driver(
            uri,
            auth=basic_auth(user, password),
            encrypted=True,
            trust=ssl.CERT_REQUIRED,  # Verify server certificate
            max_connection_lifetime=3600,  # 1 hour max lifetime
            max_connection_pool_size=50,
            connection_acquisition_timeout=30,
            connection_timeout=15
        )

        # Verify connection
        self.driver.verify_connectivity()

        audit_log.info(
            "neo4j_connected",
            uri=uri.split("@")[-1],  # Log URI without credentials
            pool_size=50
        )

        return self.driver

    def get_session(self, database: str = None, access_mode: str = "READ"):
        """Get session with access mode control."""
        if access_mode not in ["READ", "WRITE"]:
            raise ValueError("access_mode must be READ or WRITE")

        from neo4j import READ_ACCESS, WRITE_ACCESS

        mode = READ_ACCESS if access_mode == "READ" else WRITE_ACCESS

        return self.driver.session(
            database=database,
            default_access_mode=mode
        )

    def close(self):
        """Close connection pool."""
        if self.driver:
            self.driver.close()
            audit_log.info("neo4j_disconnected")

# Connection factory with credential management
class Neo4jConnectionFactory:
    _instance = None

    @classmethod
    def get_connection(cls):
        """Get singleton connection with secure configuration."""
        if cls._instance is None:
            cls._instance = SecureBoltConnection()
            cls._instance.connect(
                uri=os.environ["NEO4J_URI"],
                user=os.environ["NEO4J_USER"],
                password=os.environ["NEO4J_PASSWORD"]
            )
        return cls._instance

    @classmethod
    def shutdown(cls):
        """Shutdown connection pool."""
        if cls._instance:
            cls._instance.close()
            cls._instance = None

# Context manager for transaction safety
class SecureTransaction:
    def __init__(self, driver, database: str = None):
        self.driver = driver
        self.database = database
        self.session = None
        self.transaction = None

    def __enter__(self):
        self.session = self.driver.session(database=self.database)
        self.transaction = self.session.begin_transaction()
        return self.transaction

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                self.transaction.commit()
            else:
                self.transaction.rollback()
        finally:
            self.session.close()
        return False

# Usage example
def execute_secure_query():
    conn = Neo4jConnectionFactory.get_connection()

    with SecureTransaction(conn.driver) as tx:
        result = tx.run("""
            MATCH (d:Document {tenant_id: $tenant_id})
            RETURN d.id, d.title
            LIMIT 10
        """, {"tenant_id": "tenant_abc"})
        return [record.data() for record in result]

# neo4j.conf - Server-side connection security
"""
# Enable TLS
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates/bolt
dbms.ssl.policy.bolt.private_key=private.key
dbms.ssl.policy.bolt.public_certificate=public.crt
dbms.ssl.policy.bolt.trust_all=false
dbms.ssl.policy.bolt.client_auth=REQUIRE

# Connection limits
dbms.connector.bolt.connection_keep_alive=60s
dbms.connector.bolt.connection_keep_alive_for_requests=200

# Authentication settings
dbms.security.auth_enabled=true
dbms.security.auth_lock_time=5s
dbms.security.auth_max_failed_attempts=3
"""
```

**Don't**: Use unencrypted connections or hardcode credentials

```python
# VULNERABLE: Unencrypted connection
driver = GraphDatabase.driver(
    "bolt://neo4j.example.com:7687",  # No TLS
    auth=("neo4j", "password")
)

# VULNERABLE: Hardcoded credentials
driver = GraphDatabase.driver(
    uri,
    auth=("admin", "SuperSecret123!")  # Exposed in source code
)

# VULNERABLE: Disabled certificate verification
driver = GraphDatabase.driver(
    "bolt+s://neo4j.example.com:7687",
    auth=auth,
    trust=ssl.CERT_NONE  # Accepts any certificate - MITM vulnerable
)

# VULNERABLE: No connection limits
driver = GraphDatabase.driver(
    uri,
    auth=auth,
    max_connection_pool_size=10000,  # Resource exhaustion
    connection_timeout=0  # No timeout
)

# VULNERABLE: Credentials in URI
driver = GraphDatabase.driver(
    "bolt+s://admin:password@neo4j.example.com:7687"  # Logged in errors
)
```

**Why**: Unencrypted Bolt connections expose all queries and data to network interception, including sensitive graph traversals and embeddings. Hardcoded credentials leak through version control and logs. Without connection pool limits, attackers can exhaust database connections causing denial of service.

**Refs**: OWASP A02:2021 (Cryptographic Failures), CWE-319 (Cleartext Transmission), CWE-798 (Hardcoded Credentials), CWE-400 (Uncontrolled Resource Consumption)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 8 security rules |

---

## Additional Resources

- [Neo4j Security Documentation](https://neo4j.com/docs/operations-manual/current/security/)
- [Neo4j RBAC Guide](https://neo4j.com/docs/operations-manual/current/authentication-authorization/)
- [APOC Security Configuration](https://neo4j.com/labs/apoc/4.4/installation/)
- [Neo4j GDS Security](https://neo4j.com/docs/graph-data-science/current/production-deployment/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE-943: Improper Neutralization in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
