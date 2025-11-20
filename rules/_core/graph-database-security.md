# Graph Database Security - RAG Knowledge Graph Rules

Security rules for graph databases used in RAG knowledge graphs, covering Neo4j, Amazon Neptune, TigerGraph, ArangoDB, and Memgraph.

## Overview

**Standards**: OWASP A03:2025 (Injection), CWE-89, CWE-943, CWE-284
**Scope**: Query injection prevention, traversal control, procedure security, multi-tenancy isolation

---

## Query Injection Prevention

### Rule: Use Parameterized Cypher Queries (Neo4j)

**Level**: `strict`

**When**: Constructing Cypher queries with any external input in Neo4j.

**Do**:
```python
from neo4j import GraphDatabase

class SecureNeo4jClient:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def find_entity(self, entity_name: str, entity_type: str):
        """Secure parameterized query for RAG entity lookup."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:$label {name: $name})
                RETURN n.name AS name, n.embedding AS embedding, n.content AS content
                """,
                label=entity_type,  # Note: labels need special handling
                name=entity_name
            )
            return [record.data() for record in result]

    def find_related_concepts(self, concept_id: str, max_depth: int = 3):
        """Secure traversal with depth limits for knowledge graph."""
        # Validate depth to prevent resource exhaustion
        if max_depth > 5:
            raise ValueError("Maximum depth exceeded")

        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (start:Concept {id: $concept_id})-[*1..$depth]-(related)
                WHERE ALL(r IN relationships(path) WHERE type(r) IN $allowed_relationships)
                RETURN related.name AS name, related.content AS content,
                       length(path) AS distance
                LIMIT $limit
                """,
                concept_id=concept_id,
                depth=max_depth,
                allowed_relationships=["RELATES_TO", "PART_OF", "REFERENCES"],
                limit=100
            )
            return [record.data() for record in result]

    def vector_similarity_search(self, embedding: list, top_k: int = 10):
        """Secure vector search for RAG retrieval."""
        if top_k > 100:
            raise ValueError("Result limit exceeded")

        with self.driver.session() as session:
            result = session.run(
                """
                CALL db.index.vector.queryNodes('embedding_index', $k, $embedding)
                YIELD node, score
                RETURN node.content AS content, node.source AS source, score
                """,
                k=top_k,
                embedding=embedding
            )
            return [record.data() for record in result]
```

**Don't**:
```python
# VULNERABLE: String interpolation in Cypher
def find_entity(entity_name, entity_type):
    query = f"MATCH (n:{entity_type} {{name: '{entity_name}'}}) RETURN n"
    return session.run(query)  # Cypher injection!

# VULNERABLE: Direct user input in query
def search_knowledge_graph(user_query):
    return session.run(f"MATCH (n) WHERE n.content CONTAINS '{user_query}' RETURN n")

# VULNERABLE: No depth limits on traversal
def get_all_related(node_id):
    return session.run(f"MATCH (n {{id: '{node_id}'}})-[*]-(m) RETURN m")  # Can traverse entire graph
```

**Why**: Cypher injection allows attackers to modify queries, bypass access controls, extract unauthorized data, or delete nodes. Example attack: `entity_name = "' OR 1=1 RETURN n //"` returns all nodes.

**Refs**: OWASP A03:2025, CWE-943 (Improper Neutralization in Data Query Logic), CWE-89

---

### Rule: Use Parameterized Gremlin Queries (Neptune)

**Level**: `strict`

**When**: Constructing Gremlin queries for Amazon Neptune.

**Do**:
```python
from gremlin_python.driver import client, serializer
from gremlin_python.driver.protocol import GremlinServerError

class SecureNeptuneClient:
    def __init__(self, endpoint):
        self.client = client.Client(
            f'wss://{endpoint}:8182/gremlin',
            'g',
            message_serializer=serializer.GraphSONSerializersV2d0()
        )

    def find_entity(self, entity_id: str):
        """Secure parameterized Gremlin query."""
        # Use parameterized bindings
        query = "g.V().has('entity', 'id', entity_id).valueMap(true)"
        bindings = {'entity_id': entity_id}

        result = self.client.submit(query, bindings=bindings)
        return result.all().result()

    def traverse_knowledge_graph(self, start_id: str, relationship: str, depth: int = 2):
        """Secure traversal with parameterized depth."""
        # Whitelist allowed relationships
        allowed_relationships = {'relates_to', 'contains', 'references', 'part_of'}
        if relationship not in allowed_relationships:
            raise ValueError(f"Relationship {relationship} not allowed")

        if depth > 4:
            raise ValueError("Maximum depth exceeded")

        # Build parameterized query with depth limit
        query = """
            g.V().has('entity', 'id', start_id)
             .repeat(out(relationship).simplePath())
             .times(depth)
             .dedup()
             .limit(limit)
             .valueMap(true)
        """
        bindings = {
            'start_id': start_id,
            'relationship': relationship,
            'depth': depth,
            'limit': 50
        }

        result = self.client.submit(query, bindings=bindings)
        return result.all().result()

    def semantic_search(self, embedding: list, threshold: float = 0.8):
        """Secure vector similarity search in Neptune."""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0 and 1")

        query = """
            g.V().has('embedding')
             .where(__.values('embedding')
                     .is(P.within(embedding).by(similarity)))
             .order().by('score', desc)
             .limit(top_k)
             .project('content', 'source', 'score')
               .by('content')
               .by('source')
               .by('score')
        """
        bindings = {
            'embedding': embedding,
            'similarity': threshold,
            'top_k': 10
        }

        return self.client.submit(query, bindings=bindings).all().result()
```

**Don't**:
```python
# VULNERABLE: String concatenation in Gremlin
def find_entity(entity_id):
    query = f"g.V().has('entity', 'id', '{entity_id}').valueMap()"
    return client.submit(query)  # Gremlin injection!

# VULNERABLE: User-controlled traversal steps
def traverse(user_traversal):
    query = f"g.V().{user_traversal}"  # Arbitrary traversal execution
    return client.submit(query)

# VULNERABLE: No limits on results
def get_all_related(node_id):
    return client.submit(f"g.V('{node_id}').both().both().both()")  # Exponential explosion
```

**Why**: Gremlin injection allows arbitrary graph traversals, data exfiltration, and DoS through expensive operations. Attack example: `entity_id = "').drop().V().has('secret"` deletes vertices.

**Refs**: OWASP A03:2025, CWE-943, AWS Neptune Security Best Practices

---

### Rule: Use Parameterized AQL Queries (ArangoDB)

**Level**: `strict`

**When**: Constructing AQL queries in ArangoDB.

**Do**:
```python
from arango import ArangoClient

class SecureArangoClient:
    def __init__(self, host, db_name, username, password):
        client = ArangoClient(hosts=host)
        self.db = client.db(db_name, username=username, password=password)

    def find_entity(self, entity_id: str, collection: str):
        """Secure parameterized AQL query."""
        # Validate collection name against whitelist
        allowed_collections = {'entities', 'concepts', 'documents'}
        if collection not in allowed_collections:
            raise ValueError(f"Collection {collection} not allowed")

        # Use bind variables for all user input
        query = """
            FOR doc IN @@collection
                FILTER doc._key == @entity_id
                RETURN {
                    id: doc._key,
                    content: doc.content,
                    embedding: doc.embedding
                }
        """

        cursor = self.db.aql.execute(
            query,
            bind_vars={
                '@collection': collection,
                'entity_id': entity_id
            }
        )
        return list(cursor)

    def traverse_graph(self, start_vertex: str, graph_name: str, depth: int = 3):
        """Secure graph traversal with depth limits."""
        # Validate graph name
        allowed_graphs = {'knowledge_graph', 'entity_graph'}
        if graph_name not in allowed_graphs:
            raise ValueError(f"Graph {graph_name} not allowed")

        if depth > 5:
            raise ValueError("Maximum depth exceeded")

        query = """
            FOR v, e, p IN 1..@depth OUTBOUND @start GRAPH @graph
                OPTIONS {bfs: true, uniqueVertices: 'global'}
                LIMIT @limit
                RETURN {
                    vertex: v,
                    edge: e,
                    path_length: LENGTH(p.edges)
                }
        """

        cursor = self.db.aql.execute(
            query,
            bind_vars={
                'start': start_vertex,
                'graph': graph_name,
                'depth': depth,
                'limit': 100
            }
        )
        return list(cursor)

    def vector_search(self, embedding: list, collection: str, top_k: int = 10):
        """Secure AQL vector similarity search."""
        if top_k > 100:
            raise ValueError("Result limit exceeded")

        query = """
            FOR doc IN @@collection
                LET similarity = COSINE_SIMILARITY(doc.embedding, @embedding)
                FILTER similarity >= @threshold
                SORT similarity DESC
                LIMIT @top_k
                RETURN {
                    content: doc.content,
                    source: doc.source,
                    score: similarity
                }
        """

        cursor = self.db.aql.execute(
            query,
            bind_vars={
                '@collection': collection,
                'embedding': embedding,
                'threshold': 0.7,
                'top_k': top_k
            }
        )
        return list(cursor)
```

**Don't**:
```python
# VULNERABLE: String interpolation in AQL
def find_entity(entity_id, collection):
    query = f'FOR doc IN {collection} FILTER doc._key == "{entity_id}" RETURN doc'
    return db.aql.execute(query)  # AQL injection!

# VULNERABLE: User-controlled collection names
def query_collection(user_collection, user_filter):
    query = f'FOR doc IN {user_collection} FILTER {user_filter} RETURN doc'
    return db.aql.execute(query)

# VULNERABLE: No traversal limits
def get_all_paths(start):
    query = f'FOR v IN 1..100 ANY "{start}" GRAPH "knowledge" RETURN v'
    return db.aql.execute(query)
```

**Why**: AQL injection enables unauthorized data access, modification, and system resource exhaustion. Attack: `entity_id = '" || true || "'` bypasses filters.

**Refs**: OWASP A03:2025, CWE-943, ArangoDB Security Documentation

---

## APOC Procedure Security (Neo4j)

### Rule: Restrict APOC Procedures

**Level**: `strict`

**When**: Using APOC procedures in Neo4j for RAG workflows.

**Do**:
```properties
# neo4j.conf - Whitelist only required procedures
dbms.security.procedures.unrestricted=apoc.coll.*,apoc.convert.*,apoc.text.*
dbms.security.procedures.allowlist=apoc.coll.*,apoc.convert.*,apoc.text.*,apoc.cypher.runFirstColumn

# Block dangerous procedures
# DO NOT allow: apoc.load.*, apoc.export.*, apoc.do.*, apoc.periodic.*
```

```python
class SecureAPOCUsage:
    # Allowed APOC procedures for RAG operations
    ALLOWED_PROCEDURES = {
        'apoc.convert.toJson',
        'apoc.convert.fromJsonMap',
        'apoc.text.clean',
        'apoc.coll.flatten',
        'apoc.coll.toSet',
    }

    def use_apoc_procedure(self, procedure: str, params: dict):
        """Use APOC with validation."""
        if procedure not in self.ALLOWED_PROCEDURES:
            raise SecurityError(f"Procedure {procedure} not allowed")

        # Use parameterized call
        with self.driver.session() as session:
            result = session.run(
                f"CALL {procedure}($params) YIELD value RETURN value",
                params=params
            )
            return [record["value"] for record in result]

    def load_json_safely(self, json_data: dict):
        """Convert JSON data safely without file system access."""
        # DO NOT use apoc.load.json - use Python to load, then pass to Neo4j
        with self.driver.session() as session:
            result = session.run(
                """
                UNWIND $data AS item
                MERGE (n:Entity {id: item.id})
                SET n.content = item.content, n.embedding = item.embedding
                RETURN count(n) AS created
                """,
                data=json_data
            )
            return result.single()["created"]
```

**Don't**:
```python
# VULNERABLE: Allowing unrestricted file system access
# neo4j.conf: dbms.security.procedures.unrestricted=apoc.*  # TOO BROAD!

# VULNERABLE: Using apoc.load.csv with user input
def load_user_file(file_path):
    return session.run(f"CALL apoc.load.csv('{file_path}') YIELD map RETURN map")

# VULNERABLE: Using apoc.cypher.run for dynamic queries
def run_dynamic_query(user_query):
    return session.run(f"CALL apoc.cypher.run('{user_query}', {{}}) YIELD value")

# VULNERABLE: HTTP requests via APOC
def fetch_external_data(url):
    return session.run(f"CALL apoc.load.json('{url}') YIELD value RETURN value")
```

**Why**: APOC procedures like `apoc.load.*` and `apoc.cypher.run` can access file systems, make HTTP requests, and execute dynamic Cypher, enabling SSRF and arbitrary code execution.

**Refs**: CWE-918 (SSRF), CWE-94 (Code Injection), Neo4j Security Guide

---

## Traversal Attack Prevention

### Rule: Implement Graph Traversal Controls

**Level**: `strict`

**When**: Allowing users to traverse graph relationships in RAG knowledge graphs.

**Do**:
```python
from dataclasses import dataclass
from typing import Set

@dataclass
class TraversalPolicy:
    max_depth: int = 3
    max_results: int = 100
    allowed_relationships: Set[str] = None
    allowed_labels: Set[str] = None
    timeout_ms: int = 5000

class SecureGraphTraversal:
    def __init__(self, driver):
        self.driver = driver

    def traverse(self, start_id: str, policy: TraversalPolicy):
        """Secure traversal with comprehensive controls."""
        # Validate policy
        if policy.max_depth > 5:
            raise ValueError("Depth limit exceeded maximum allowed (5)")

        if policy.max_results > 1000:
            raise ValueError("Result limit exceeded maximum allowed (1000)")

        # Build safe relationship pattern
        rel_filter = ""
        if policy.allowed_relationships:
            rel_types = "|".join(policy.allowed_relationships)
            rel_filter = f":{rel_types}"

        with self.driver.session() as session:
            result = session.run(
                f"""
                MATCH path = (start {{id: $start_id}})-[r{rel_filter}*1..$depth]-(end)
                WHERE ALL(node IN nodes(path) WHERE
                      ANY(label IN labels(node) WHERE label IN $allowed_labels))
                WITH end, path
                LIMIT $limit
                RETURN DISTINCT end.id AS id, end.content AS content,
                       length(path) AS distance
                """,
                start_id=start_id,
                depth=policy.max_depth,
                allowed_labels=list(policy.allowed_labels or ["Entity", "Concept"]),
                limit=policy.max_results,
                # Note: Set query timeout at database level
            )
            return [record.data() for record in result]

    def check_path_authorization(self, user_id: str, start_id: str, end_id: str):
        """Verify user has permission to access path."""
        with self.driver.session() as session:
            result = session.run(
                """
                // Check if user has access to both endpoints
                MATCH (u:User {id: $user_id})-[:HAS_ACCESS]->(start {id: $start_id})
                MATCH (u)-[:HAS_ACCESS]->(end {id: $end_id})
                RETURN count(*) > 0 AS authorized
                """,
                user_id=user_id,
                start_id=start_id,
                end_id=end_id
            )
            record = result.single()
            return record and record["authorized"]


# Usage for RAG knowledge graph
policy = TraversalPolicy(
    max_depth=3,
    max_results=50,
    allowed_relationships={"RELATES_TO", "PART_OF", "REFERENCES"},
    allowed_labels={"Entity", "Concept", "Document"},
    timeout_ms=3000
)

traversal = SecureGraphTraversal(driver)
results = traversal.traverse("entity_123", policy)
```

**Don't**:
```python
# VULNERABLE: Unlimited depth traversal
def traverse_all(start_id):
    return session.run(f"MATCH (n {{id: '{start_id}'}})-[*]-(m) RETURN m")

# VULNERABLE: No relationship type restrictions
def get_related(node_id):
    return session.run(f"MATCH (n {{id: '{node_id}'}})-[r]-(m) RETURN m, type(r)")

# VULNERABLE: No result limits
def get_all_connections(node_id):
    return session.run(f"MATCH (n {{id: '{node_id}'}})-[*1..10]-(m) RETURN DISTINCT m")

# VULNERABLE: No access control on traversal
def find_path(start, end):
    return session.run(f"MATCH p=shortestPath((a {{id: '{start}'}})-[*]-(b {{id: '{end}'}})) RETURN p")
```

**Why**: Unrestricted traversals can expose sensitive nodes, cause DoS through expensive computations, and leak organizational relationships. Example: Finding paths to admin nodes reveals org structure.

**Refs**: CWE-284 (Improper Access Control), CWE-400 (Resource Exhaustion)

---

## Graph Algorithm Security

### Rule: Control Graph Algorithm Execution

**Level**: `strict`

**When**: Using graph algorithms (GDS) for embeddings, community detection, or centrality in RAG.

**Do**:
```python
class SecureGraphAlgorithms:
    def __init__(self, driver):
        self.driver = driver
        # Resource limits for algorithms
        self.max_node_count = 100000
        self.timeout_seconds = 30
        self.memory_limit_gb = 4

    def run_node2vec(self, graph_name: str, embedding_dimension: int = 128):
        """Secure node2vec for RAG embeddings."""
        # Validate parameters
        if embedding_dimension > 512:
            raise ValueError("Embedding dimension too large")

        # Check graph size before running
        node_count = self._get_graph_size(graph_name)
        if node_count > self.max_node_count:
            raise ResourceError(f"Graph too large: {node_count} nodes")

        with self.driver.session() as session:
            # Create graph projection with limits
            session.run(
                """
                CALL gds.graph.project(
                    $projection_name,
                    $node_labels,
                    $relationship_types,
                    {
                        nodeProperties: ['content'],
                        relationshipProperties: []
                    }
                )
                """,
                projection_name=f"{graph_name}_projection",
                node_labels=["Entity", "Concept"],
                relationship_types=["RELATES_TO"]
            )

            # Run algorithm with timeout
            result = session.run(
                """
                CALL gds.node2vec.stream($projection, {
                    embeddingDimension: $dimension,
                    walkLength: 20,
                    walksPerNode: 10,
                    windowSize: 5,
                    iterations: 1
                })
                YIELD nodeId, embedding
                RETURN gds.util.asNode(nodeId).id AS id, embedding
                LIMIT $limit
                """,
                projection=f"{graph_name}_projection",
                dimension=embedding_dimension,
                limit=10000
            )
            return [record.data() for record in result]

    def _get_graph_size(self, graph_name: str) -> int:
        """Check graph size for resource estimation."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n)
                WHERE any(label IN labels(n) WHERE label IN $allowed_labels)
                RETURN count(n) AS node_count
                """,
                allowed_labels=["Entity", "Concept", "Document"]
            )
            return result.single()["node_count"]

    def community_detection_safe(self, graph_name: str, user_id: str):
        """Run community detection with access control."""
        # Verify user has algorithm execution permission
        if not self._has_algorithm_permission(user_id, "community_detection"):
            raise PermissionError("User not authorized for community detection")

        with self.driver.session() as session:
            result = session.run(
                """
                CALL gds.louvain.stream($projection, {
                    maxIterations: 10,
                    tolerance: 0.0001,
                    maxLevels: 5
                })
                YIELD nodeId, communityId
                WITH gds.util.asNode(nodeId) AS node, communityId
                // Only return communities user has access to
                WHERE exists((node)<-[:HAS_ACCESS]-(:User {id: $user_id}))
                RETURN node.id AS id, communityId
                LIMIT $limit
                """,
                projection=f"{graph_name}_projection",
                user_id=user_id,
                limit=1000
            )
            return [record.data() for record in result]
```

**Don't**:
```python
# VULNERABLE: No size limits before algorithm execution
def run_pagerank():
    return session.run("CALL gds.pageRank.stream('myGraph') YIELD nodeId, score RETURN *")

# VULNERABLE: User-controlled algorithm parameters
def run_algorithm(algorithm_name, params):
    query = f"CALL gds.{algorithm_name}.stream('graph', {params})"
    return session.run(query)

# VULNERABLE: No access control on algorithm results
def get_central_nodes():
    return session.run("""
        CALL gds.betweenness.stream('graph') YIELD nodeId, score
        RETURN gds.util.asNode(nodeId) AS node, score
        ORDER BY score DESC
    """)  # Reveals influential nodes without authorization
```

**Why**: Graph algorithms can exhaust system resources and leak sensitive structural information. Centrality algorithms reveal important nodes; community detection exposes organizational boundaries.

**Refs**: CWE-400 (Resource Exhaustion), CWE-200 (Information Exposure)

---

## Multi-Tenancy Security

### Rule: Implement Tenant Isolation in Graph Databases

**Level**: `strict`

**When**: Multiple tenants share a graph database for RAG knowledge graphs.

**Do**:
```python
from contextlib import contextmanager

class MultiTenantGraphClient:
    def __init__(self, driver):
        self.driver = driver

    @contextmanager
    def tenant_session(self, tenant_id: str):
        """Create session with tenant isolation."""
        # Option 1: Separate databases per tenant (preferred)
        with self.driver.session(database=f"tenant_{tenant_id}") as session:
            yield session

    def query_with_tenant_filter(self, tenant_id: str, query_params: dict):
        """Ensure all queries filter by tenant."""
        with self.driver.session() as session:
            # Add tenant filter to all queries
            result = session.run(
                """
                MATCH (n:Entity {tenant_id: $tenant_id})
                WHERE n.content CONTAINS $search_term
                RETURN n.id AS id, n.content AS content
                LIMIT $limit
                """,
                tenant_id=tenant_id,
                search_term=query_params["search"],
                limit=query_params.get("limit", 100)
            )
            return [record.data() for record in result]

    def create_entity_with_tenant(self, tenant_id: str, entity_data: dict):
        """Create entity with mandatory tenant association."""
        with self.driver.session() as session:
            result = session.run(
                """
                CREATE (n:Entity {
                    id: $id,
                    content: $content,
                    embedding: $embedding,
                    tenant_id: $tenant_id,
                    created_at: datetime()
                })
                // Also create tenant relationship for graph traversal isolation
                WITH n
                MATCH (t:Tenant {id: $tenant_id})
                CREATE (n)-[:BELONGS_TO]->(t)
                RETURN n.id AS id
                """,
                id=entity_data["id"],
                content=entity_data["content"],
                embedding=entity_data.get("embedding"),
                tenant_id=tenant_id
            )
            return result.single()["id"]

    def traverse_within_tenant(self, tenant_id: str, start_id: str, depth: int = 3):
        """Ensure traversal stays within tenant boundary."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH path = (start:Entity {id: $start_id, tenant_id: $tenant_id})
                            -[*1..$depth]-(end:Entity {tenant_id: $tenant_id})
                WHERE ALL(node IN nodes(path) WHERE node.tenant_id = $tenant_id)
                RETURN DISTINCT end.id AS id, end.content AS content,
                       length(path) AS distance
                LIMIT $limit
                """,
                start_id=start_id,
                tenant_id=tenant_id,
                depth=depth,
                limit=100
            )
            return [record.data() for record in result]


# Property-level encryption for sensitive tenant data
from cryptography.fernet import Fernet

class EncryptedPropertyHandler:
    def __init__(self, tenant_keys: dict):
        self.tenant_keys = tenant_keys  # tenant_id -> encryption key

    def encrypt_property(self, tenant_id: str, value: str) -> str:
        """Encrypt sensitive property value."""
        key = self.tenant_keys.get(tenant_id)
        if not key:
            raise SecurityError(f"No encryption key for tenant {tenant_id}")
        f = Fernet(key)
        return f.encrypt(value.encode()).decode()

    def decrypt_property(self, tenant_id: str, encrypted_value: str) -> str:
        """Decrypt property value for authorized tenant."""
        key = self.tenant_keys.get(tenant_id)
        if not key:
            raise SecurityError(f"No encryption key for tenant {tenant_id}")
        f = Fernet(key)
        return f.decrypt(encrypted_value.encode()).decode()
```

**Don't**:
```python
# VULNERABLE: No tenant isolation
def find_entity(entity_id):
    return session.run("MATCH (n:Entity {id: $id}) RETURN n", id=entity_id)

# VULNERABLE: Label-based isolation only (easily bypassed)
def find_entity_by_label(tenant_id, entity_id):
    return session.run(f"MATCH (n:{tenant_id} {{id: $id}}) RETURN n", id=entity_id)

# VULNERABLE: Traversal can cross tenant boundaries
def traverse(start_id, depth):
    return session.run("MATCH (n {id: $id})-[*1..$depth]-(m) RETURN m",
                      id=start_id, depth=depth)

# VULNERABLE: Shared properties without encryption
def store_pii(tenant_id, user_id, pii_data):
    session.run("""
        CREATE (n:UserData {tenant_id: $tid, user_id: $uid, ssn: $ssn})
    """, tid=tenant_id, uid=user_id, ssn=pii_data["ssn"])  # PII in plaintext
```

**Why**: Without proper isolation, queries can access other tenants' data. Label-based isolation can be bypassed via MATCH patterns without label filters.

**Refs**: CWE-284 (Improper Access Control), CWE-311 (Missing Encryption)

---

## Export/Import Security

### Rule: Secure Graph Data Export and Import

**Level**: `strict`

**When**: Exporting graph data for backup, migration, or sharing RAG knowledge graphs.

**Do**:
```python
import hashlib
import json
import gzip
from cryptography.fernet import Fernet
from datetime import datetime

class SecureGraphExport:
    def __init__(self, driver, encryption_key: bytes):
        self.driver = driver
        self.fernet = Fernet(encryption_key)

    def export_graph(self, graph_name: str, output_path: str, include_embeddings: bool = False):
        """Export graph data with encryption and integrity verification."""
        with self.driver.session() as session:
            # Export nodes
            nodes_result = session.run(
                """
                MATCH (n)
                WHERE any(label IN labels(n) WHERE label IN $allowed_labels)
                RETURN id(n) AS internal_id, labels(n) AS labels, properties(n) AS props
                """,
                allowed_labels=["Entity", "Concept", "Document"]
            )
            nodes = [record.data() for record in nodes_result]

            # Export relationships
            rels_result = session.run(
                """
                MATCH (s)-[r]->(e)
                WHERE any(l IN labels(s) WHERE l IN $allowed)
                  AND any(l IN labels(e) WHERE l IN $allowed)
                RETURN id(s) AS start_id, id(e) AS end_id, type(r) AS type,
                       properties(r) AS props
                """,
                allowed=["Entity", "Concept", "Document"]
            )
            relationships = [record.data() for record in rels_result]

        # Remove embeddings if not requested (large, sensitive)
        if not include_embeddings:
            for node in nodes:
                node["props"].pop("embedding", None)

        # Create export package
        export_data = {
            "graph_name": graph_name,
            "exported_at": datetime.utcnow().isoformat(),
            "node_count": len(nodes),
            "relationship_count": len(relationships),
            "nodes": nodes,
            "relationships": relationships
        }

        # Serialize and compress
        json_bytes = json.dumps(export_data).encode()
        compressed = gzip.compress(json_bytes)

        # Encrypt
        encrypted = self.fernet.encrypt(compressed)

        # Generate integrity hash
        content_hash = hashlib.sha256(encrypted).hexdigest()

        # Create signed package
        package = {
            "version": "1.0",
            "encrypted_data": encrypted.decode('latin-1'),
            "sha256": content_hash,
            "exported_at": export_data["exported_at"]
        }

        with open(output_path, 'w') as f:
            json.dump(package, f)

        return {"path": output_path, "hash": content_hash}

    def import_graph(self, input_path: str, validate_only: bool = False):
        """Import graph data with integrity verification."""
        with open(input_path, 'r') as f:
            package = json.load(f)

        # Verify version
        if package.get("version") != "1.0":
            raise ImportError(f"Unsupported export version: {package.get('version')}")

        # Verify integrity
        encrypted_bytes = package["encrypted_data"].encode('latin-1')
        actual_hash = hashlib.sha256(encrypted_bytes).hexdigest()
        if actual_hash != package["sha256"]:
            raise SecurityError("Export file integrity check failed - possible tampering")

        # Decrypt
        try:
            compressed = self.fernet.decrypt(encrypted_bytes)
        except Exception as e:
            raise SecurityError(f"Decryption failed: {e}")

        # Decompress and parse
        json_bytes = gzip.decompress(compressed)
        export_data = json.loads(json_bytes)

        if validate_only:
            return {
                "valid": True,
                "node_count": export_data["node_count"],
                "relationship_count": export_data["relationship_count"]
            }

        # Import to database
        return self._import_data(export_data)

    def _import_data(self, export_data: dict):
        """Import validated data into graph."""
        with self.driver.session() as session:
            # Import nodes with parameterized queries
            for node in export_data["nodes"]:
                labels = ":".join(node["labels"])
                session.run(
                    f"""
                    CREATE (n:{labels})
                    SET n = $props
                    """,
                    props=node["props"]
                )

            # Import relationships
            for rel in export_data["relationships"]:
                session.run(
                    f"""
                    MATCH (s) WHERE id(s) = $start_id
                    MATCH (e) WHERE id(e) = $end_id
                    CREATE (s)-[r:{rel['type']}]->(e)
                    SET r = $props
                    """,
                    start_id=rel["start_id"],
                    end_id=rel["end_id"],
                    props=rel["props"]
                )

        return {
            "imported_nodes": export_data["node_count"],
            "imported_relationships": export_data["relationship_count"]
        }
```

**Don't**:
```python
# VULNERABLE: Unencrypted export
def export_graph(output_path):
    data = session.run("MATCH (n) RETURN n").data()
    with open(output_path, 'w') as f:
        json.dump(data, f)  # Plaintext export!

# VULNERABLE: No integrity verification on import
def import_graph(input_path):
    with open(input_path) as f:
        data = json.load(f)  # Could be tampered
    for node in data:
        session.run(f"CREATE (n:{node['label']}) SET n = $props", props=node)

# VULNERABLE: Deserializing untrusted data
import pickle
def import_pickle(path):
    with open(path, 'rb') as f:
        return pickle.load(f)  # Arbitrary code execution!

# VULNERABLE: Including sensitive data in exports
def export_all():
    return session.run("MATCH (n) RETURN n").data()  # Includes embeddings, PII
```

**Why**: Unencrypted exports expose sensitive data. Unsigned imports allow tampered data injection. Pickle deserialization enables arbitrary code execution.

**Refs**: CWE-502 (Deserialization), CWE-311 (Missing Encryption), CWE-354 (Improper Validation of Integrity Check)

---

## Database-Specific Security Configurations

### Neo4j Security Configuration

```properties
# neo4j.conf - Security hardening

# Authentication
dbms.security.auth_enabled=true
dbms.security.auth_lock_time=5s
dbms.security.auth_max_failed_attempts=3

# Encryption
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates/bolt
dbms.ssl.policy.bolt.private_key=private.key
dbms.ssl.policy.bolt.public_certificate=public.crt

# Procedure security
dbms.security.procedures.unrestricted=
dbms.security.procedures.allowlist=apoc.coll.*,apoc.convert.*,apoc.text.*

# Query limits
dbms.transaction.timeout=30s
dbms.memory.heap.max_size=4G
dbms.memory.transaction.global_max_size=2G

# Audit logging
dbms.security.log_successful_authentication=true
dbms.logs.security.level=INFO
```

### Amazon Neptune Security (CloudFormation)

```yaml
Resources:
  NeptuneCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      DBClusterIdentifier: rag-knowledge-graph
      EngineVersion: "1.2.0.2"
      IamAuthEnabled: true  # Enable IAM authentication
      StorageEncrypted: true
      KmsKeyId: !Ref NeptuneKMSKey
      EnableCloudwatchLogsExports:
        - audit
      VpcSecurityGroupIds:
        - !Ref NeptuneSecurityGroup
      DBClusterParameterGroupName: !Ref NeptuneParameterGroup
      DeletionProtection: true

  NeptuneParameterGroup:
    Type: AWS::Neptune::DBClusterParameterGroup
    Properties:
      Family: neptune1.2
      Parameters:
        neptune_enable_audit_log: "1"
        neptune_query_timeout: 30000  # 30 seconds

  NeptuneSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Neptune security group
      VpcId: !Ref VPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 8182
          ToPort: 8182
          SourceSecurityGroupId: !Ref AppSecurityGroup  # Only from app servers
```

### ArangoDB Security Configuration

```yaml
# arangod.conf
[server]
authentication = true
jwt-secret = /secure/jwt-secret  # External secret management

[ssl]
keyfile = /secure/server.pem
cafile = /secure/ca.pem

[query]
memory-limit = 4294967296  # 4GB
max-runtime = 30.0  # 30 seconds
slow-threshold = 10.0  # Log queries > 10s

[log]
level = info
audit-level = info
```

---

## Monitoring and Audit

### Rule: Implement Graph Database Audit Logging

**Level**: `warning`

**When**: Operating graph databases containing RAG knowledge graphs in production.

**Do**:
```python
import logging
import time
import hashlib
from functools import wraps

class GraphDatabaseAuditLogger:
    def __init__(self, logger_name="graph_audit"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)

    def audit_query(self, user_id: str, query_type: str):
        """Decorator for auditing graph queries."""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                query_id = hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()[:12]

                # Log query start
                self.logger.info({
                    "event": "query_start",
                    "query_id": query_id,
                    "user_id": user_id,
                    "query_type": query_type,
                    "timestamp": time.time()
                })

                try:
                    result = func(*args, **kwargs)

                    # Log successful completion
                    self.logger.info({
                        "event": "query_complete",
                        "query_id": query_id,
                        "user_id": user_id,
                        "duration_ms": (time.time() - start_time) * 1000,
                        "result_count": len(result) if hasattr(result, '__len__') else 1
                    })

                    return result

                except Exception as e:
                    # Log failure
                    self.logger.error({
                        "event": "query_failed",
                        "query_id": query_id,
                        "user_id": user_id,
                        "error": str(e),
                        "duration_ms": (time.time() - start_time) * 1000
                    })
                    raise
            return wrapper
        return decorator

    def log_security_event(self, event_type: str, user_id: str, details: dict):
        """Log security-relevant events."""
        self.logger.warning({
            "event": event_type,
            "user_id": user_id,
            "timestamp": time.time(),
            **details
        })

# Usage
audit = GraphDatabaseAuditLogger()

@audit.audit_query(user_id="user_123", query_type="entity_lookup")
def find_entity(entity_id: str):
    return neo4j_client.find_entity(entity_id)

# Log security events
audit.log_security_event(
    "traversal_limit_exceeded",
    user_id="user_456",
    {"requested_depth": 10, "max_allowed": 5}
)
```

---

## Quick Reference

| Rule | Level | CWE | OWASP |
|------|-------|-----|-------|
| Parameterized Cypher (Neo4j) | strict | CWE-943 | A03:2025 |
| Parameterized Gremlin (Neptune) | strict | CWE-943 | A03:2025 |
| Parameterized AQL (ArangoDB) | strict | CWE-943 | A03:2025 |
| APOC Procedure Restrictions | strict | CWE-94, CWE-918 | A03:2025 |
| Traversal Controls | strict | CWE-284, CWE-400 | A01:2025 |
| Graph Algorithm Security | strict | CWE-400, CWE-200 | A01:2025 |
| Multi-Tenancy Isolation | strict | CWE-284, CWE-311 | A01:2025 |
| Secure Export/Import | strict | CWE-502, CWE-311 | A08:2025 |
| Audit Logging | warning | CWE-778 | A09:2025 |

---

## Version History

- **v1.0.0** - Initial release covering Neo4j, Neptune, ArangoDB, TigerGraph, Memgraph
