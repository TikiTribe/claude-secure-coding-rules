# ArangoDB Security Rules for Claude Code

**Prerequisites**: `rules/_core/rag-security.md`, `rules/_core/graph-database-security.md`

These rules enforce secure coding practices for ArangoDB multi-model database operations in RAG systems, covering AQL injection prevention, access control, Foxx services, and cluster security.

---

## Rule 1: AQL Injection Prevention with Bind Variables

**Level**: `strict`

**When**: Constructing AQL queries with any dynamic values, user input, or application data

**Do**: Always use bind variables for dynamic values in AQL queries

```python
from arango import ArangoClient

def get_user_documents(db, user_id: str, collection: str):
    """Secure AQL query using bind variables."""
    # Validate collection name against allowlist
    allowed_collections = {"users", "documents", "embeddings"}
    if collection not in allowed_collections:
        raise ValueError(f"Invalid collection: {collection}")

    # Use bind variables for all dynamic values
    aql = """
        FOR doc IN @@collection
            FILTER doc.user_id == @user_id
            FILTER doc.active == true
            RETURN doc
    """

    cursor = db.aql.execute(
        aql,
        bind_vars={
            "@collection": collection,  # @@ for collection names
            "user_id": user_id          # @ for values
        }
    )

    return list(cursor)

def search_with_filters(db, filters: dict):
    """Complex query with multiple bind variables."""
    aql = """
        FOR doc IN documents
            FILTER doc.category == @category
            FILTER doc.created_at >= @start_date
            FILTER doc.status IN @allowed_statuses
            SORT doc.created_at DESC
            LIMIT @offset, @limit
            RETURN doc
    """

    cursor = db.aql.execute(
        aql,
        bind_vars={
            "category": filters.get("category", "default"),
            "start_date": filters.get("start_date", "2020-01-01"),
            "allowed_statuses": ["active", "pending"],
            "offset": max(0, int(filters.get("offset", 0))),
            "limit": min(100, int(filters.get("limit", 10)))
        }
    )

    return list(cursor)
```

**Don't**: Concatenate user input directly into AQL queries

```python
def get_user_documents_vulnerable(db, user_id: str, collection: str):
    """VULNERABLE: Direct string interpolation in AQL."""
    # DANGEROUS: AQL injection vulnerability
    aql = f"""
        FOR doc IN {collection}
            FILTER doc.user_id == "{user_id}"
            RETURN doc
    """

    cursor = db.aql.execute(aql)
    return list(cursor)

# Attack example:
# user_id = '" || true || "'
# collection = "users REMOVE doc IN users //"
```

**Why**: AQL injection allows attackers to bypass access controls, exfiltrate data, modify or delete records, and potentially execute administrative operations. ArangoDB's AQL is Turing-complete and supports data modification operations, making injection attacks particularly dangerous in multi-model scenarios.

**Refs**: CWE-89, OWASP A03:2025, ArangoDB Security Best Practices

---

## Rule 2: Multi-Model Access Control

**Level**: `strict`

**When**: Accessing data through different ArangoDB models (document, graph, key-value) or switching between access patterns

**Do**: Implement consistent access control across all data models

```python
from arango import ArangoClient
from functools import wraps

class MultiModelAccessControl:
    """Unified access control for ArangoDB multi-model operations."""

    def __init__(self, db, user_context):
        self.db = db
        self.user = user_context
        self.permissions = self._load_permissions()

    def _load_permissions(self) -> dict:
        """Load user permissions from database."""
        aql = """
            FOR perm IN permissions
                FILTER perm.user_id == @user_id
                RETURN perm
        """
        cursor = self.db.aql.execute(
            aql,
            bind_vars={"user_id": self.user.id}
        )
        return {p["resource"]: p["actions"] for p in cursor}

    def check_permission(self, resource: str, action: str) -> bool:
        """Check if user has permission for action on resource."""
        if resource not in self.permissions:
            return False
        return action in self.permissions[resource]

    # Document model access
    def get_document(self, collection: str, key: str):
        """Access document with permission check."""
        if not self.check_permission(f"collection:{collection}", "read"):
            raise PermissionError(f"No read access to {collection}")

        return self.db.collection(collection).get(key)

    # Graph model access
    def traverse_graph(self, graph_name: str, start_vertex: str,
                       direction: str = "outbound", max_depth: int = 3):
        """Graph traversal with permission and depth limits."""
        if not self.check_permission(f"graph:{graph_name}", "traverse"):
            raise PermissionError(f"No traverse access to {graph_name}")

        # Enforce maximum depth limit
        safe_depth = min(max_depth, 5)

        aql = """
            FOR v, e, p IN 1..@max_depth @direction @start_vertex
                GRAPH @graph_name
                LIMIT @max_results
                RETURN {vertex: v, edge: e, path: p}
        """

        cursor = self.db.aql.execute(
            aql,
            bind_vars={
                "max_depth": safe_depth,
                "direction": direction,
                "start_vertex": start_vertex,
                "graph_name": graph_name,
                "max_results": 1000
            }
        )

        return list(cursor)

    # Key-value model access
    def get_by_key(self, collection: str, key: str):
        """Key-value access with permission check."""
        if not self.check_permission(f"kv:{collection}", "read"):
            raise PermissionError(f"No key-value read access to {collection}")

        return self.db.collection(collection).get({"_key": key})
```

**Don't**: Allow inconsistent access control between data models

```python
def vulnerable_multi_model_access(db, user_id, doc_key):
    """VULNERABLE: Inconsistent access control across models."""
    # Document access has permission check
    if not check_document_permission(user_id, "documents"):
        raise PermissionError("No access")

    doc = db.collection("documents").get(doc_key)

    # DANGEROUS: Graph traversal bypasses permission check
    # Attacker can access restricted nodes through graph relationships
    graph = db.graph("knowledge_graph")
    neighbors = graph.traverse(
        start_vertex=f"documents/{doc_key}",
        direction="any",
        max_depth=10  # No depth limit enforcement
    )

    return {"document": doc, "related": neighbors}
```

**Why**: ArangoDB's multi-model capability allows the same data to be accessed through different paradigms. Attackers can exploit inconsistent access controls by accessing restricted data through an alternative model that lacks proper authorization checks.

**Refs**: CWE-284, CWE-863, OWASP A01:2025

---

## Rule 3: User Authentication and JWT Security

**Level**: `strict`

**When**: Configuring ArangoDB authentication, managing user sessions, or implementing JWT-based access

**Do**: Use strong authentication with secure JWT configuration

```python
from arango import ArangoClient
import jwt
import secrets
from datetime import datetime, timedelta

class SecureArangoAuth:
    """Secure authentication wrapper for ArangoDB."""

    def __init__(self, hosts: list, jwt_secret: str):
        self.client = ArangoClient(hosts=hosts)
        self.jwt_secret = jwt_secret
        self._validate_jwt_secret()

    def _validate_jwt_secret(self):
        """Ensure JWT secret meets security requirements."""
        if len(self.jwt_secret) < 32:
            raise ValueError("JWT secret must be at least 32 characters")

    def authenticate_user(self, username: str, password: str) -> dict:
        """Authenticate user and return JWT token."""
        # Connect to _system database for authentication
        sys_db = self.client.db(
            "_system",
            username=username,
            password=password,
            verify=True  # Verify TLS certificate
        )

        # Verify credentials by attempting database access
        try:
            sys_db.properties()
        except Exception:
            raise AuthenticationError("Invalid credentials")

        # Generate JWT with security claims
        token_payload = {
            "sub": username,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "jti": secrets.token_urlsafe(16),  # Unique token ID
            "iss": "arango-auth-service"
        }

        token = jwt.encode(
            token_payload,
            self.jwt_secret,
            algorithm="HS256"
        )

        return {
            "token": token,
            "expires_in": 3600,
            "token_type": "Bearer"
        }

    def get_authenticated_db(self, token: str, db_name: str):
        """Get database connection using JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "sub", "jti"],
                    "verify_exp": True
                }
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")

        # Use superuser JWT for ArangoDB (configured in arangod.conf)
        return self.client.db(
            db_name,
            username=payload["sub"],
            verify=True
        )

    def create_database_user(self, sys_db, username: str,
                             password: str, databases: dict):
        """Create user with specific database permissions."""
        # Validate password strength
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")

        # Create user with explicit permissions
        sys_db.create_user(
            username=username,
            password=password,
            active=True
        )

        # Grant specific permissions per database
        for db_name, permission in databases.items():
            if permission not in ["ro", "rw", "none"]:
                raise ValueError(f"Invalid permission: {permission}")

            sys_db.update_permission(
                username=username,
                permission=permission,
                database=db_name
            )

        return {"username": username, "databases": databases}
```

**Don't**: Use weak authentication or insecure JWT configuration

```python
def vulnerable_auth_setup(client):
    """VULNERABLE: Weak authentication configuration."""
    # DANGEROUS: Hardcoded credentials
    db = client.db(
        "production",
        username="root",
        password="root123",  # Weak password
        verify=False  # Disabled TLS verification
    )

    # DANGEROUS: Weak JWT configuration
    token = jwt.encode(
        {"user": "admin"},
        "secret",  # Too short, easily guessable
        algorithm="none"  # No algorithm!
    )

    # DANGEROUS: No token expiration
    payload = jwt.decode(token, options={"verify_signature": False})

    return db
```

**Why**: Weak authentication allows unauthorized access to the database. Insecure JWT configuration enables token forgery, replay attacks, and session hijacking. ArangoDB's powerful query language makes unauthorized access particularly dangerous.

**Refs**: CWE-287, CWE-347, OWASP A07:2025

---

## Rule 4: Database and Collection-Level RBAC

**Level**: `strict`

**When**: Setting up database permissions, creating collections, or managing user access rights

**Do**: Implement granular RBAC at database and collection levels

```python
from arango import ArangoClient

class ArangoRBACManager:
    """Role-based access control manager for ArangoDB."""

    def __init__(self, sys_db):
        self.sys_db = sys_db

    def create_role_based_user(self, username: str, password: str,
                                role: str) -> dict:
        """Create user with predefined role permissions."""
        # Define role templates
        roles = {
            "reader": {
                "databases": {"rag_db": "ro"},
                "collections": {
                    "rag_db": {
                        "documents": "ro",
                        "embeddings": "ro",
                        "users": "none"
                    }
                }
            },
            "writer": {
                "databases": {"rag_db": "rw"},
                "collections": {
                    "rag_db": {
                        "documents": "rw",
                        "embeddings": "rw",
                        "users": "none"
                    }
                }
            },
            "admin": {
                "databases": {"rag_db": "rw"},
                "collections": {
                    "rag_db": {
                        "*": "rw"
                    }
                }
            }
        }

        if role not in roles:
            raise ValueError(f"Unknown role: {role}")

        role_config = roles[role]

        # Create user
        self.sys_db.create_user(
            username=username,
            password=password,
            active=True
        )

        # Apply database-level permissions
        for db_name, perm in role_config["databases"].items():
            self.sys_db.update_permission(
                username=username,
                permission=perm,
                database=db_name
            )

        # Apply collection-level permissions
        for db_name, collections in role_config["collections"].items():
            for collection, perm in collections.items():
                self.sys_db.update_permission(
                    username=username,
                    permission=perm,
                    database=db_name,
                    collection=collection
                )

        return {"username": username, "role": role}

    def setup_collection_access(self, db_name: str, collection_name: str,
                                 access_rules: list):
        """Configure fine-grained collection access."""
        for rule in access_rules:
            username = rule["username"]
            permission = rule["permission"]

            # Validate permission value
            if permission not in ["ro", "rw", "none"]:
                raise ValueError(f"Invalid permission: {permission}")

            self.sys_db.update_permission(
                username=username,
                permission=permission,
                database=db_name,
                collection=collection_name
            )

    def audit_user_permissions(self, username: str) -> dict:
        """Audit all permissions for a user."""
        permissions = self.sys_db.permissions(username)

        audit_report = {
            "username": username,
            "databases": {},
            "excessive_permissions": []
        }

        for db_name, db_perm in permissions.items():
            if isinstance(db_perm, str):
                audit_report["databases"][db_name] = db_perm

                # Flag excessive permissions
                if db_perm == "rw" and db_name == "_system":
                    audit_report["excessive_permissions"].append(
                        f"User has write access to _system database"
                    )

        return audit_report
```

**Don't**: Use overly permissive or inconsistent access controls

```python
def vulnerable_permission_setup(sys_db, username):
    """VULNERABLE: Overly permissive access control."""
    # DANGEROUS: Grant access to all databases
    sys_db.update_permission(
        username=username,
        permission="rw",
        database="*"  # All databases including _system
    )

    # DANGEROUS: No collection-level restrictions
    # User can access all collections in all databases

    # DANGEROUS: Never audit or review permissions
    return {"status": "created"}
```

**Why**: Without granular RBAC, users may access sensitive collections they shouldn't see, modify system databases, or escalate privileges. ArangoDB's multi-model nature means a single overly-permissive grant can expose document, graph, and key-value data simultaneously.

**Refs**: CWE-284, CWE-269, OWASP A01:2025

---

## Rule 5: Foxx Microservices Security

**Level**: `strict`

**When**: Developing Foxx microservices, configuring service permissions, or deploying custom APIs on ArangoDB

**Do**: Implement secure Foxx services with proper sandboxing and permission controls

```javascript
// Secure Foxx service configuration (manifest.json)
{
  "name": "secure-rag-service",
  "version": "1.0.0",
  "engines": {
    "arangodb": "^3.10"
  },
  "configuration": {
    "jwtSecret": {
      "type": "password",
      "required": true,
      "description": "Secret for JWT validation"
    },
    "maxQueryDepth": {
      "type": "integer",
      "default": 5,
      "description": "Maximum graph traversal depth"
    }
  },
  "dependencies": {
    "sessions": "sessions-local"
  },
  "provides": {
    "rag-api": "1.0.0"
  }
}
```

```javascript
// Secure Foxx router implementation (index.js)
'use strict';
const createRouter = require('@arangodb/foxx/router');
const sessionsMiddleware = require('@arangodb/foxx/sessions');
const joi = require('joi');
const crypto = require('@arangodb/crypto');

const router = createRouter();
const db = require('@arangodb').db;

// Configure session middleware
const sessions = sessionsMiddleware({
  storage: module.context.dependencies.sessions,
  transport: 'header'
});

router.use(sessions);

// Input validation middleware
router.use((req, res, next) => {
  // Rate limiting check
  const clientIp = req.headers['x-forwarded-for'] || req.remoteAddress;
  const rateLimitKey = `ratelimit:${clientIp}`;

  // Implement rate limiting logic here
  next();
});

// Secure endpoint with validation
router.post('/search', (req, res) => {
  // Validate input with joi schema
  const schema = joi.object({
    query: joi.string().max(1000).required(),
    collection: joi.string().alphanum().max(64).required(),
    limit: joi.number().integer().min(1).max(100).default(10)
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    res.status(400).json({ error: error.details[0].message });
    return;
  }

  // Verify collection is in allowlist
  const allowedCollections = ['documents', 'embeddings'];
  if (!allowedCollections.includes(value.collection)) {
    res.status(403).json({ error: 'Collection not allowed' });
    return;
  }

  // Use bind variables in AQL
  const cursor = db._query(`
    FOR doc IN @@collection
      FILTER CONTAINS(LOWER(doc.content), LOWER(@query))
      LIMIT @limit
      RETURN doc
  `, {
    '@collection': value.collection,
    query: value.query,
    limit: value.limit
  });

  res.json(cursor.toArray());
})
.body(joi.object().required())
.response(['application/json'])
.summary('Search documents')
.description('Search documents with input validation');

// Authenticated endpoint
router.get('/user/documents', (req, res) => {
  // Verify session authentication
  if (!req.session.uid) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const userId = req.session.uid;

  // Query only user's documents
  const cursor = db._query(`
    FOR doc IN documents
      FILTER doc.owner == @userId
      RETURN doc
  `, { userId });

  res.json(cursor.toArray());
})
.response(['application/json'])
.summary('Get user documents')
.description('Retrieve documents owned by authenticated user');

module.exports = router;
```

**Don't**: Deploy Foxx services without security controls

```javascript
// VULNERABLE: Insecure Foxx service
'use strict';
const router = require('@arangodb/foxx/router')();
const db = require('@arangodb').db;

// DANGEROUS: No input validation
router.post('/query', (req, res) => {
  const { aql } = req.body;

  // DANGEROUS: Direct AQL execution from user input
  const result = db._query(aql);
  res.json(result.toArray());
});

// DANGEROUS: Exposes internal modules
router.get('/internal/:module', (req, res) => {
  const mod = require(req.pathParams.module);
  res.json(Object.keys(mod));
});

// DANGEROUS: No authentication check
router.delete('/documents/:id', (req, res) => {
  db.documents.remove(req.pathParams.id);
  res.json({ deleted: true });
});

module.exports = router;
```

**Why**: Foxx microservices run inside ArangoDB with full database access. Insecure services can be exploited for AQL injection, unauthorized data access, denial of service, or arbitrary code execution within the database server context.

**Refs**: CWE-94, CWE-284, OWASP A03:2025

---

## Rule 6: Graph Traversal Limits

**Level**: `strict`

**When**: Implementing graph queries, traversals, or path-finding operations in RAG knowledge graphs

**Do**: Enforce strict limits on traversal depth, vertex count, and execution time

```python
from arango import ArangoClient
import time

class SecureGraphTraversal:
    """Secure graph traversal with resource limits."""

    # Maximum allowed values
    MAX_DEPTH = 5
    MAX_VERTICES = 1000
    MAX_EDGES = 5000
    MAX_EXECUTION_TIME = 30  # seconds

    def __init__(self, db):
        self.db = db

    def traverse(self, graph_name: str, start_vertex: str,
                 direction: str = "outbound",
                 depth: int = 3,
                 vertex_limit: int = 100) -> dict:
        """Execute graph traversal with security limits."""

        # Enforce maximum depth
        safe_depth = min(depth, self.MAX_DEPTH)
        if depth > self.MAX_DEPTH:
            raise ValueError(
                f"Depth {depth} exceeds maximum {self.MAX_DEPTH}"
            )

        # Enforce vertex limit
        safe_vertex_limit = min(vertex_limit, self.MAX_VERTICES)

        # Validate direction
        if direction not in ["outbound", "inbound", "any"]:
            raise ValueError(f"Invalid direction: {direction}")

        # Build traversal query with limits
        aql = """
            FOR v, e, p IN 1..@depth @direction @start_vertex
                GRAPH @graph_name
                OPTIONS {
                    bfs: true,
                    uniqueVertices: 'global',
                    uniqueEdges: 'path'
                }
                LIMIT @vertex_limit
                RETURN {
                    vertex: v,
                    edge: e,
                    depth: LENGTH(p.edges)
                }
        """

        # Execute with timeout
        cursor = self.db.aql.execute(
            aql,
            bind_vars={
                "depth": safe_depth,
                "direction": direction,
                "start_vertex": start_vertex,
                "graph_name": graph_name,
                "vertex_limit": safe_vertex_limit
            },
            max_runtime=self.MAX_EXECUTION_TIME
        )

        results = list(cursor)

        return {
            "vertices": results,
            "count": len(results),
            "depth_used": safe_depth,
            "truncated": len(results) >= safe_vertex_limit
        }

    def shortest_path(self, graph_name: str,
                      start_vertex: str,
                      end_vertex: str) -> dict:
        """Find shortest path with security limits."""

        aql = """
            FOR v, e IN OUTBOUND SHORTEST_PATH
                @start_vertex TO @end_vertex
                GRAPH @graph_name
                OPTIONS {
                    weightAttribute: 'weight'
                }
                LIMIT @max_path_length
                RETURN {vertex: v, edge: e}
        """

        cursor = self.db.aql.execute(
            aql,
            bind_vars={
                "start_vertex": start_vertex,
                "end_vertex": end_vertex,
                "graph_name": graph_name,
                "max_path_length": self.MAX_DEPTH * 2
            },
            max_runtime=self.MAX_EXECUTION_TIME
        )

        return list(cursor)

    def k_paths(self, graph_name: str, start_vertex: str,
                end_vertex: str, k: int = 5) -> list:
        """Find K shortest paths with limits."""

        # Limit K to prevent resource exhaustion
        safe_k = min(k, 10)

        aql = """
            FOR path IN OUTBOUND K_PATHS
                @start_vertex TO @end_vertex
                GRAPH @graph_name
                LIMIT @k
                RETURN path
        """

        cursor = self.db.aql.execute(
            aql,
            bind_vars={
                "start_vertex": start_vertex,
                "end_vertex": end_vertex,
                "graph_name": graph_name,
                "k": safe_k
            },
            max_runtime=self.MAX_EXECUTION_TIME
        )

        return list(cursor)
```

**Don't**: Allow unbounded graph traversals

```python
def vulnerable_traversal(db, graph_name, start_vertex, depth):
    """VULNERABLE: Unbounded graph traversal."""
    # DANGEROUS: No depth limit enforcement
    aql = f"""
        FOR v, e, p IN 1..{depth} ANY '{start_vertex}'
            GRAPH '{graph_name}'
            RETURN v
    """

    # DANGEROUS: No timeout, no vertex limit
    cursor = db.aql.execute(aql)

    # DANGEROUS: Loading all results into memory
    return list(cursor)

# Attack: depth=1000000 causes resource exhaustion
```

**Why**: Unbounded graph traversals can consume excessive CPU, memory, and I/O resources, leading to denial of service. Deep traversals in densely connected graphs can explode exponentially, potentially crashing the database server or affecting other tenants.

**Refs**: CWE-400, CWE-770, OWASP API4:2023

---

## Rule 7: Smart Graph Security for Sharding

**Level**: `warning`

**When**: Using ArangoDB SmartGraphs for distributed RAG systems with sharded collections

**Do**: Configure SmartGraphs with secure sharding keys and access patterns

```python
from arango import ArangoClient

class SecureSmartGraphManager:
    """Secure SmartGraph management for sharded deployments."""

    def __init__(self, db):
        self.db = db

    def create_smart_graph(self, graph_name: str,
                           edge_definitions: list,
                           smart_field: str = "tenant_id",
                           num_shards: int = 3) -> dict:
        """Create SmartGraph with security-aware sharding."""

        # Validate smart field for tenant isolation
        if smart_field not in ["tenant_id", "user_id", "org_id"]:
            raise ValueError(
                f"Smart field must be a tenant identifier, not {smart_field}"
            )

        # Create SmartGraph with enterprise features
        graph = self.db.create_graph(
            graph_name,
            edge_definitions=edge_definitions,
            smart=True,
            smart_field=smart_field,
            shard_count=num_shards,
            replication_factor=2,  # Data redundancy
            write_concern=2  # Require writes to multiple replicas
        )

        return {
            "graph": graph_name,
            "smart_field": smart_field,
            "shards": num_shards
        }

    def query_with_tenant_isolation(self, graph_name: str,
                                    tenant_id: str,
                                    query_params: dict) -> list:
        """Execute graph query with tenant isolation enforced."""

        # SmartGraph queries are efficient when filtering by smart field
        aql = """
            FOR v IN @@vertices
                FILTER v.tenant_id == @tenant_id
                FOR neighbor IN 1..2 OUTBOUND v
                    GRAPH @graph_name
                    FILTER neighbor.tenant_id == @tenant_id
                    LIMIT @limit
                    RETURN neighbor
        """

        cursor = self.db.aql.execute(
            aql,
            bind_vars={
                "@vertices": query_params.get("collection", "documents"),
                "tenant_id": tenant_id,
                "graph_name": graph_name,
                "limit": min(query_params.get("limit", 100), 1000)
            }
        )

        return list(cursor)

    def create_satellite_collection(self, collection_name: str,
                                    content: list) -> dict:
        """Create satellite collection for shared lookup data."""

        # Satellite collections are replicated to all shards
        # Use only for small, read-heavy, shared data
        if len(content) > 10000:
            raise ValueError(
                "Satellite collections should contain < 10K documents"
            )

        self.db.create_collection(
            collection_name,
            replication_factor="satellite"
        )

        # Insert lookup data
        collection = self.db.collection(collection_name)
        collection.insert_many(content)

        return {
            "collection": collection_name,
            "type": "satellite",
            "documents": len(content)
        }
```

**Don't**: Misconfigure SmartGraphs allowing cross-tenant data access

```python
def vulnerable_smart_graph(db):
    """VULNERABLE: SmartGraph without tenant isolation."""
    # DANGEROUS: Using non-isolating smart field
    graph = db.create_graph(
        "rag_graph",
        smart=True,
        smart_field="category",  # Not a tenant identifier!
        shard_count=1  # Single shard defeats purpose
    )

    # DANGEROUS: Query without tenant filter
    aql = """
        FOR v IN documents
            FOR neighbor IN 1..5 ANY v
                GRAPH 'rag_graph'
                RETURN neighbor
    """
    # This returns data from ALL tenants!
    return db.aql.execute(aql)
```

**Why**: SmartGraphs use a designated field to co-locate related data on the same shard. If not configured with tenant isolation in mind, queries can inadvertently access data from other tenants, or inefficient queries can cause cross-shard operations that degrade performance and leak information.

**Refs**: CWE-284, CWE-200, ArangoDB SmartGraph Documentation

---

## Rule 8: Backup Encryption and Restore Validation

**Level**: `strict`

**When**: Creating database backups, storing backup files, or restoring from backups

**Do**: Encrypt backups and validate integrity before restoration

```python
import subprocess
import hashlib
import json
from pathlib import Path
from cryptography.fernet import Fernet
import tempfile

class SecureArangoBackup:
    """Secure backup and restore operations for ArangoDB."""

    def __init__(self, arango_endpoint: str, encryption_key: bytes):
        self.endpoint = arango_endpoint
        self.cipher = Fernet(encryption_key)

    def create_encrypted_backup(self, output_path: str,
                                 database: str = None,
                                 collections: list = None) -> dict:
        """Create encrypted backup with integrity verification."""

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create arangodump backup
            cmd = [
                "arangodump",
                f"--server.endpoint={self.endpoint}",
                f"--output-directory={temp_dir}",
                "--compress-output=true",
                "--overwrite=true"
            ]

            if database:
                cmd.append(f"--server.database={database}")

            if collections:
                for coll in collections:
                    cmd.append(f"--collection={coll}")

            # Execute backup
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600
            )

            if result.returncode != 0:
                raise RuntimeError(f"Backup failed: {result.stderr}")

            # Calculate checksum of backup files
            checksums = {}
            backup_data = b""

            for file_path in Path(temp_dir).rglob("*"):
                if file_path.is_file():
                    file_data = file_path.read_bytes()
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    checksums[str(file_path.name)] = file_hash
                    backup_data += file_data

            # Encrypt the backup
            encrypted_data = self.cipher.encrypt(backup_data)

            # Create backup package with metadata
            backup_package = {
                "metadata": {
                    "database": database,
                    "collections": collections,
                    "checksums": checksums,
                    "total_hash": hashlib.sha256(backup_data).hexdigest()
                },
                "encrypted_data": encrypted_data.hex()
            }

            # Write encrypted backup
            output_file = Path(output_path)
            output_file.write_text(json.dumps(backup_package))

            return {
                "backup_file": str(output_file),
                "checksum": backup_package["metadata"]["total_hash"],
                "encrypted": True
            }

    def restore_with_validation(self, backup_path: str,
                                 target_database: str) -> dict:
        """Restore backup with integrity validation."""

        # Load backup package
        backup_file = Path(backup_path)
        if not backup_file.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        backup_package = json.loads(backup_file.read_text())
        metadata = backup_package["metadata"]

        # Decrypt backup data
        encrypted_data = bytes.fromhex(backup_package["encrypted_data"])
        decrypted_data = self.cipher.decrypt(encrypted_data)

        # Verify integrity
        actual_hash = hashlib.sha256(decrypted_data).hexdigest()
        if actual_hash != metadata["total_hash"]:
            raise ValueError(
                f"Backup integrity check failed. "
                f"Expected {metadata['total_hash']}, got {actual_hash}"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract decrypted backup (implementation depends on format)
            # ... extraction logic ...

            # Validate collection schemas before restore
            for collection in metadata.get("collections", []):
                self._validate_collection_schema(temp_dir, collection)

            # Execute restore
            cmd = [
                "arangorestore",
                f"--server.endpoint={self.endpoint}",
                f"--server.database={target_database}",
                f"--input-directory={temp_dir}",
                "--create-database=false",  # Don't auto-create
                "--overwrite=true"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600
            )

            if result.returncode != 0:
                raise RuntimeError(f"Restore failed: {result.stderr}")

        return {
            "restored_to": target_database,
            "collections": metadata.get("collections"),
            "verified": True
        }

    def _validate_collection_schema(self, backup_dir: str,
                                    collection: str):
        """Validate collection data before restore."""
        # Implement schema validation logic
        pass
```

**Don't**: Create or restore backups without encryption or validation

```python
def vulnerable_backup(endpoint, output_dir):
    """VULNERABLE: Unencrypted backup without validation."""
    # DANGEROUS: No encryption, credentials in command
    cmd = f"""
        arangodump \
            --server.endpoint={endpoint} \
            --server.password=secret123 \
            --output-directory={output_dir}
    """

    subprocess.run(cmd, shell=True)  # Shell injection risk

    # DANGEROUS: No checksum, no integrity verification
    return {"backup": output_dir}

def vulnerable_restore(endpoint, backup_dir, database):
    """VULNERABLE: Restore without validation."""
    # DANGEROUS: No integrity check before restore
    # DANGEROUS: Auto-create database without verification
    cmd = f"""
        arangorestore \
            --server.endpoint={endpoint} \
            --input-directory={backup_dir} \
            --server.database={database} \
            --create-database=true
    """

    subprocess.run(cmd, shell=True)
```

**Why**: Unencrypted backups expose sensitive data if storage is compromised. Without integrity validation, attackers could tamper with backups to inject malicious data or corrupt the database upon restoration. Automated restore without validation can introduce vulnerabilities or data corruption.

**Refs**: CWE-311, CWE-345, OWASP A02:2025

---

## Rule 9: Replication and Cluster Security

**Level**: `strict`

**When**: Configuring ArangoDB cluster deployments, setting up replication, or managing coordinators and DB servers

**Do**: Secure cluster communication and implement proper replication controls

```python
from arango import ArangoClient
import ssl

class SecureClusterManager:
    """Secure cluster configuration for ArangoDB."""

    def __init__(self, coordinators: list, jwt_secret: str):
        """Initialize with secure cluster connection."""

        # Create SSL context for cluster communication
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Connect to coordinators with TLS
        self.client = ArangoClient(
            hosts=coordinators,
            http_client_options={
                "ssl_context": ssl_context,
                "timeout": 30
            }
        )

        self.jwt_secret = jwt_secret

    def get_cluster_health(self, sys_db) -> dict:
        """Check cluster health and security status."""

        # Get cluster health information
        health = sys_db.cluster.health()

        security_report = {
            "healthy": True,
            "warnings": [],
            "servers": {}
        }

        for server_id, server_info in health.get("Health", {}).items():
            server_status = {
                "status": server_info.get("Status"),
                "role": server_info.get("Role"),
                "endpoint": server_info.get("Endpoint", "")
            }

            # Check for security issues
            endpoint = server_status["endpoint"]

            # Warning if not using TLS
            if endpoint.startswith("tcp://") or endpoint.startswith("http://"):
                security_report["warnings"].append(
                    f"Server {server_id} not using TLS: {endpoint}"
                )
                security_report["healthy"] = False

            security_report["servers"][server_id] = server_status

        return security_report

    def configure_write_concern(self, db, collection_name: str,
                                 replication_factor: int = 2,
                                 write_concern: int = 2) -> dict:
        """Configure collection with secure write concern."""

        # Ensure write concern doesn't exceed replication factor
        if write_concern > replication_factor:
            raise ValueError(
                f"Write concern ({write_concern}) cannot exceed "
                f"replication factor ({replication_factor})"
            )

        # Create or modify collection
        if db.has_collection(collection_name):
            collection = db.collection(collection_name)
            collection.configure(
                replication_factor=replication_factor,
                write_concern=write_concern
            )
        else:
            db.create_collection(
                collection_name,
                replication_factor=replication_factor,
                write_concern=write_concern
            )

        return {
            "collection": collection_name,
            "replication_factor": replication_factor,
            "write_concern": write_concern
        }

    def setup_datacenter_replication(self, source_db, target_endpoint: str,
                                      collections: list) -> dict:
        """Configure secure datacenter-to-datacenter replication."""

        # Verify target uses TLS
        if not target_endpoint.startswith("ssl://"):
            raise ValueError(
                "Target endpoint must use SSL/TLS for DC replication"
            )

        # Configure replication for specified collections
        replication_config = {
            "endpoint": target_endpoint,
            "database": source_db.name,
            "includeSystem": False,
            "incremental": True,
            "autoResync": True,
            "restrictCollections": collections
        }

        # Note: Actual DC2DC replication setup requires Enterprise Edition
        # and arangosync configuration

        return {
            "status": "configured",
            "target": target_endpoint,
            "collections": collections
        }

    def monitor_replication_lag(self, sys_db, threshold_seconds: int = 60):
        """Monitor replication lag and alert on issues."""

        # Get replication status
        replication = sys_db.replication.inventory()

        lag_report = {
            "status": "healthy",
            "collections": {},
            "alerts": []
        }

        for collection in replication.get("collections", []):
            coll_name = collection.get("name")

            # Check replication status
            # Implementation depends on cluster configuration

        return lag_report
```

**Don't**: Use insecure cluster configuration

```python
def vulnerable_cluster_setup():
    """VULNERABLE: Insecure cluster configuration."""
    # DANGEROUS: No TLS between cluster nodes
    client = ArangoClient(
        hosts=[
            "http://coordinator1:8529",  # No TLS!
            "http://coordinator2:8529"
        ]
    )

    # DANGEROUS: No write concern (data loss risk)
    db = client.db("production")
    db.create_collection(
        "critical_data",
        replication_factor=1,  # No redundancy!
        write_concern=0  # No durability guarantee!
    )

    # DANGEROUS: System collections replicated externally
    # This exposes user credentials and system configuration
```

**Why**: Insecure cluster communication allows eavesdropping and man-in-the-middle attacks between ArangoDB nodes. Inadequate write concern settings risk data loss during node failures. Improperly configured replication can expose sensitive data or allow unauthorized data modification across datacenters.

**Refs**: CWE-319, CWE-311, OWASP A02:2025, A05:2025

---

## Summary

These rules provide comprehensive security coverage for ArangoDB deployments in RAG systems:

| Rule | Security Control | Level |
|------|------------------|-------|
| 1 | AQL Injection Prevention | `strict` |
| 2 | Multi-Model Access Control | `strict` |
| 3 | Authentication & JWT | `strict` |
| 4 | Database/Collection RBAC | `strict` |
| 5 | Foxx Services Security | `strict` |
| 6 | Graph Traversal Limits | `strict` |
| 7 | SmartGraph Sharding | `warning` |
| 8 | Backup Encryption | `strict` |
| 9 | Cluster Security | `strict` |

Always apply these rules in conjunction with the core RAG security rules (`rules/_core/rag-security.md`) and graph database security rules (`rules/_core/graph-database-security.md`).

