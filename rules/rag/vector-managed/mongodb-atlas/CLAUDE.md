# MongoDB Atlas Vector Search Security Rules

Security rules for MongoDB Atlas Vector Search implementations with focus on aggregation pipeline security, ACID transactions, and multi-tenant document isolation.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Connection String Security | `strict` | Credential exposure, data interception |
| Vector Search Index Security | `strict` | Index manipulation, unauthorized field access |
| Aggregation Pipeline Injection | `strict` | NoSQL injection, data exfiltration |
| ACID Transaction Security | `warning` | Data inconsistency, race conditions |
| Collection-Level Access Control | `strict` | Unauthorized data access, privilege escalation |
| Query Filter Security | `strict` | Filter bypass, cross-tenant leakage |
| Existing Data Integration | `warning` | Migration vulnerabilities, schema violations |
| IP Access List | `strict` | Unrestricted network exposure |
| Encryption at Rest with CMK | `strict` | Data exposure in storage layer |
| Private Network Connectivity | `strict` | Public internet exposure of cluster |

---

## Rule: Connection String Security

**Level**: `strict`

**When**: Establishing connections to MongoDB Atlas for vector search operations

**Do**: Use SRV connection format, environment-based credentials, TLS enforcement, and connection pooling

```python
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.server_api import ServerApi

# Secure connection with SRV format and TLS
def get_secure_client():
    """Create secure MongoDB Atlas connection."""
    connection_string = os.environ["MONGODB_ATLAS_URI"]

    # Validate connection string format
    if not connection_string.startswith("mongodb+srv://"):
        raise ValueError("Must use SRV connection format for Atlas")

    client = MongoClient(
        connection_string,
        server_api=ServerApi('1'),
        # TLS configuration
        tls=True,
        tlsAllowInvalidCertificates=False,
        tlsAllowInvalidHostnames=False,
        # Connection pool settings
        maxPoolSize=50,
        minPoolSize=10,
        maxIdleTimeMS=30000,
        # Timeouts
        connectTimeoutMS=10000,
        serverSelectionTimeoutMS=10000,
        socketTimeoutMS=20000,
        # Retry configuration
        retryWrites=True,
        retryReads=True,
        # Write concern for durability
        w="majority",
        journal=True
    )

    # Verify connection
    client.admin.command('ping')

    return client

# Connection with X.509 certificate authentication
def get_x509_client():
    """Create connection using X.509 certificate authentication."""
    client = MongoClient(
        os.environ["MONGODB_ATLAS_URI"],
        tls=True,
        tlsCertificateKeyFile=os.environ["MONGODB_CERT_PATH"],
        tlsCAFile=os.environ["MONGODB_CA_PATH"],
        authMechanism="MONGODB-X509"
    )
    return client

# AWS IAM authentication for Atlas
def get_iam_client():
    """Create connection using AWS IAM authentication."""
    client = MongoClient(
        os.environ["MONGODB_ATLAS_URI"],
        authMechanism="MONGODB-AWS",
        authMechanismProperties={
            "AWS_SESSION_TOKEN": os.environ.get("AWS_SESSION_TOKEN")
        }
    )
    return client
```

**Don't**: Hardcode credentials, use non-SRV connections, or disable TLS verification

```python
# VULNERABLE: Hardcoded credentials in connection string
client = MongoClient(
    "mongodb+srv://admin:password123@cluster.mongodb.net/db"  # Exposed in code/logs
)

# VULNERABLE: Standard connection without TLS
client = MongoClient(
    "mongodb://user:pass@host:27017",  # Not SRV, missing TLS
    tls=False  # Plaintext traffic
)

# VULNERABLE: Disabled certificate validation
client = MongoClient(
    os.environ["MONGODB_URI"],
    tlsAllowInvalidCertificates=True,  # MITM attack possible
    tlsAllowInvalidHostnames=True
)

# VULNERABLE: No connection timeouts
client = MongoClient(os.environ["MONGODB_URI"])  # Can hang indefinitely
```

**Why**: Hardcoded credentials leak through version control and logs. Non-SRV connections miss automatic failover and may use unencrypted transport. Disabled certificate validation enables man-in-the-middle attacks. Missing timeouts can cause resource exhaustion.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-798, CWE-319, MongoDB Atlas Security Documentation

---

## Rule: Vector Search Index Security

**Level**: `strict`

**When**: Creating or managing vector search indexes in MongoDB Atlas

**Do**: Validate index definitions, restrict indexed fields, and use appropriate similarity metrics

```python
from pymongo import MongoClient
import json

# Secure vector search index creation
def create_secure_vector_index(
    collection,
    index_name: str,
    vector_field: str,
    dimensions: int,
    similarity: str = "cosine"
):
    """Create vector search index with validation."""

    # Validate parameters
    ALLOWED_SIMILARITIES = {"cosine", "euclidean", "dotProduct"}
    if similarity not in ALLOWED_SIMILARITIES:
        raise ValueError(f"Invalid similarity: {similarity}")

    if dimensions < 1 or dimensions > 4096:
        raise ValueError(f"Invalid dimensions: {dimensions}")

    # Validate field name (prevent injection)
    if not vector_field.replace("_", "").replace(".", "").isalnum():
        raise ValueError(f"Invalid field name: {vector_field}")

    # Define index with explicit field selection
    index_definition = {
        "name": index_name,
        "type": "vectorSearch",
        "definition": {
            "fields": [
                {
                    "type": "vector",
                    "path": vector_field,
                    "numDimensions": dimensions,
                    "similarity": similarity
                },
                # Only index necessary filter fields
                {
                    "type": "filter",
                    "path": "tenant_id"
                },
                {
                    "type": "filter",
                    "path": "metadata.category"
                },
                {
                    "type": "filter",
                    "path": "metadata.status"
                }
            ]
        }
    }

    # Create index using Atlas Search API
    collection.create_search_index(index_definition)

    return index_name

# Validate existing index configuration
def validate_index_security(collection, index_name: str) -> dict:
    """Validate vector search index security configuration."""
    indexes = list(collection.list_search_indexes())

    for index in indexes:
        if index.get("name") == index_name:
            definition = index.get("latestDefinition", {})
            fields = definition.get("fields", [])

            issues = []

            # Check for overly permissive filter fields
            filter_fields = [f for f in fields if f.get("type") == "filter"]
            if len(filter_fields) > 10:
                issues.append("Too many filter fields indexed")

            # Ensure tenant isolation field exists
            tenant_field = any(
                f.get("path") == "tenant_id" and f.get("type") == "filter"
                for f in fields
            )
            if not tenant_field:
                issues.append("Missing tenant_id filter field for isolation")

            return {
                "index_name": index_name,
                "secure": len(issues) == 0,
                "issues": issues
            }

    raise ValueError(f"Index not found: {index_name}")
```

**Don't**: Create indexes without validation or index sensitive fields unnecessarily

```python
# VULNERABLE: No validation of index parameters
def create_index(collection, user_config):
    # User controls entire index definition
    collection.create_search_index(user_config)  # Injection risk

# VULNERABLE: Indexing sensitive fields
index_definition = {
    "name": "vectors",
    "type": "vectorSearch",
    "definition": {
        "fields": [
            {"type": "vector", "path": "embedding", "numDimensions": 1536, "similarity": "cosine"},
            {"type": "filter", "path": "ssn"},  # PII indexed!
            {"type": "filter", "path": "credit_card"}  # Sensitive data!
        ]
    }
}

# VULNERABLE: No tenant isolation in index
index_definition = {
    "fields": [
        {"type": "vector", "path": "embedding", "numDimensions": 1536, "similarity": "cosine"}
        # Missing tenant_id filter - cannot enforce isolation efficiently
    ]
}
```

**Why**: Unvalidated index definitions can be manipulated to expose sensitive fields or create denial-of-service conditions. Indexing PII or sensitive data increases exposure risk. Missing tenant isolation fields prevent efficient query-time filtering.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, MongoDB Atlas Search Documentation

---

## Rule: Aggregation Pipeline Injection

**Level**: `strict`

**When**: Constructing $vectorSearch aggregation pipelines with user input

**Do**: Validate all inputs, use allowlists for filter fields, and parameterize query construction

```python
from pymongo import MongoClient
from bson import ObjectId
import re

# Allowed filter fields and operators
ALLOWED_FILTER_FIELDS = {"tenant_id", "category", "status", "created_at", "source"}
ALLOWED_OPERATORS = {"$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin"}

def build_secure_vector_search(
    tenant_id: str,
    query_vector: list,
    user_filters: dict = None,
    num_candidates: int = 100,
    limit: int = 10
) -> list:
    """Build secure $vectorSearch aggregation pipeline."""

    # Validate tenant_id format
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
        raise ValueError("Invalid tenant_id format")

    # Validate vector
    if not isinstance(query_vector, list) or len(query_vector) != 1536:
        raise ValueError("Invalid query vector")

    # Validate limits
    if num_candidates < 1 or num_candidates > 10000:
        raise ValueError("num_candidates must be 1-10000")
    if limit < 1 or limit > 100:
        raise ValueError("limit must be 1-100")

    # Build pre-filter with mandatory tenant isolation
    pre_filter = {"tenant_id": {"$eq": tenant_id}}

    # Add validated user filters
    if user_filters:
        validated_filters = validate_user_filters(user_filters)
        if validated_filters:
            pre_filter = {"$and": [pre_filter, validated_filters]}

    # Construct pipeline
    pipeline = [
        {
            "$vectorSearch": {
                "index": "vector_index",
                "path": "embedding",
                "queryVector": query_vector,
                "numCandidates": num_candidates,
                "limit": limit,
                "filter": pre_filter
            }
        },
        {
            "$project": {
                "_id": 1,
                "content": 1,
                "metadata": 1,
                "score": {"$meta": "vectorSearchScore"},
                # Explicitly exclude sensitive fields
                "embedding": 0
            }
        }
    ]

    return pipeline

def validate_user_filters(user_filters: dict) -> dict:
    """Validate and sanitize user-provided filters."""
    validated = {}

    for field, condition in user_filters.items():
        # Validate field name
        if field not in ALLOWED_FILTER_FIELDS:
            continue  # Skip disallowed fields

        # Validate condition
        if isinstance(condition, dict):
            safe_condition = {}
            for op, value in condition.items():
                if op not in ALLOWED_OPERATORS:
                    raise ValueError(f"Invalid operator: {op}")
                safe_condition[op] = sanitize_value(value)
            validated[field] = safe_condition
        else:
            validated[field] = {"$eq": sanitize_value(condition)}

    return validated

def sanitize_value(value):
    """Sanitize filter values to prevent injection."""
    if isinstance(value, str):
        if len(value) > 1000:
            raise ValueError("Value too long")
        # Prevent NoSQL injection operators in strings
        if value.startswith("$"):
            raise ValueError("Invalid value format")
        return value
    elif isinstance(value, (int, float, bool)):
        return value
    elif isinstance(value, list):
        return [sanitize_value(v) for v in value[:100]]
    elif isinstance(value, ObjectId):
        return value
    else:
        raise ValueError(f"Invalid value type: {type(value)}")

# Execute secure vector search
def execute_vector_search(
    collection,
    tenant_id: str,
    query_vector: list,
    user_filters: dict = None,
    limit: int = 10
):
    """Execute vector search with security controls."""
    pipeline = build_secure_vector_search(
        tenant_id=tenant_id,
        query_vector=query_vector,
        user_filters=user_filters,
        limit=limit
    )

    results = list(collection.aggregate(pipeline))

    # Post-query validation
    for doc in results:
        if doc.get("tenant_id") != tenant_id:
            raise SecurityError("Cross-tenant data leak detected")

    return results
```

**Don't**: Construct pipelines from raw user input or use string interpolation

```python
# VULNERABLE: Direct user input in pipeline
def search(collection, user_query):
    pipeline = user_query  # User controls entire pipeline!
    return list(collection.aggregate(pipeline))

# VULNERABLE: String interpolation in filter
def search(collection, category):
    pipeline = [
        {
            "$vectorSearch": {
                "filter": {"category": category}  # No validation
            }
        }
    ]
    return list(collection.aggregate(pipeline))

# VULNERABLE: No field validation
def search(collection, filters):
    pipeline = [
        {
            "$vectorSearch": {
                "filter": filters  # User can filter on any field
            }
        }
    ]
    return list(collection.aggregate(pipeline))

# VULNERABLE: Missing tenant isolation
def search(collection, query_vector, user_filter):
    pipeline = [
        {
            "$vectorSearch": {
                "queryVector": query_vector,
                "filter": user_filter  # No tenant_id enforcement
            }
        }
    ]
    return list(collection.aggregate(pipeline))
```

**Why**: MongoDB aggregation pipelines are powerful and can be exploited for data exfiltration, denial of service, or access control bypass. NoSQL injection through operators like $where or $function can execute arbitrary code. Unvalidated filters can bypass tenant isolation. In RAG systems, injected pipeline operators can be smuggled through document content and trigger unauthorized data retrieval.

**Refs**: OWASP A03:2025 (Injection), LLM01:2025 (Prompt Injection), LLM06:2025 (Excessive Agency), CWE-943, CWE-89, MongoDB Security Documentation

---

## Rule: ACID Transaction Security

**Level**: `warning`

**When**: Performing multi-document vector operations requiring consistency

**Do**: Use transactions with appropriate read/write concerns and timeout handling

```python
from pymongo import MongoClient, WriteConcern, ReadConcern
from pymongo.read_preferences import ReadPreference
from datetime import datetime
import hashlib

def index_document_with_transaction(
    client,
    db_name: str,
    tenant_id: str,
    doc_id: str,
    content: str,
    embedding: list,
    metadata: dict
):
    """Index document with ACID transaction for consistency."""

    # Configure session with appropriate concerns
    with client.start_session() as session:
        # Set transaction options
        with session.start_transaction(
            read_concern=ReadConcern("snapshot"),
            write_concern=WriteConcern(w="majority", j=True),
            read_preference=ReadPreference.PRIMARY,
            max_commit_time_ms=30000  # 30 second timeout
        ):
            try:
                db = client[db_name]
                vectors_collection = db.vectors
                audit_collection = db.audit_log

                # Create vector document
                vector_doc = {
                    "_id": doc_id,
                    "tenant_id": tenant_id,
                    "content": content,
                    "embedding": embedding,
                    "metadata": metadata,
                    "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                    "created_at": datetime.utcnow(),
                    "version": 1
                }

                # Insert with duplicate check
                existing = vectors_collection.find_one(
                    {"_id": doc_id, "tenant_id": tenant_id},
                    session=session
                )

                if existing:
                    # Update existing document
                    result = vectors_collection.update_one(
                        {"_id": doc_id, "tenant_id": tenant_id},
                        {
                            "$set": {
                                "content": content,
                                "embedding": embedding,
                                "metadata": metadata,
                                "content_hash": vector_doc["content_hash"],
                                "updated_at": datetime.utcnow()
                            },
                            "$inc": {"version": 1}
                        },
                        session=session
                    )
                else:
                    # Insert new document
                    result = vectors_collection.insert_one(
                        vector_doc,
                        session=session
                    )

                # Create audit log entry
                audit_entry = {
                    "action": "index_document",
                    "tenant_id": tenant_id,
                    "doc_id": doc_id,
                    "timestamp": datetime.utcnow(),
                    "content_hash": vector_doc["content_hash"]
                }
                audit_collection.insert_one(audit_entry, session=session)

                # Transaction commits automatically on context exit
                return {"status": "success", "doc_id": doc_id}

            except Exception as e:
                # Transaction aborts automatically on exception
                raise

def bulk_delete_with_transaction(
    client,
    db_name: str,
    tenant_id: str,
    doc_ids: list,
    user_id: str
):
    """Delete multiple documents transactionally."""

    if len(doc_ids) > 1000:
        raise ValueError("Bulk delete limited to 1000 documents")

    with client.start_session() as session:
        with session.start_transaction(
            write_concern=WriteConcern(w="majority", j=True),
            max_commit_time_ms=60000
        ):
            db = client[db_name]

            # Delete vectors (tenant-scoped)
            result = db.vectors.delete_many(
                {
                    "_id": {"$in": doc_ids},
                    "tenant_id": tenant_id  # Enforce tenant isolation
                },
                session=session
            )

            # Audit the deletion
            db.audit_log.insert_one(
                {
                    "action": "bulk_delete",
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "doc_ids": doc_ids,
                    "deleted_count": result.deleted_count,
                    "timestamp": datetime.utcnow()
                },
                session=session
            )

            return result.deleted_count
```

**Don't**: Perform multi-step operations without transactions or ignore consistency requirements

```python
# VULNERABLE: No transaction for related operations
def index_document(db, doc_id, content, embedding):
    # These operations are not atomic
    db.vectors.insert_one({"_id": doc_id, "embedding": embedding})
    db.audit.insert_one({"action": "insert", "doc_id": doc_id})
    # If second insert fails, audit is missing

# VULNERABLE: No write concern
def update_vector(collection, doc_id, embedding):
    collection.update_one(
        {"_id": doc_id},
        {"$set": {"embedding": embedding}}
        # No write concern - may not persist on failure
    )

# VULNERABLE: No timeout on transaction
with client.start_session() as session:
    with session.start_transaction():  # No max_commit_time_ms
        # Can hold locks indefinitely
        pass

# VULNERABLE: Reading during write without snapshot
with session.start_transaction(
    read_concern=ReadConcern("local")  # May see uncommitted data
):
    pass
```

**Why**: Without transactions, multi-document operations can leave data in inconsistent states. Missing write concerns can result in data loss during failures. Unbounded transactions can cause lock contention and performance issues.

**Refs**: OWASP A04:2025 (Insecure Design), CWE-362, CWE-367, MongoDB Transaction Documentation

---

## Rule: Collection-Level Access Control

**Level**: `strict`

**When**: Managing access to vector collections in multi-tenant environments

**Do**: Implement RBAC with least privilege, use field-level encryption for sensitive data

```python
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, Algorithm
from pymongo.encryption_options import AutoEncryptionOpts
from bson.codec_options import CodecOptions
from bson.binary import STANDARD, UUID
import os

# Configure field-level encryption (CSFLE — client-side, distinct from Atlas at-rest CMK)
def get_encrypted_client():
    """Create client with client-side field-level encryption (CSFLE).

    CSFLE encrypts specific fields before they reach the server.
    This is complementary to, not a substitute for, Atlas encryption
    at rest with Customer Managed Keys (CMK). Enable both controls:
    CSFLE for field-granular protection, CMK for the storage layer.
    """

    # Key vault configuration
    key_vault_namespace = "encryption.__keyVault"

    # KMS provider configuration (AWS KMS example)
    kms_providers = {
        "aws": {
            "accessKeyId": os.environ["AWS_ACCESS_KEY_ID"],
            "secretAccessKey": os.environ["AWS_SECRET_ACCESS_KEY"]
        }
    }

    # Schema map for automatic encryption
    schema_map = {
        "vectordb.vectors": {
            "bsonType": "object",
            "encryptMetadata": {
                "keyId": [UUID(os.environ["ENCRYPTION_KEY_ID"])]
            },
            "properties": {
                "content": {
                    "encrypt": {
                        "bsonType": "string",
                        "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic
                    }
                },
                "metadata": {
                    "bsonType": "object",
                    "properties": {
                        "pii_data": {
                            "encrypt": {
                                "bsonType": "string",
                                "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random
                            }
                        }
                    }
                }
            }
        }
    }

    # Auto encryption options
    auto_encryption_opts = AutoEncryptionOpts(
        kms_providers=kms_providers,
        key_vault_namespace=key_vault_namespace,
        schema_map=schema_map
    )

    client = MongoClient(
        os.environ["MONGODB_ATLAS_URI"],
        auto_encryption_opts=auto_encryption_opts
    )

    return client

# Role-based access control setup
def setup_rbac_roles(admin_client, db_name: str):
    """Create RBAC roles for vector store access."""

    db = admin_client[db_name]

    # Read-only role for query services
    db.command({
        "createRole": "vectorQueryRole",
        "privileges": [
            {
                "resource": {"db": db_name, "collection": "vectors"},
                "actions": ["find", "aggregate"]
            }
        ],
        "roles": []
    })

    # Write role for indexing services
    db.command({
        "createRole": "vectorIndexRole",
        "privileges": [
            {
                "resource": {"db": db_name, "collection": "vectors"},
                "actions": ["find", "aggregate", "insert", "update"]
            },
            {
                "resource": {"db": db_name, "collection": "audit_log"},
                "actions": ["insert"]
            }
        ],
        "roles": []
    })

    # Admin role for index management
    db.command({
        "createRole": "vectorAdminRole",
        "privileges": [
            {
                "resource": {"db": db_name, "collection": "vectors"},
                "actions": ["find", "aggregate", "insert", "update", "remove", "createIndex", "dropIndex"]
            }
        ],
        "roles": []
    })

# Create users with specific roles
def create_service_users(admin_client, db_name: str):
    """Create service users with appropriate roles."""

    admin_db = admin_client.admin

    # Query service user
    admin_db.command({
        "createUser": "query_service",
        "pwd": os.environ["QUERY_SERVICE_PASSWORD"],
        "roles": [
            {"role": "vectorQueryRole", "db": db_name}
        ]
    })

    # Indexing service user
    admin_db.command({
        "createUser": "indexing_service",
        "pwd": os.environ["INDEXING_SERVICE_PASSWORD"],
        "roles": [
            {"role": "vectorIndexRole", "db": db_name}
        ]
    })

# Multi-tenant document structure with access control
def create_tenant_document(
    tenant_id: str,
    doc_id: str,
    content: str,
    embedding: list,
    owner_id: str,
    access_list: list = None
) -> dict:
    """Create document with tenant isolation and access control."""

    return {
        "_id": doc_id,
        # Tenant isolation
        "tenant_id": tenant_id,
        # Access control
        "owner_id": owner_id,
        "access_list": access_list or [owner_id],
        # Content
        "content": content,
        "embedding": embedding,
        # Audit fields
        "created_at": datetime.utcnow(),
        "created_by": owner_id,
        # Classification
        "data_classification": "internal",
        "metadata": {}
    }
```

**Don't**: Use shared credentials or grant excessive permissions

```python
# VULNERABLE: All services use admin credentials
client = MongoClient(
    f"mongodb+srv://admin:{os.environ['ADMIN_PASSWORD']}@cluster.mongodb.net"
)

# VULNERABLE: Overly permissive role
db.command({
    "createRole": "vectorRole",
    "privileges": [
        {
            "resource": {"db": "", "collection": ""},  # All databases!
            "actions": ["*"]  # All actions!
        }
    ]
})

# VULNERABLE: Sensitive data without encryption
doc = {
    "content": "Patient SSN: 123-45-6789",  # PII in plaintext
    "embedding": embedding
}

# VULNERABLE: No tenant isolation in document
doc = {
    "_id": doc_id,
    "embedding": embedding
    # Missing tenant_id - no isolation possible
}
```

**Why**: Without RBAC, compromised services can perform unauthorized operations. Shared credentials prevent auditing and granular revocation. Unencrypted sensitive data is exposed in backups, logs, and to database administrators. In LLM pipelines, over-privileged database credentials widen the blast radius of a prompt injection that achieves tool execution.

**Refs**: OWASP A01:2025 (Broken Access Control), LLM02:2025 (Insecure Output Handling), CWE-284, CWE-732, MongoDB Security Documentation

---

## Rule: Query Filter Security

**Level**: `strict`

**When**: Applying pre-filters and post-filters to vector search queries

**Do**: Enforce tenant isolation at filter level with defense in depth

```python
from pymongo import MongoClient
from datetime import datetime
import re

class SecureVectorSearch:
    """Secure vector search with mandatory tenant isolation."""

    ALLOWED_FILTER_FIELDS = {
        "category", "status", "source", "created_at",
        "metadata.type", "metadata.tags"
    }

    def __init__(self, collection, audit_logger):
        self.collection = collection
        self.audit = audit_logger

    def search(
        self,
        tenant_id: str,
        user_id: str,
        query_vector: list,
        pre_filter: dict = None,
        post_filter: dict = None,
        limit: int = 10
    ):
        """Execute vector search with security controls."""

        # Validate tenant access
        if not self._validate_tenant_access(user_id, tenant_id):
            self.audit.warning(
                "unauthorized_access",
                user_id=user_id,
                tenant_id=tenant_id
            )
            raise PermissionError("User not authorized for tenant")

        # Build secure pipeline
        pipeline = self._build_secure_pipeline(
            tenant_id=tenant_id,
            query_vector=query_vector,
            pre_filter=pre_filter,
            post_filter=post_filter,
            limit=limit
        )

        # Execute query
        results = list(self.collection.aggregate(pipeline))

        # Post-query validation
        validated_results = self._validate_results(results, tenant_id)

        # Audit successful query
        self.audit.info(
            "vector_search",
            tenant_id=tenant_id,
            user_id=user_id,
            result_count=len(validated_results),
            timestamp=datetime.utcnow().isoformat()
        )

        return validated_results

    def _build_secure_pipeline(
        self,
        tenant_id: str,
        query_vector: list,
        pre_filter: dict,
        post_filter: dict,
        limit: int
    ) -> list:
        """Build aggregation pipeline with mandatory tenant filter."""

        # Mandatory tenant isolation in pre-filter
        secure_pre_filter = {"tenant_id": {"$eq": tenant_id}}

        # Merge with validated user pre-filter
        if pre_filter:
            validated_pre = self._validate_filter(pre_filter)
            # Remove any tenant_id override attempts
            validated_pre.pop("tenant_id", None)
            if validated_pre:
                secure_pre_filter = {
                    "$and": [secure_pre_filter, validated_pre]
                }

        pipeline = [
            {
                "$vectorSearch": {
                    "index": "vector_index",
                    "path": "embedding",
                    "queryVector": query_vector,
                    "numCandidates": min(limit * 10, 1000),
                    "limit": limit,
                    "filter": secure_pre_filter
                }
            },
            {
                "$addFields": {
                    "score": {"$meta": "vectorSearchScore"}
                }
            }
        ]

        # Add validated post-filter
        if post_filter:
            validated_post = self._validate_filter(post_filter)
            validated_post.pop("tenant_id", None)
            if validated_post:
                # Re-enforce tenant isolation in post-filter
                pipeline.append({
                    "$match": {
                        "$and": [
                            {"tenant_id": tenant_id},
                            validated_post
                        ]
                    }
                })

        # Final projection (exclude sensitive fields)
        pipeline.append({
            "$project": {
                "embedding": 0,  # Don't return vectors
                "internal_notes": 0  # Exclude internal fields
            }
        })

        return pipeline

    def _validate_filter(self, user_filter: dict) -> dict:
        """Validate user-provided filter against allowlist."""
        validated = {}

        for field, condition in user_filter.items():
            # Skip disallowed fields
            if field not in self.ALLOWED_FILTER_FIELDS:
                continue

            # Validate and sanitize condition
            if isinstance(condition, dict):
                safe_condition = {}
                for op, value in condition.items():
                    if op.startswith("$"):
                        if op in {"$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin"}:
                            safe_condition[op] = self._sanitize_value(value)
                validated[field] = safe_condition
            else:
                validated[field] = {"$eq": self._sanitize_value(condition)}

        return validated

    def _sanitize_value(self, value):
        """Sanitize filter value."""
        if isinstance(value, str):
            if len(value) > 1000 or value.startswith("$"):
                raise ValueError("Invalid filter value")
            return value
        elif isinstance(value, (int, float, bool)):
            return value
        elif isinstance(value, list):
            return [self._sanitize_value(v) for v in value[:100]]
        else:
            raise ValueError(f"Invalid value type: {type(value)}")

    def _validate_results(self, results: list, expected_tenant: str) -> list:
        """Validate all results belong to expected tenant."""
        validated = []

        for doc in results:
            doc_tenant = doc.get("tenant_id")
            if doc_tenant != expected_tenant:
                self.audit.error(
                    "cross_tenant_leak",
                    expected=expected_tenant,
                    actual=doc_tenant,
                    doc_id=str(doc.get("_id"))
                )
                continue
            validated.append(doc)

        return validated

    def _validate_tenant_access(self, user_id: str, tenant_id: str) -> bool:
        """Check if user has access to tenant."""
        # Implement based on your auth system
        return auth_service.check_tenant_access(user_id, tenant_id)
```

**Don't**: Trust user-provided filters without validation or skip result verification

```python
# VULNERABLE: No tenant filter
def search(collection, query_vector, user_filter):
    pipeline = [
        {
            "$vectorSearch": {
                "queryVector": query_vector,
                "filter": user_filter  # No tenant enforcement
            }
        }
    ]
    return list(collection.aggregate(pipeline))

# VULNERABLE: Tenant filter can be overridden
def search(collection, tenant_id, user_filter):
    # User can override tenant_id in their filter
    combined = {"tenant_id": tenant_id, **user_filter}
    # If user_filter contains tenant_id, it overrides!

# VULNERABLE: No result validation
def search(collection, tenant_id, query_vector):
    results = list(collection.aggregate(pipeline))
    return results  # No verification results belong to tenant

# VULNERABLE: No field allowlist
def search(collection, user_filter):
    # User can filter on any field including sensitive ones
    pipeline = [{"$match": user_filter}]
```

**Why**: Without mandatory tenant filters, queries can access other tenants' data. User-controlled filters can bypass security controls through operator injection. Result validation provides defense in depth against filter bugs or misconfigurations. Returning raw embedding vectors leaks model internals and enables reconstruction attacks.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A03:2025 (Injection), LLM02:2025 (Insecure Output Handling), CWE-863, CWE-943

---

## Rule: Existing Data Integration

**Level**: `warning`

**When**: Migrating existing MongoDB data to vector search or integrating with existing collections

**Do**: Validate schema compatibility, enforce data classification, and maintain audit trails

```python
from pymongo import MongoClient
from datetime import datetime
import hashlib

class SecureDataMigration:
    """Secure migration of existing data to vector search."""

    REQUIRED_FIELDS = {"tenant_id", "owner_id", "created_at"}

    def __init__(self, source_collection, target_collection, embedding_service, audit_logger):
        self.source = source_collection
        self.target = target_collection
        self.embedder = embedding_service
        self.audit = audit_logger

    def migrate_collection(
        self,
        tenant_id: str,
        query: dict = None,
        batch_size: int = 100,
        dry_run: bool = True
    ):
        """Migrate documents with security validation."""

        # Enforce tenant scope in query
        migration_query = {"tenant_id": tenant_id}
        if query:
            migration_query = {"$and": [migration_query, query]}

        cursor = self.source.find(migration_query).batch_size(batch_size)

        migrated = 0
        skipped = 0
        errors = []

        for doc in cursor:
            try:
                # Validate document schema
                validation_result = self._validate_document(doc, tenant_id)
                if not validation_result["valid"]:
                    skipped += 1
                    errors.append({
                        "doc_id": str(doc.get("_id")),
                        "reason": validation_result["reason"]
                    })
                    continue

                # Check for sensitive data
                classification = self._classify_data(doc)

                # Generate embedding
                content = self._extract_content(doc)
                embedding = self.embedder.embed(content)

                # Create vector document
                vector_doc = {
                    "_id": doc["_id"],
                    "tenant_id": tenant_id,
                    "owner_id": doc.get("owner_id", "system"),
                    "content": content,
                    "embedding": embedding,
                    "metadata": {
                        "source_collection": self.source.name,
                        "migrated_at": datetime.utcnow(),
                        "original_created_at": doc.get("created_at"),
                        "data_classification": classification
                    },
                    "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                    "created_at": doc.get("created_at", datetime.utcnow())
                }

                if not dry_run:
                    self.target.update_one(
                        {"_id": doc["_id"], "tenant_id": tenant_id},
                        {"$set": vector_doc},
                        upsert=True
                    )

                migrated += 1

            except Exception as e:
                errors.append({
                    "doc_id": str(doc.get("_id")),
                    "reason": str(e)
                })

        # Audit migration
        self.audit.info(
            "data_migration",
            tenant_id=tenant_id,
            migrated=migrated,
            skipped=skipped,
            errors=len(errors),
            dry_run=dry_run,
            timestamp=datetime.utcnow().isoformat()
        )

        return {
            "migrated": migrated,
            "skipped": skipped,
            "errors": errors,
            "dry_run": dry_run
        }

    def _validate_document(self, doc: dict, expected_tenant: str) -> dict:
        """Validate document meets security requirements."""

        # Check tenant isolation
        if doc.get("tenant_id") != expected_tenant:
            return {"valid": False, "reason": "tenant_id mismatch"}

        # Check required fields
        missing = self.REQUIRED_FIELDS - set(doc.keys())
        if missing:
            return {"valid": False, "reason": f"missing fields: {missing}"}

        # Validate owner_id format
        owner_id = doc.get("owner_id")
        if not owner_id or not isinstance(owner_id, str):
            return {"valid": False, "reason": "invalid owner_id"}

        return {"valid": True, "reason": None}

    def _classify_data(self, doc: dict) -> str:
        """Classify document data sensitivity."""
        content = str(doc)

        # Check for PII patterns
        pii_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{16}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email
        ]

        import re
        for pattern in pii_patterns:
            if re.search(pattern, content):
                return "pii"

        return doc.get("data_classification", "internal")

    def _extract_content(self, doc: dict) -> str:
        """Extract text content for embedding."""
        # Customize based on your schema
        if "content" in doc:
            return doc["content"]
        elif "text" in doc:
            return doc["text"]
        elif "body" in doc:
            return doc["body"]
        else:
            # Fallback to relevant string fields
            text_parts = []
            for key in ["title", "description", "summary"]:
                if key in doc and isinstance(doc[key], str):
                    text_parts.append(doc[key])
            return " ".join(text_parts)

# Schema validation for vector documents
def create_vector_schema_validation(db, collection_name: str):
    """Create schema validation for vector documents."""

    validator = {
        "$jsonSchema": {
            "bsonType": "object",
            "required": ["tenant_id", "owner_id", "embedding", "created_at"],
            "properties": {
                "tenant_id": {
                    "bsonType": "string",
                    "description": "Tenant identifier for isolation"
                },
                "owner_id": {
                    "bsonType": "string",
                    "description": "Document owner identifier"
                },
                "embedding": {
                    "bsonType": "array",
                    "items": {"bsonType": "double"},
                    "description": "Vector embedding"
                },
                "content": {
                    "bsonType": "string",
                    "maxLength": 100000
                },
                "created_at": {
                    "bsonType": "date"
                },
                "data_classification": {
                    "enum": ["public", "internal", "confidential", "pii"],
                    "description": "Data sensitivity classification"
                }
            }
        }
    }

    db.command({
        "collMod": collection_name,
        "validator": validator,
        "validationLevel": "strict",
        "validationAction": "error"
    })
```

**Don't**: Migrate data without validation or ignore schema requirements

```python
# VULNERABLE: No validation during migration
def migrate_all(source, target):
    for doc in source.find():
        embedding = embed(doc["content"])
        target.insert_one({
            "embedding": embedding,
            **doc  # No validation, missing tenant isolation
        })

# VULNERABLE: No tenant scoping in migration
def migrate(source, target, query):
    # Query not scoped to tenant
    for doc in source.find(query):
        target.insert_one(transform(doc))

# VULNERABLE: No schema validation
# Documents can be inserted without required fields
target.insert_one({
    "embedding": embedding
    # Missing tenant_id, owner_id, created_at
})

# VULNERABLE: No audit trail
def migrate(source, target):
    for doc in source.find():
        target.insert_one(transform(doc))
    # No record of what was migrated
```

**Why**: Unvalidated migrations can introduce documents without proper tenant isolation or access controls. Missing schema validation allows malformed documents that break security assumptions. Without audit trails, data provenance is lost.

**Refs**: OWASP A04:2025 (Insecure Design), CWE-20, CWE-778, MongoDB Schema Validation Documentation

---

## Rule: IP Access List

**Level**: `strict`

**When**: Configuring network access for any Atlas cluster used in a vector search deployment

**Do**: Restrict the Atlas IP access list to specific VPC CIDRs or application server IPs; never allow 0.0.0.0/0

```python
# Atlas IP access list is configured via the Atlas Administration API or Terraform,
# not the pymongo driver. The examples below show the Atlas Admin API calls and
# the equivalent Terraform resource.

import os
import requests

ATLAS_API_BASE = "https://cloud.mongodb.com/api/atlas/v2"

def configure_ip_access_list(project_id: str, vpc_cidr: str, comment: str):
    """Add a specific CIDR to the Atlas IP access list.

    vpc_cidr must be a narrowly scoped block such as 10.0.1.0/24,
    never 0.0.0.0/0 or ::/0.
    """
    import ipaddress

    # Reject any CIDR that covers the entire address space
    network = ipaddress.ip_network(vpc_cidr, strict=False)
    if network.prefixlen < 8:
        raise ValueError(
            f"CIDR {vpc_cidr} is too broad. Use a specific VPC subnet CIDR."
        )

    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    payload = [
        {
            "cidrBlock": vpc_cidr,
            "comment": comment  # e.g. "app-server-subnet-us-east-1a"
        }
    ]

    response = requests.post(
        f"{ATLAS_API_BASE}/groups/{project_id}/accessList",
        json=payload,
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    return response.json()

def audit_ip_access_list(project_id: str) -> list:
    """Return any access list entries that are overly permissive."""
    import ipaddress

    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    response = requests.get(
        f"{ATLAS_API_BASE}/groups/{project_id}/accessList",
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()

    findings = []
    for entry in response.json().get("results", []):
        cidr = entry.get("cidrBlock", "")
        if cidr in ("0.0.0.0/0", "::/0"):
            findings.append({
                "cidr": cidr,
                "comment": entry.get("comment", ""),
                "severity": "critical",
                "finding": "Unrestricted access — exposes cluster to the public internet"
            })
        elif cidr:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen < 8:
                findings.append({
                    "cidr": cidr,
                    "comment": entry.get("comment", ""),
                    "severity": "high",
                    "finding": "Overly broad CIDR — restrict to VPC subnet"
                })
    return findings
```

Terraform equivalent:

```hcl
# Correct: restrict to the application VPC subnet
resource "mongodbatlas_project_ip_access_list" "app_subnet" {
  project_id = var.atlas_project_id
  cidr_block = "10.0.1.0/24"   # Application server subnet only
  comment    = "app-server-subnet-us-east-1a"
}

# WRONG — never use this
# resource "mongodbatlas_project_ip_access_list" "open" {
#   project_id = var.atlas_project_id
#   cidr_block = "0.0.0.0/0"   # Exposes cluster to the entire internet
# }
```

**Don't**: Open the cluster to 0.0.0.0/0 or any CIDR broader than the application subnets

```python
# VULNERABLE: Blanket allow-all during development, forgotten in production
payload = [{"cidrBlock": "0.0.0.0/0", "comment": "temp - remove before prod"}]
# "temp" entries routinely survive to production

# VULNERABLE: Overly broad class-A block
payload = [{"cidrBlock": "10.0.0.0/8", "comment": "internal network"}]
# Grants access to every host on a /8; a single compromised internal machine
# reaches the cluster.
```

**Why**: Atlas clusters without a restrictive IP access list are reachable from the public internet. A valid credential pair (leaked via env var, log file, or supply-chain compromise) is then sufficient to extract all vector data. Restricting to the application VPC CIDR means network access is a second independent factor that an attacker must also compromise.

**Refs**: OWASP A05:2025 (Security Misconfiguration), CWE-668, MongoDB Atlas Network Access Documentation

---

## Rule: Encryption at Rest with CMK

**Level**: `strict`

**When**: Deploying any Atlas cluster that stores vector data, embeddings, or associated documents

**Do**: Enable Atlas encryption at rest using a Customer Managed Key (CMK) via AWS KMS, Azure Key Vault, or GCP KMS. This is a cluster-level control distinct from client-side field-level encryption (CSFLE).

```python
# Atlas encryption at rest with CMK is configured through the Atlas Administration API
# or Terraform. It is not a driver-level setting — enable it for the entire cluster.

import os
import requests

ATLAS_API_BASE = "https://cloud.mongodb.com/api/atlas/v2"

def enable_aws_kms_encryption(project_id: str, aws_key_arn: str, aws_role_arn: str):
    """Enable Atlas encryption at rest using an AWS KMS Customer Managed Key.

    Prerequisites in Atlas UI / API:
    - Create an Atlas-to-AWS IAM role with kms:Encrypt, kms:Decrypt, kms:DescribeKey.
    - The CMK must be in the same region as the Atlas cluster.
    """
    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    payload = {
        "awsKms": {
            "enabled": True,
            "customerMasterKeyID": aws_key_arn,
            "roleId": aws_role_arn,
            "region": os.environ["AWS_REGION"]
        }
    }

    response = requests.patch(
        f"{ATLAS_API_BASE}/groups/{project_id}/encryptionAtRest",
        json=payload,
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    return response.json()

def verify_encryption_at_rest(project_id: str) -> dict:
    """Verify that encryption at rest with CMK is active on the project."""
    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    response = requests.get(
        f"{ATLAS_API_BASE}/groups/{project_id}/encryptionAtRest",
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    config = response.json()

    aws_enabled = config.get("awsKms", {}).get("enabled", False)
    azure_enabled = config.get("azureKeyVault", {}).get("enabled", False)
    gcp_enabled = config.get("googleCloudKms", {}).get("enabled", False)

    if not any([aws_enabled, azure_enabled, gcp_enabled]):
        raise RuntimeError(
            "Encryption at rest with CMK is NOT enabled. "
            "Atlas default encryption uses MongoDB-managed keys, "
            "which do not satisfy CMK requirements."
        )

    return config
```

Terraform equivalent:

```hcl
# AWS KMS — enable CMK encryption at rest on the Atlas project
resource "mongodbatlas_encryption_at_rest" "cmk" {
  project_id = var.atlas_project_id

  aws_kms_config {
    enabled                = true
    customer_master_key_id = var.aws_kms_key_arn
    region                 = var.aws_region
    role_id                = mongodbatlas_cloud_provider_access_authorization.role.role_id
  }
}

# Each cluster must also have encryptionAtRestProvider set
resource "mongodbatlas_cluster" "vector_store" {
  project_id                  = var.atlas_project_id
  name                        = "vector-store-prod"
  encryption_at_rest_provider = "AWS"   # Must match the KMS config above
  # ... other cluster settings
}
```

**Don't**: Rely on Atlas default encryption (MongoDB-managed keys) or assume CSFLE alone satisfies at-rest CMK requirements

```python
# WRONG: Atlas default encryption uses MongoDB-managed keys.
# Data at rest is encrypted, but you do not control key rotation,
# revocation, or access auditing.
# No code change is required to make this mistake — it is the default.

# WRONG: CSFLE encrypts specific document fields before they reach the server.
# It does NOT encrypt:
#   - Index structures
#   - Oplog entries
#   - Journal files
#   - Backup snapshots (unless CMK is also enabled)
# CSFLE and CMK at-rest encryption are complementary; neither replaces the other.
auto_encryption_opts = AutoEncryptionOpts(...)   # CSFLE only — not a CMK substitute
```

**Why**: Atlas default encryption uses keys managed by MongoDB. If MongoDB's key management is compromised, or if a regulatory requirement mandates customer key control, the default is insufficient. CMK encryption lets you revoke Atlas's ability to decrypt your data by disabling the KMS key, gives you an independent audit trail of decryption events, and satisfies compliance frameworks (PCI DSS, HIPAA, SOC 2 Type II) that require customer-controlled key material. Embeddings stored in Atlas are model derivatives of your source data; they carry equivalent sensitivity.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, NIST SP 800-57, MongoDB Atlas Encryption at Rest Documentation

---

## Rule: Private Network Connectivity

**Level**: `strict`

**When**: Deploying production Atlas clusters for vector search workloads

**Do**: Connect application workloads to Atlas exclusively via Private Endpoints (AWS PrivateLink, GCP Private Service Connect, Azure Private Link) or VPC/VNet peering. Disable public cluster endpoint access after private connectivity is verified.

```python
# Private endpoint setup is performed via the Atlas Administration API or Terraform.
# The driver connection string changes to the private endpoint hostname once
# private connectivity is established.

import os
import requests

ATLAS_API_BASE = "https://cloud.mongodb.com/api/atlas/v2"

def create_aws_private_endpoint(project_id: str, region: str) -> dict:
    """Initiate an AWS PrivateLink private endpoint for an Atlas project."""
    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    # Step 1: Create the endpoint service on the Atlas side
    response = requests.post(
        f"{ATLAS_API_BASE}/groups/{project_id}/privateEndpoint/AWS/endpointService",
        json={"region": region},
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    service = response.json()

    # service["endpointServiceName"] is the VPC endpoint service name.
    # Use it to create a VPC Interface Endpoint in your AWS account via boto3 or Terraform.
    # After the VPC endpoint is accepted, call the Atlas API to register the endpoint ID.
    return {
        "atlas_service_name": service.get("endpointServiceName"),
        "status": service.get("status"),
        "note": "Create a VPC Interface Endpoint using the service name, then register its ID with Atlas."
    }

def register_aws_private_endpoint(
    project_id: str,
    endpoint_service_id: str,
    vpc_endpoint_id: str
) -> dict:
    """Register an accepted VPC Interface Endpoint with Atlas."""
    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    response = requests.post(
        f"{ATLAS_API_BASE}/groups/{project_id}/privateEndpoint/AWS/endpointService/{endpoint_service_id}/endpoint",
        json={"id": vpc_endpoint_id},
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    return response.json()

def get_private_endpoint_connection_string(project_id: str, cluster_name: str) -> str:
    """Retrieve the private-endpoint-aware SRV connection string for a cluster."""
    public_key = os.environ["ATLAS_PUBLIC_KEY"]
    private_key = os.environ["ATLAS_PRIVATE_KEY"]

    response = requests.get(
        f"{ATLAS_API_BASE}/groups/{project_id}/clusters/{cluster_name}",
        auth=(public_key, private_key),
        headers={"Accept": "application/vnd.atlas.2023-01-01+json"}
    )
    response.raise_for_status()
    cluster = response.json()

    # connectionStrings.privateEndpoint contains per-endpoint SRV strings
    pe_strings = cluster.get("connectionStrings", {}).get("privateEndpoint", [])
    if not pe_strings:
        raise RuntimeError(
            "No private endpoint connection strings found. "
            "Ensure private endpoints are active before routing production traffic."
        )

    # Return the SRV string for the first active endpoint
    return pe_strings[0].get("srvConnectionString")
```

Terraform equivalent:

```hcl
# AWS PrivateLink private endpoint for Atlas
resource "mongodbatlas_privatelink_endpoint" "pe" {
  project_id    = var.atlas_project_id
  provider_name = "AWS"
  region        = var.aws_region
}

# AWS VPC Interface Endpoint pointing at the Atlas service
resource "aws_vpc_endpoint" "atlas" {
  vpc_id              = var.vpc_id
  service_name        = mongodbatlas_privatelink_endpoint.pe.endpoint_service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.atlas_pe.id]
  private_dns_enabled = true
}

# Register the VPC endpoint with Atlas
resource "mongodbatlas_privatelink_endpoint_service" "pe_svc" {
  project_id            = var.atlas_project_id
  private_link_id       = mongodbatlas_privatelink_endpoint.pe.id
  endpoint_service_id   = aws_vpc_endpoint.atlas.id
  provider_name         = "AWS"
}
```

**Don't**: Route production traffic over the public Atlas hostname or leave public access enabled after private endpoints are configured

```python
# VULNERABLE: Using the public SRV hostname for a production cluster
# mongodb+srv://cluster0.abc12.mongodb.net  <-- public hostname
# Traffic traverses the public internet even when TLS is enabled.
# A valid credential pair is the only barrier — no network-layer isolation.

# VULNERABLE: Leaving public access enabled "just in case"
# If privateEndpointAccessEnabled is True but publicAccessEnabled is also True,
# both paths are open. An attacker who cannot reach the private endpoint can
# still reach the cluster via the public internet.
```

**Why**: TLS in transit is necessary but not sufficient for production database connectivity. A credential leak (environment variable, log file, build artifact) is enough to connect from any internet host if the cluster has a public endpoint. Private endpoints constrain connectivity to resources within the VPC; an attacker would need both valid credentials and VPC-level access, which are independent security boundaries. For regulatory environments (PCI DSS, HIPAA, FedRAMP), private-only connectivity is typically mandatory.

**Refs**: OWASP A05:2025 (Security Misconfiguration), CWE-668, NIST SP 800-53 SC-7 (Boundary Protection), MongoDB Atlas Private Endpoint Documentation

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 core rules |
| 2.0 | 2026-05-26 | OWASP refs :2021 → :2025; added LLM01/02/06:2025 refs; added IP access list, CMK at-rest encryption, and PrivateLink rules |

---

## Additional Resources

- [MongoDB Atlas Vector Search Documentation](https://www.mongodb.com/docs/atlas/atlas-vector-search/)
- [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
- [MongoDB Client-Side Field Level Encryption](https://www.mongodb.com/docs/manual/core/csfle/)
- [MongoDB Atlas Encryption at Rest](https://www.mongodb.com/docs/atlas/security-kms-encryption/)
- [MongoDB Atlas Private Endpoints](https://www.mongodb.com/docs/atlas/security-private-endpoint/)
- [MongoDB Atlas IP Access List](https://www.mongodb.com/docs/atlas/security/ip-access-list/)
- [MongoDB Role-Based Access Control](https://www.mongodb.com/docs/manual/core/authorization/)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
