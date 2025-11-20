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

**Refs**: OWASP A02:2021 (Cryptographic Failures), CWE-798, CWE-319, MongoDB Atlas Security Documentation

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

**Refs**: OWASP A01:2021 (Broken Access Control), CWE-284, MongoDB Atlas Search Documentation

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

**Why**: MongoDB aggregation pipelines are powerful and can be exploited for data exfiltration, denial of service, or access control bypass. NoSQL injection through operators like $where or $function can execute arbitrary code. Unvalidated filters can bypass tenant isolation.

**Refs**: OWASP A03:2021 (Injection), CWE-943, CWE-89, MongoDB Security Documentation

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

**Refs**: OWASP A04:2021 (Insecure Design), CWE-362, CWE-367, MongoDB Transaction Documentation

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

# Configure field-level encryption
def get_encrypted_client():
    """Create client with client-side field-level encryption."""

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

**Why**: Without RBAC, compromised services can perform unauthorized operations. Shared credentials prevent auditing and granular revocation. Unencrypted sensitive data is exposed in backups, logs, and to database administrators.

**Refs**: OWASP A01:2021 (Broken Access Control), CWE-284, CWE-732, MongoDB Security Documentation

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

**Why**: Without mandatory tenant filters, queries can access other tenants' data. User-controlled filters can bypass security controls through operator injection. Result validation provides defense in depth against filter bugs or misconfigurations.

**Refs**: OWASP A01:2021 (Broken Access Control), OWASP A03:2021 (Injection), CWE-863, CWE-943

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

**Refs**: OWASP A04:2021 (Insecure Design), CWE-20, CWE-778, MongoDB Schema Validation Documentation

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 core rules |

---

## Additional Resources

- [MongoDB Atlas Vector Search Documentation](https://www.mongodb.com/docs/atlas/atlas-vector-search/)
- [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
- [MongoDB Client-Side Field Level Encryption](https://www.mongodb.com/docs/manual/core/csfle/)
- [MongoDB Role-Based Access Control](https://www.mongodb.com/docs/manual/core/authorization/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
