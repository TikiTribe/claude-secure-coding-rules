# Weaviate Cloud Security Rules

Security rules for Weaviate Cloud vector database implementations with focus on authentication, multi-tenancy, GraphQL security, and generative AI features.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| Authentication Configuration | `strict` | Unauthorized access, credential exposure |
| Multi-Tenancy with RBAC | `strict` | Cross-tenant data leakage |
| GraphQL Query Security | `strict` | Query injection, DoS attacks |
| Generative Search Security | `warning` | Prompt injection, data exposure |
| Schema Security | `warning` | Data validation bypass, misconfiguration |
| Backup and Restore Security | `strict` | Data exposure, unauthorized restore |
| Module Security | `warning` | Malicious vectorizers, API key leakage |

---

## Rule: Authentication Configuration

**Level**: `strict`

**When**: Connecting to Weaviate Cloud instances or configuring authentication

**Do**: Use API keys from environment variables with OIDC for user authentication

```python
import weaviate
from weaviate.auth import AuthApiKey, AuthClientCredentials
import os

# Weaviate Cloud - API key authentication
def create_weaviate_client():
    """Create authenticated Weaviate Cloud client."""
    return weaviate.connect_to_weaviate_cloud(
        cluster_url=os.environ["WEAVIATE_URL"],
        auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
        headers={
            "X-OpenAI-Api-Key": os.environ.get("OPENAI_API_KEY", ""),
        }
    )

# OIDC authentication for user-based access
def create_oidc_client():
    """Create client with OIDC authentication for user-specific access."""
    return weaviate.connect_to_weaviate_cloud(
        cluster_url=os.environ["WEAVIATE_URL"],
        auth_credentials=AuthClientCredentials(
            client_secret=os.environ["WEAVIATE_CLIENT_SECRET"],
            scope="openid profile email"
        )
    )

# Client with connection pooling and timeouts
def create_secure_client():
    """Create client with secure configuration."""
    return weaviate.connect_to_weaviate_cloud(
        cluster_url=os.environ["WEAVIATE_URL"],
        auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
        additional_config=weaviate.config.AdditionalConfig(
            timeout=(30, 60),  # (connect, read) timeouts
            startup_period=10
        )
    )

# Proper context management
def query_with_client():
    """Use client with proper lifecycle management."""
    with create_secure_client() as client:
        # Client automatically closed after use
        collection = client.collections.get("Documents")
        return collection.query.fetch_objects(limit=10)
```

**Don't**: Hardcode credentials or use unencrypted connections

```python
# VULNERABLE: Hardcoded API key
client = weaviate.connect_to_weaviate_cloud(
    cluster_url="https://my-cluster.weaviate.cloud",
    auth_credentials=AuthApiKey("my-secret-api-key")  # Exposed in code
)

# VULNERABLE: No authentication
client = weaviate.connect_to_local()  # No auth for production

# VULNERABLE: API keys in headers without env vars
client = weaviate.connect_to_weaviate_cloud(
    cluster_url=os.environ["WEAVIATE_URL"],
    auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
    headers={
        "X-OpenAI-Api-Key": "sk-hardcoded-key"  # Exposed
    }
)

# VULNERABLE: No connection cleanup
client = create_secure_client()
# Client never closed, connection leak
```

**Why**: Hardcoded credentials leak through version control, logs, and error messages. Unencrypted connections expose queries and data to network interception. Missing connection cleanup can exhaust resources and leave sessions open.

**Refs**: OWASP A01:2025 (Broken Access Control), OWASP A07:2025 (Identification and Authentication Failures), CWE-798, CWE-319

---

## Rule: Multi-Tenancy with RBAC

**Level**: `strict`

**When**: Storing data from multiple tenants or users in the same Weaviate instance

**Do**: Use native multi-tenancy with tenant-specific access control

```python
import weaviate
from weaviate.classes.config import Configure, Property, DataType
from weaviate.classes.tenants import Tenant, TenantActivityStatus
import re

def create_multi_tenant_collection(client, collection_name: str):
    """Create collection with multi-tenancy enabled."""
    client.collections.create(
        name=collection_name,
        multi_tenancy_config=Configure.multi_tenancy(
            enabled=True,
            auto_tenant_creation=False,  # Explicit tenant management
            auto_tenant_activation=False  # Control tenant lifecycle
        ),
        vectorizer_config=Configure.Vectorizer.text2vec_openai(),
        properties=[
            Property(name="content", data_type=DataType.TEXT),
            Property(name="source", data_type=DataType.TEXT),
            Property(name="owner_id", data_type=DataType.TEXT),
            Property(name="created_at", data_type=DataType.DATE),
        ]
    )

def provision_tenant(client, collection_name: str, tenant_id: str):
    """Provision a new tenant with validation."""
    # Validate tenant_id format
    if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id):
        raise ValueError("Invalid tenant_id format")

    collection = client.collections.get(collection_name)
    collection.tenants.create([
        Tenant(name=tenant_id, activity_status=TenantActivityStatus.ACTIVE)
    ])

    # Audit log
    audit_log.info("tenant_provisioned", tenant_id=tenant_id, collection=collection_name)

def get_tenant_collection(client, collection_name: str, tenant_id: str, user_id: str):
    """Get tenant-specific collection with authorization check."""
    # Verify user has access to tenant
    if not auth_service.user_has_tenant_access(user_id, tenant_id):
        audit_log.warning(
            "unauthorized_tenant_access",
            user_id=user_id,
            attempted_tenant=tenant_id
        )
        raise PermissionError("User not authorized for tenant")

    collection = client.collections.get(collection_name)
    return collection.with_tenant(tenant_id)

def insert_with_tenant_isolation(client, collection_name: str, tenant_id: str,
                                  user_id: str, objects: list):
    """Insert objects with tenant isolation."""
    tenant_collection = get_tenant_collection(client, collection_name, tenant_id, user_id)

    # Add provenance metadata
    for obj in objects:
        obj["owner_id"] = user_id
        obj["tenant_id"] = tenant_id  # Redundant but useful for validation
        obj["created_at"] = datetime.utcnow().isoformat()

    result = tenant_collection.data.insert_many(objects)

    audit_log.info(
        "objects_inserted",
        tenant_id=tenant_id,
        user_id=user_id,
        count=len(objects)
    )
    return result

def query_with_tenant_isolation(client, collection_name: str, tenant_id: str,
                                 user_id: str, query: str, limit: int = 10):
    """Query with strict tenant isolation."""
    tenant_collection = get_tenant_collection(client, collection_name, tenant_id, user_id)

    results = tenant_collection.query.near_text(
        query=query,
        limit=limit,
        return_metadata=["distance"]
    )

    # Validate results belong to tenant (defense in depth)
    for obj in results.objects:
        if obj.properties.get("tenant_id") != tenant_id:
            audit_log.error(
                "cross_tenant_leak_detected",
                expected_tenant=tenant_id,
                leaked_tenant=obj.properties.get("tenant_id")
            )
            raise SecurityError("Tenant isolation violation")

    audit_log.info(
        "query_executed",
        tenant_id=tenant_id,
        user_id=user_id,
        result_count=len(results.objects)
    )

    return results

def deactivate_tenant(client, collection_name: str, tenant_id: str):
    """Deactivate tenant without deleting data."""
    collection = client.collections.get(collection_name)
    collection.tenants.update([
        Tenant(name=tenant_id, activity_status=TenantActivityStatus.INACTIVE)
    ])
    audit_log.info("tenant_deactivated", tenant_id=tenant_id)
```

**Don't**: Mix tenant data without isolation or trust client-provided tenant IDs

```python
# VULNERABLE: No multi-tenancy - all data mixed
collection = client.collections.create(
    name="Documents",
    # No multi_tenancy_config
    properties=[Property(name="content", data_type=DataType.TEXT)]
)

# VULNERABLE: Trust user-provided tenant_id without auth check
def query(request):
    tenant_id = request.json["tenant_id"]  # User controls this
    collection = client.collections.get("Documents").with_tenant(tenant_id)
    return collection.query.near_text(request.json["query"])

# VULNERABLE: Filter-based isolation only
def query_with_filter(tenant_id, query):
    collection = client.collections.get("Documents")
    # Attacker can manipulate or remove filter
    return collection.query.near_text(
        query=query,
        filters=Filter.by_property("tenant_id").equal(tenant_id)
    )

# VULNERABLE: Auto tenant creation allows arbitrary tenants
client.collections.create(
    name="Documents",
    multi_tenancy_config=Configure.multi_tenancy(
        enabled=True,
        auto_tenant_creation=True  # Anyone can create tenants
    )
)
```

**Why**: Without native multi-tenancy, a malicious or buggy query can access other tenants' data. Filter-based isolation can be bypassed through query manipulation. Auto tenant creation allows unauthorized users to create isolated spaces for malicious data.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-863

---

## Rule: GraphQL Query Security

**Level**: `strict`

**When**: Executing GraphQL queries through Weaviate's GraphQL API

**Do**: Implement query depth limits, input validation, and injection prevention

```python
from weaviate.classes.query import Filter
import re

# Query depth and complexity limits
MAX_QUERY_DEPTH = 5
MAX_RESULTS_PER_QUERY = 100
ALLOWED_PROPERTIES = {"content", "source", "created_at", "owner_id"}

def validate_query_parameters(query: str, limit: int, properties: list):
    """Validate query parameters before execution."""
    # Validate limit
    if limit < 1 or limit > MAX_RESULTS_PER_QUERY:
        raise ValueError(f"Limit must be between 1 and {MAX_RESULTS_PER_QUERY}")

    # Validate query string
    if len(query) > 1000:
        raise ValueError("Query too long")

    # Check for injection patterns
    injection_patterns = [
        r'\{.*\{.*\{.*\{.*\{',  # Deep nesting
        r'__schema',  # Schema introspection
        r'__type',  # Type introspection
        r'fragment.*on',  # Fragment injection
    ]
    for pattern in injection_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            raise ValueError("Invalid query pattern detected")

    # Validate requested properties
    if properties:
        invalid_props = set(properties) - ALLOWED_PROPERTIES
        if invalid_props:
            raise ValueError(f"Invalid properties: {invalid_props}")

    return True

def safe_near_text_query(client, collection_name: str, tenant_id: str,
                         query: str, limit: int = 10, properties: list = None):
    """Execute near_text query with security validation."""
    # Validate inputs
    validate_query_parameters(query, limit, properties)

    collection = client.collections.get(collection_name).with_tenant(tenant_id)

    # Execute with controlled parameters
    return collection.query.near_text(
        query=query,
        limit=min(limit, MAX_RESULTS_PER_QUERY),
        return_properties=properties or list(ALLOWED_PROPERTIES),
        return_metadata=["distance", "certainty"]
    )

def safe_filter_query(client, collection_name: str, tenant_id: str,
                      filters: dict, limit: int = 10):
    """Execute filter query with input validation."""
    # Validate filter structure
    validated_filter = build_safe_filter(filters)

    collection = client.collections.get(collection_name).with_tenant(tenant_id)

    return collection.query.fetch_objects(
        filters=validated_filter,
        limit=min(limit, MAX_RESULTS_PER_QUERY)
    )

def build_safe_filter(user_filters: dict) -> Filter:
    """Build Weaviate filter with validation."""
    ALLOWED_FILTER_FIELDS = {"source", "created_at", "owner_id"}
    ALLOWED_OPERATORS = {"equal", "not_equal", "greater_than", "less_than", "like"}

    if not user_filters:
        return None

    conditions = []
    for field, condition in user_filters.items():
        # Validate field
        if field not in ALLOWED_FILTER_FIELDS:
            raise ValueError(f"Invalid filter field: {field}")

        # Validate operator and value
        if isinstance(condition, dict):
            for op, value in condition.items():
                if op not in ALLOWED_OPERATORS:
                    raise ValueError(f"Invalid operator: {op}")

                # Sanitize value
                sanitized = sanitize_filter_value(value)

                # Build filter
                filter_prop = Filter.by_property(field)
                if op == "equal":
                    conditions.append(filter_prop.equal(sanitized))
                elif op == "not_equal":
                    conditions.append(filter_prop.not_equal(sanitized))
                elif op == "greater_than":
                    conditions.append(filter_prop.greater_than(sanitized))
                elif op == "less_than":
                    conditions.append(filter_prop.less_than(sanitized))
                elif op == "like":
                    conditions.append(filter_prop.like(sanitized))

    # Combine conditions
    if len(conditions) == 1:
        return conditions[0]
    return Filter.all_of(conditions)

def sanitize_filter_value(value):
    """Sanitize filter values."""
    if isinstance(value, str):
        if len(value) > 500:
            raise ValueError("Filter value too long")
        # Remove potentially dangerous characters
        return value.strip()
    elif isinstance(value, (int, float, bool)):
        return value
    elif isinstance(value, list):
        return [sanitize_filter_value(v) for v in value[:50]]
    else:
        raise ValueError(f"Invalid value type: {type(value)}")

# Rate limiting for GraphQL queries
from functools import wraps
import time

query_timestamps = {}

def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """Rate limit decorator for queries."""
    def decorator(func):
        @wraps(func)
        def wrapper(client, tenant_id, *args, **kwargs):
            current_time = time.time()
            key = f"{tenant_id}:{func.__name__}"

            if key not in query_timestamps:
                query_timestamps[key] = []

            # Clean old timestamps
            query_timestamps[key] = [
                ts for ts in query_timestamps[key]
                if current_time - ts < window_seconds
            ]

            # Check rate limit
            if len(query_timestamps[key]) >= max_requests:
                raise RateLimitError("Query rate limit exceeded")

            query_timestamps[key].append(current_time)
            return func(client, tenant_id, *args, **kwargs)
        return wrapper
    return decorator

@rate_limit(max_requests=100, window_seconds=60)
def rate_limited_query(client, tenant_id, query, limit=10):
    """Query with rate limiting."""
    return safe_near_text_query(client, "Documents", tenant_id, query, limit)
```

**Don't**: Pass raw user input to GraphQL queries or allow unlimited query depth

```python
# VULNERABLE: Direct user input in query
def query(user_input):
    return collection.query.near_text(
        query=user_input  # No validation
    )

# VULNERABLE: Unrestricted limit
def query_all(query, limit):
    return collection.query.near_text(
        query=query,
        limit=limit  # User can request millions
    )

# VULNERABLE: No filter validation
def filter_query(user_filters):
    # User can access any field
    filter_obj = Filter.by_property(user_filters["field"]).equal(user_filters["value"])
    return collection.query.fetch_objects(filters=filter_obj)

# VULNERABLE: Raw GraphQL execution
def raw_graphql(graphql_query):
    # User controls entire query structure
    return client.graphql_raw_query(graphql_query)
```

**Why**: Unvalidated GraphQL queries can cause denial of service through deep nesting or large result sets. Injection attacks can bypass filters or access unauthorized data. Schema introspection can expose internal structure to attackers.

**Refs**: OWASP A03:2025 (Injection), CWE-89, CWE-943, CWE-400

---

## Rule: Generative Search Security

**Level**: `warning`

**When**: Using Weaviate's generative search features (RAG with generate module)

**Do**: Validate prompts, filter outputs, and control LLM access

```python
from weaviate.classes.generate import GenerativeSearchConfig
import re

# Allowed prompt templates
APPROVED_PROMPTS = {
    "summarize": "Summarize the following content in 2-3 sentences: {content}",
    "extract_key_points": "Extract the key points from: {content}",
    "answer_question": "Based on the following context, answer the question.\n\nContext: {content}\n\nQuestion: {question}",
}

def validate_prompt_template(prompt: str) -> bool:
    """Validate prompt for injection attacks."""
    # Check for prompt injection patterns
    injection_patterns = [
        r'ignore.*previous.*instructions',
        r'disregard.*above',
        r'forget.*everything',
        r'system.*prompt',
        r'you.*are.*now',
        r'act.*as',
        r'pretend.*to.*be',
        r'\[INST\]',
        r'<\|.*\|>',
    ]

    for pattern in injection_patterns:
        if re.search(pattern, prompt, re.IGNORECASE):
            return False

    # Check length
    if len(prompt) > 2000:
        return False

    return True

def safe_generative_search(client, collection_name: str, tenant_id: str,
                           query: str, prompt_type: str, limit: int = 5,
                           custom_question: str = None):
    """Execute generative search with security controls."""
    # Use approved prompt template
    if prompt_type not in APPROVED_PROMPTS:
        raise ValueError(f"Unknown prompt type: {prompt_type}")

    prompt_template = APPROVED_PROMPTS[prompt_type]

    # Validate custom question if provided
    if custom_question:
        if not validate_prompt_template(custom_question):
            raise ValueError("Invalid question content")
        if len(custom_question) > 500:
            raise ValueError("Question too long")
        prompt_template = prompt_template.replace("{question}", custom_question)

    collection = client.collections.get(collection_name).with_tenant(tenant_id)

    # Execute with controlled parameters
    results = collection.generate.near_text(
        query=query,
        limit=min(limit, 10),  # Limit context size
        grouped_task=prompt_template,
        return_metadata=["distance"]
    )

    # Filter generated output
    if results.generated:
        filtered_output = filter_generated_output(results.generated)
        results._generated = filtered_output

    audit_log.info(
        "generative_search",
        tenant_id=tenant_id,
        prompt_type=prompt_type,
        query_length=len(query),
        result_count=len(results.objects)
    )

    return results

def filter_generated_output(output: str) -> str:
    """Filter LLM output for sensitive content."""
    # Remove potential PII patterns
    pii_patterns = [
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]'),  # SSN
        (r'\b\d{16}\b', '[CARD REDACTED]'),  # Credit card
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]'),
    ]

    filtered = output
    for pattern, replacement in pii_patterns:
        filtered = re.sub(pattern, replacement, filtered)

    # Truncate very long outputs
    if len(filtered) > 5000:
        filtered = filtered[:5000] + "... [truncated]"

    return filtered

def secure_rag_pipeline(client, collection_name: str, tenant_id: str,
                        user_id: str, question: str):
    """Complete RAG pipeline with security controls."""
    # Validate question
    if not validate_prompt_template(question):
        raise ValueError("Invalid question content")

    # Check user authorization
    if not auth_service.user_has_tenant_access(user_id, tenant_id):
        raise PermissionError("Unauthorized")

    # Execute generative search
    results = safe_generative_search(
        client=client,
        collection_name=collection_name,
        tenant_id=tenant_id,
        query=question,
        prompt_type="answer_question",
        custom_question=question,
        limit=5
    )

    # Log for audit
    audit_log.info(
        "rag_query",
        tenant_id=tenant_id,
        user_id=user_id,
        question_length=len(question),
        sources_used=len(results.objects)
    )

    return {
        "answer": results.generated,
        "sources": [
            {
                "content": obj.properties.get("content", "")[:200],
                "source": obj.properties.get("source"),
                "distance": obj.metadata.distance
            }
            for obj in results.objects
        ]
    }
```

**Don't**: Pass raw user input as prompts or expose raw LLM outputs

```python
# VULNERABLE: User controls entire prompt
def generate(user_prompt, context):
    return collection.generate.near_text(
        query=context,
        grouped_task=user_prompt  # Prompt injection possible
    )

# VULNERABLE: No output filtering
def generate_answer(query):
    results = collection.generate.near_text(
        query=query,
        single_prompt="Answer: {content}"
    )
    return results.generated  # May contain PII or injected content

# VULNERABLE: Excessive context
def generate_with_all(query):
    return collection.generate.near_text(
        query=query,
        limit=1000,  # Too much context, cost and latency issues
        grouped_task="Summarize: {content}"
    )

# VULNERABLE: No audit logging
def generate_silent(query, prompt):
    return collection.generate.near_text(query=query, grouped_task=prompt)
    # No record of what was queried or generated
```

**Why**: Generative search combines vector retrieval with LLM generation, creating multiple attack vectors. Prompt injection can manipulate LLM behavior. Unfiltered outputs may leak PII from context. Large context windows increase costs and latency.

**Refs**: OWASP LLM01 (Prompt Injection), OWASP LLM02 (Insecure Output Handling), CWE-74

---

## Rule: Schema Security

**Level**: `warning`

**When**: Defining collection schemas and vectorizer configurations

**Do**: Validate property configurations and secure vectorizer settings

```python
from weaviate.classes.config import Configure, Property, DataType, Tokenization
import re

# Allowed configurations
ALLOWED_DATA_TYPES = {DataType.TEXT, DataType.INT, DataType.NUMBER,
                      DataType.BOOL, DataType.DATE, DataType.UUID}
ALLOWED_VECTORIZERS = {"text2vec-openai", "text2vec-cohere", "text2vec-huggingface"}
MAX_PROPERTIES = 50

def validate_property_config(properties: list) -> bool:
    """Validate property configurations."""
    if len(properties) > MAX_PROPERTIES:
        raise ValueError(f"Too many properties: {len(properties)} > {MAX_PROPERTIES}")

    property_names = set()
    for prop in properties:
        # Validate name format
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]{0,63}$', prop.name):
            raise ValueError(f"Invalid property name: {prop.name}")

        # Check for duplicates
        if prop.name in property_names:
            raise ValueError(f"Duplicate property: {prop.name}")
        property_names.add(prop.name)

        # Validate data type
        if prop.data_type not in ALLOWED_DATA_TYPES:
            raise ValueError(f"Disallowed data type: {prop.data_type}")

    return True

def create_secure_collection(client, collection_name: str, properties: list,
                              vectorizer: str = "text2vec-openai"):
    """Create collection with secure configuration."""
    # Validate collection name
    if not re.match(r'^[A-Z][a-zA-Z0-9_]{0,63}$', collection_name):
        raise ValueError("Collection name must start with uppercase letter")

    # Validate properties
    validate_property_config(properties)

    # Validate vectorizer
    if vectorizer not in ALLOWED_VECTORIZERS:
        raise ValueError(f"Disallowed vectorizer: {vectorizer}")

    # Configure vectorizer based on type
    if vectorizer == "text2vec-openai":
        vectorizer_config = Configure.Vectorizer.text2vec_openai(
            model="text-embedding-3-small",
            vectorize_collection_name=False  # Don't include collection name in vectors
        )
    elif vectorizer == "text2vec-cohere":
        vectorizer_config = Configure.Vectorizer.text2vec_cohere(
            model="embed-english-v3.0"
        )
    else:
        vectorizer_config = Configure.Vectorizer.text2vec_huggingface()

    # Create with security-focused configuration
    client.collections.create(
        name=collection_name,
        vectorizer_config=vectorizer_config,
        properties=properties,
        # Enable multi-tenancy by default
        multi_tenancy_config=Configure.multi_tenancy(
            enabled=True,
            auto_tenant_creation=False
        ),
        # Configure inverted index for security
        inverted_index_config=Configure.inverted_index(
            bm25_b=0.75,
            bm25_k1=1.2,
            cleanup_interval_seconds=60,
            index_null_state=False,
            index_property_length=False,  # Don't expose property lengths
            index_timestamps=True  # Enable timestamp filtering
        )
    )

    audit_log.info(
        "collection_created",
        collection=collection_name,
        vectorizer=vectorizer,
        property_count=len(properties)
    )

def secure_property_definition(name: str, data_type: DataType,
                                skip_vectorization: bool = False,
                                tokenization: Tokenization = None) -> Property:
    """Create property with secure defaults."""
    config = {
        "name": name,
        "data_type": data_type,
        "skip_vectorization": skip_vectorization,
    }

    # Set tokenization for text fields
    if data_type == DataType.TEXT:
        config["tokenization"] = tokenization or Tokenization.WORD
        # Prevent field-level injection
        config["index_filterable"] = True
        config["index_searchable"] = True

    return Property(**config)

# Example secure schema
def create_documents_collection(client):
    """Create documents collection with secure schema."""
    properties = [
        secure_property_definition("content", DataType.TEXT),
        secure_property_definition("title", DataType.TEXT, skip_vectorization=True),
        secure_property_definition("source", DataType.TEXT, skip_vectorization=True),
        secure_property_definition("owner_id", DataType.TEXT, skip_vectorization=True),
        secure_property_definition("created_at", DataType.DATE, skip_vectorization=True),
        secure_property_definition("classification", DataType.TEXT, skip_vectorization=True),
    ]

    create_secure_collection(client, "Documents", properties)
```

**Don't**: Allow arbitrary schema creation or expose sensitive configuration

```python
# VULNERABLE: Allow any property type
def create_collection(name, properties):
    # No validation of property types
    client.collections.create(name=name, properties=properties)

# VULNERABLE: Expose all fields in vectors
client.collections.create(
    name="Users",
    vectorizer_config=Configure.Vectorizer.text2vec_openai(),
    properties=[
        Property(name="email", data_type=DataType.TEXT),  # PII vectorized
        Property(name="ssn", data_type=DataType.TEXT),    # Sensitive data
        # All fields included in vector by default
    ]
)

# VULNERABLE: Auto tenant creation
client.collections.create(
    name="Data",
    multi_tenancy_config=Configure.multi_tenancy(
        enabled=True,
        auto_tenant_creation=True  # Anyone can create tenants
    )
)

# VULNERABLE: Index property lengths (information leakage)
client.collections.create(
    name="Secrets",
    inverted_index_config=Configure.inverted_index(
        index_property_length=True  # Exposes data characteristics
    )
)
```

**Why**: Schema misconfiguration can expose sensitive data through vectorization, allow unauthorized tenant creation, or leak information through index metadata. Vectorizing PII creates embeddings that could potentially be inverted.

**Refs**: OWASP A05:2025 (Security Misconfiguration), CWE-200, CWE-284

---

## Rule: Backup and Restore Security

**Level**: `strict`

**When**: Creating backups or restoring Weaviate data

**Do**: Encrypt backups, verify integrity, and control restore access

```python
import hashlib
from cryptography.fernet import Fernet
import json
import os

def backup_collection_secure(client, collection_name: str, tenant_id: str,
                              backup_path: str):
    """Create encrypted backup of collection data."""
    # Get collection with tenant
    collection = client.collections.get(collection_name).with_tenant(tenant_id)

    # Export all objects
    objects = []
    for obj in collection.iterator():
        objects.append({
            "uuid": str(obj.uuid),
            "properties": obj.properties,
            "vector": obj.vector if obj.vector else None
        })

    # Serialize data
    backup_data = json.dumps({
        "collection": collection_name,
        "tenant": tenant_id,
        "timestamp": datetime.utcnow().isoformat(),
        "object_count": len(objects),
        "objects": objects
    }).encode()

    # Calculate checksum before encryption
    checksum = hashlib.sha256(backup_data).hexdigest()

    # Encrypt backup
    key = os.environ["BACKUP_ENCRYPTION_KEY"]
    fernet = Fernet(key)
    encrypted = fernet.encrypt(backup_data)

    # Write encrypted backup
    with open(backup_path, "wb") as f:
        f.write(encrypted)

    # Store checksum separately (or in metadata)
    checksum_path = f"{backup_path}.sha256"
    with open(checksum_path, "w") as f:
        f.write(checksum)

    audit_log.info(
        "backup_created",
        collection=collection_name,
        tenant=tenant_id,
        object_count=len(objects),
        backup_path=backup_path,
        checksum=checksum
    )

    return checksum

def restore_collection_secure(client, backup_path: str, expected_checksum: str,
                               target_tenant: str = None):
    """Restore encrypted backup with integrity verification."""
    # Load encrypted backup
    with open(backup_path, "rb") as f:
        encrypted = f.read()

    # Decrypt
    key = os.environ["BACKUP_ENCRYPTION_KEY"]
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    # Verify integrity
    actual_checksum = hashlib.sha256(decrypted).hexdigest()
    if actual_checksum != expected_checksum:
        audit_log.error(
            "backup_integrity_failed",
            backup_path=backup_path,
            expected=expected_checksum,
            actual=actual_checksum
        )
        raise IntegrityError("Backup checksum mismatch - possible tampering")

    # Parse backup
    backup_data = json.loads(decrypted)
    collection_name = backup_data["collection"]
    tenant_id = target_tenant or backup_data["tenant"]

    # Get collection
    collection = client.collections.get(collection_name).with_tenant(tenant_id)

    # Restore objects
    restored_count = 0
    for obj in backup_data["objects"]:
        try:
            collection.data.insert(
                properties=obj["properties"],
                uuid=obj["uuid"],
                vector=obj["vector"]
            )
            restored_count += 1
        except Exception as e:
            audit_log.warning(
                "restore_object_failed",
                uuid=obj["uuid"],
                error=str(e)
            )

    audit_log.info(
        "backup_restored",
        collection=collection_name,
        tenant=tenant_id,
        restored_count=restored_count,
        total_count=backup_data["object_count"]
    )

    return restored_count

def verify_backup_integrity(backup_path: str, expected_checksum: str) -> bool:
    """Verify backup integrity without decryption."""
    checksum_path = f"{backup_path}.sha256"

    if os.path.exists(checksum_path):
        with open(checksum_path, "r") as f:
            stored_checksum = f.read().strip()

        if stored_checksum != expected_checksum:
            return False

    # Decrypt and verify content checksum
    key = os.environ["BACKUP_ENCRYPTION_KEY"]
    fernet = Fernet(key)

    with open(backup_path, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = fernet.decrypt(encrypted)
        actual_checksum = hashlib.sha256(decrypted).hexdigest()
        return actual_checksum == expected_checksum
    except Exception:
        return False

# Weaviate Cloud native backup (uses cloud provider encryption)
def create_cloud_backup(client, backup_id: str, collections: list):
    """Create Weaviate Cloud backup with proper configuration."""
    # Weaviate Cloud handles encryption at rest
    result = client.backup.create(
        backup_id=backup_id,
        backend="s3",  # or "gcs", "azure"
        include_collections=collections,
        wait_for_completion=True
    )

    audit_log.info(
        "cloud_backup_created",
        backup_id=backup_id,
        collections=collections,
        status=result.status
    )

    return result

def restore_cloud_backup(client, backup_id: str, collections: list = None):
    """Restore from Weaviate Cloud backup."""
    result = client.backup.restore(
        backup_id=backup_id,
        backend="s3",
        include_collections=collections,
        wait_for_completion=True
    )

    audit_log.info(
        "cloud_backup_restored",
        backup_id=backup_id,
        collections=collections,
        status=result.status
    )

    return result
```

**Don't**: Store unencrypted backups or skip integrity verification

```python
# VULNERABLE: Unencrypted backup
def backup_collection(client, collection_name):
    objects = list(collection.iterator())
    with open("/backups/data.json", "w") as f:
        json.dump(objects, f)  # Plaintext backup

# VULNERABLE: No integrity verification on restore
def restore_backup(client, backup_path):
    with open(backup_path, "r") as f:
        data = json.load(f)  # Could be tampered
    for obj in data:
        collection.data.insert(obj)  # Blind restore

# VULNERABLE: Backups accessible without auth
backup_path = "/public/backups/weaviate/"  # Anyone can access

# VULNERABLE: No audit trail
def silent_backup(client, collection):
    # No logging of backup operations
    data = list(collection.iterator())
    save_to_storage(data)
```

**Why**: Backups contain complete vector database snapshots including potentially sensitive embeddings. Unencrypted backups can be exfiltrated or tampered with. Missing integrity checks allow restoring corrupted or malicious data.

**Refs**: OWASP A02:2025 (Cryptographic Failures), CWE-311, CWE-312, CWE-354

---

## Rule: Module Security

**Level**: `warning`

**When**: Configuring vectorizer modules and external integrations

**Do**: Validate module configurations and secure API key handling

```python
from weaviate.classes.config import Configure
import os

# Approved modules and models
APPROVED_VECTORIZERS = {
    "text2vec-openai": ["text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"],
    "text2vec-cohere": ["embed-english-v3.0", "embed-multilingual-v3.0"],
    "text2vec-huggingface": ["sentence-transformers/all-MiniLM-L6-v2"],
}

APPROVED_GENERATIVE = {
    "generative-openai": ["gpt-4o-mini", "gpt-4o"],
    "generative-cohere": ["command-r"],
}

def validate_vectorizer_config(vectorizer: str, model: str) -> bool:
    """Validate vectorizer module and model."""
    if vectorizer not in APPROVED_VECTORIZERS:
        raise ValueError(f"Unapproved vectorizer: {vectorizer}")

    if model not in APPROVED_VECTORIZERS[vectorizer]:
        raise ValueError(f"Unapproved model for {vectorizer}: {model}")

    return True

def create_collection_with_validated_modules(client, collection_name: str,
                                              vectorizer: str, vectorizer_model: str,
                                              generative: str = None, generative_model: str = None):
    """Create collection with validated module configuration."""
    # Validate vectorizer
    validate_vectorizer_config(vectorizer, vectorizer_model)

    # Configure vectorizer
    if vectorizer == "text2vec-openai":
        vectorizer_config = Configure.Vectorizer.text2vec_openai(
            model=vectorizer_model,
            vectorize_collection_name=False
        )
    elif vectorizer == "text2vec-cohere":
        vectorizer_config = Configure.Vectorizer.text2vec_cohere(
            model=vectorizer_model
        )
    elif vectorizer == "text2vec-huggingface":
        vectorizer_config = Configure.Vectorizer.text2vec_huggingface(
            model=vectorizer_model
        )

    # Configure generative if specified
    generative_config = None
    if generative and generative_model:
        if generative not in APPROVED_GENERATIVE:
            raise ValueError(f"Unapproved generative module: {generative}")
        if generative_model not in APPROVED_GENERATIVE[generative]:
            raise ValueError(f"Unapproved generative model: {generative_model}")

        if generative == "generative-openai":
            generative_config = Configure.Generative.openai(model=generative_model)
        elif generative == "generative-cohere":
            generative_config = Configure.Generative.cohere(model=generative_model)

    # Create collection
    client.collections.create(
        name=collection_name,
        vectorizer_config=vectorizer_config,
        generative_config=generative_config,
        multi_tenancy_config=Configure.multi_tenancy(enabled=True)
    )

    audit_log.info(
        "collection_created_with_modules",
        collection=collection_name,
        vectorizer=vectorizer,
        vectorizer_model=vectorizer_model,
        generative=generative,
        generative_model=generative_model
    )

def secure_client_with_module_keys():
    """Create client with secure API key handling for modules."""
    # Validate required keys exist
    required_keys = ["WEAVIATE_API_KEY"]
    optional_keys = ["OPENAI_API_KEY", "COHERE_API_KEY", "HUGGINGFACE_API_KEY"]

    for key in required_keys:
        if key not in os.environ:
            raise EnvironmentError(f"Missing required key: {key}")

    # Build headers only for available keys
    headers = {}
    if os.environ.get("OPENAI_API_KEY"):
        headers["X-OpenAI-Api-Key"] = os.environ["OPENAI_API_KEY"]
    if os.environ.get("COHERE_API_KEY"):
        headers["X-Cohere-Api-Key"] = os.environ["COHERE_API_KEY"]
    if os.environ.get("HUGGINGFACE_API_KEY"):
        headers["X-HuggingFace-Api-Key"] = os.environ["HUGGINGFACE_API_KEY"]

    return weaviate.connect_to_weaviate_cloud(
        cluster_url=os.environ["WEAVIATE_URL"],
        auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
        headers=headers
    )

def validate_module_response(response, expected_dimensions: int):
    """Validate vectorizer module response."""
    if not response or not response.vector:
        raise ValueError("Empty vector response from module")

    if len(response.vector) != expected_dimensions:
        raise ValueError(
            f"Unexpected vector dimensions: {len(response.vector)} != {expected_dimensions}"
        )

    # Check for anomalous values
    import numpy as np
    vector = np.array(response.vector)

    if np.any(np.isnan(vector)):
        raise ValueError("NaN values in vector")

    if np.any(np.isinf(vector)):
        raise ValueError("Infinite values in vector")

    return True
```

**Don't**: Allow arbitrary modules or expose API keys

```python
# VULNERABLE: Allow any module/model
def create_collection(client, config):
    vectorizer = config.get("vectorizer")  # User controls module
    model = config.get("model")  # User controls model

    client.collections.create(
        name=config["name"],
        vectorizer_config=Configure.Vectorizer.text2vec_openai(model=model)
    )

# VULNERABLE: Hardcoded API keys
client = weaviate.connect_to_weaviate_cloud(
    cluster_url=os.environ["WEAVIATE_URL"],
    auth_credentials=AuthApiKey(os.environ["WEAVIATE_API_KEY"]),
    headers={
        "X-OpenAI-Api-Key": "sk-1234567890abcdef"  # Exposed
    }
)

# VULNERABLE: API keys in logs
def create_client():
    headers = {"X-OpenAI-Api-Key": os.environ["OPENAI_API_KEY"]}
    logger.info(f"Creating client with headers: {headers}")  # Key logged
    return weaviate.connect_to_weaviate_cloud(...)

# VULNERABLE: No module response validation
def insert_object(collection, content):
    # Trust whatever the vectorizer returns
    collection.data.insert({"content": content})
```

**Why**: Arbitrary module selection could use malicious or vulnerable vectorizers. API keys for external services (OpenAI, Cohere) must be protected from exposure. Invalid module responses could indicate compromise or misconfiguration.

**Refs**: OWASP A05:2025 (Security Misconfiguration), OWASP A07:2025 (Identification and Authentication Failures), CWE-798, CWE-532

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial release with 7 security rules |

---

## Additional Resources

- [Weaviate Security Documentation](https://weaviate.io/developers/weaviate/configuration/authentication)
- [Weaviate Multi-Tenancy Guide](https://weaviate.io/developers/weaviate/concepts/data#multi-tenancy)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [OWASP LLM Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [Weaviate GraphQL API Security](https://weaviate.io/developers/weaviate/api/graphql)
- [Vector Store Security Core Rules](../../_core/vector-store-security.md)
