# Azure AI Search Security Rules

Security rules for Azure AI Search (formerly Azure Cognitive Search) implementations in RAG systems.

## Quick Reference

| Rule | Level | Primary Risk |
|------|-------|--------------|
| API Key and RBAC Security | `strict` | Unauthorized access, key exposure |
| Semantic Ranking Security | `warning` | Score manipulation, information leakage |
| Hybrid Search Security | `warning` | Filter bypass, result manipulation |
| Azure OpenAI Integration | `strict` | Endpoint exposure, credential theft |
| Index Schema Security | `warning` | Data exposure, injection attacks |
| Skillset Security | `warning` | Custom skill abuse, cognitive service key exposure |
| Data Source Connection | `strict` | Connection string exposure, unauthorized data access |

---

## Rule: API Key and RBAC Security

**Level**: `strict`

**When**: Configuring authentication for Azure AI Search service access

**Do**: Use Managed Identity for Azure-to-Azure communication, separate admin and query keys, implement Azure RBAC

```python
# Secure configuration with Managed Identity (recommended)
from azure.identity import DefaultAzureCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
import os

def get_search_client_with_identity(index_name: str) -> SearchClient:
    """Create search client using Managed Identity (zero credentials in code)."""
    credential = DefaultAzureCredential()

    endpoint = os.environ["AZURE_SEARCH_ENDPOINT"]
    # Validate endpoint format
    if not endpoint.startswith("https://"):
        raise ValueError("Search endpoint must use HTTPS")

    return SearchClient(
        endpoint=endpoint,
        index_name=index_name,
        credential=credential
    )

def get_index_client_with_identity() -> SearchIndexClient:
    """Create index management client using Managed Identity."""
    credential = DefaultAzureCredential()

    return SearchIndexClient(
        endpoint=os.environ["AZURE_SEARCH_ENDPOINT"],
        credential=credential
    )

# API Key approach with proper key separation
def get_query_client(index_name: str) -> SearchClient:
    """Create read-only search client with query key."""
    from azure.core.credentials import AzureKeyCredential

    # Query key has read-only access
    query_key = os.environ.get("AZURE_SEARCH_QUERY_KEY")
    if not query_key:
        raise ValueError("Query key not configured")

    return SearchClient(
        endpoint=os.environ["AZURE_SEARCH_ENDPOINT"],
        index_name=index_name,
        credential=AzureKeyCredential(query_key)
    )

def get_admin_client() -> SearchIndexClient:
    """Create admin client for index management (restricted use)."""
    from azure.core.credentials import AzureKeyCredential

    # Admin key should only be used by privileged operations
    admin_key = os.environ.get("AZURE_SEARCH_ADMIN_KEY")
    if not admin_key:
        raise ValueError("Admin key not configured")

    return SearchIndexClient(
        endpoint=os.environ["AZURE_SEARCH_ENDPOINT"],
        credential=AzureKeyCredential(admin_key)
    )

# Azure RBAC role assignments (via Azure CLI or ARM template)
"""
# Assign Search Index Data Reader for query operations
az role assignment create \
    --assignee <managed-identity-id> \
    --role "Search Index Data Reader" \
    --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Search/searchServices/<service>

# Assign Search Index Data Contributor for indexing operations
az role assignment create \
    --assignee <indexer-identity-id> \
    --role "Search Index Data Contributor" \
    --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Search/searchServices/<service>

# Never assign Search Service Contributor to application identities
"""

# Audit key usage
import logging
from datetime import datetime

audit_logger = logging.getLogger("security.audit")

def audit_search_operation(operation: str, user_id: str, index_name: str,
                           auth_type: str, success: bool):
    """Log search operations for security audit."""
    audit_logger.info(
        "search_operation",
        extra={
            "operation": operation,
            "user_id": user_id,
            "index_name": index_name,
            "auth_type": auth_type,  # "managed_identity" or "api_key"
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

**Don't**: Hardcode API keys, use admin keys for queries, or skip RBAC setup

```python
# VULNERABLE: Hardcoded admin key
from azure.search.documents import SearchClient
from azure.core.credentials import AzureKeyCredential

client = SearchClient(
    endpoint="https://mysearch.search.windows.net",
    index_name="documents",
    credential=AzureKeyCredential("abc123xyz789")  # Hardcoded admin key
)

# VULNERABLE: Using admin key for all operations
def search(query):
    admin_key = os.environ["AZURE_SEARCH_ADMIN_KEY"]
    client = SearchClient(
        endpoint=os.environ["AZURE_SEARCH_ENDPOINT"],
        index_name="documents",
        credential=AzureKeyCredential(admin_key)  # Admin key for queries
    )
    return client.search(query)

# VULNERABLE: No key rotation or monitoring
# Keys never rotated, no audit logging
```

**Why**: Admin keys grant full control including delete operations. Exposed keys in code/logs enable attackers to exfiltrate or destroy data. Managed Identity eliminates credential management risks. RBAC provides fine-grained access control and audit trails.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-284, CWE-798, Microsoft Security Baseline for Azure AI Search

---

## Rule: Semantic Ranking Security

**Level**: `warning`

**When**: Using semantic ranker for improved search relevance

**Do**: Validate semantic configuration, interpret scores correctly, implement rate limiting

```python
from azure.search.documents import SearchClient
from azure.search.documents.models import (
    QueryType,
    QueryCaptionType,
    QueryAnswerType
)
import logging

logger = logging.getLogger(__name__)

def secure_semantic_search(
    client: SearchClient,
    query: str,
    user_id: str,
    top_k: int = 10,
    min_score: float = 0.5
) -> list:
    """Execute semantic search with security validations."""

    # Input validation
    if not query or len(query) > 10000:
        raise ValueError("Invalid query length")

    # Sanitize query (remove potential injection patterns)
    sanitized_query = sanitize_search_query(query)

    try:
        results = client.search(
            search_text=sanitized_query,
            query_type=QueryType.SEMANTIC,
            semantic_configuration_name="my-semantic-config",
            query_caption=QueryCaptionType.EXTRACTIVE,
            query_answer=QueryAnswerType.EXTRACTIVE,
            top=min(top_k, 50),  # Limit maximum results
            include_total_count=True
        )

        # Process and validate results
        validated_results = []
        for result in results:
            # Check reranker score threshold
            reranker_score = result.get("@search.reranker_score", 0)

            if reranker_score < min_score:
                logger.debug(f"Filtered low-score result: {reranker_score}")
                continue

            # Validate result has expected fields
            if not validate_result_structure(result):
                logger.warning(f"Invalid result structure: {result.get('id')}")
                continue

            validated_results.append({
                "id": result["id"],
                "score": reranker_score,
                "captions": result.get("@search.captions", []),
                "content": result.get("content", "")
            })

        # Audit the search
        audit_semantic_search(
            user_id=user_id,
            query_length=len(sanitized_query),
            result_count=len(validated_results)
        )

        return validated_results

    except Exception as e:
        logger.error(f"Semantic search failed: {e}")
        raise

def sanitize_search_query(query: str) -> str:
    """Sanitize search query for Azure AI Search."""
    # Remove Lucene special characters that could be exploited
    special_chars = ['+', '-', '&&', '||', '!', '(', ')', '{', '}',
                    '[', ']', '^', '"', '~', '*', '?', ':', '\\', '/']

    sanitized = query
    for char in special_chars:
        sanitized = sanitized.replace(char, ' ')

    # Collapse multiple spaces
    sanitized = ' '.join(sanitized.split())

    return sanitized.strip()

def validate_result_structure(result: dict) -> bool:
    """Validate search result has expected secure structure."""
    required_fields = ["id"]
    return all(field in result for field in required_fields)

# Semantic configuration validation
def validate_semantic_config(index_client, index_name: str, config_name: str) -> bool:
    """Validate semantic configuration exists and is properly configured."""
    try:
        index = index_client.get_index(index_name)

        if not index.semantic_configurations:
            logger.error(f"No semantic configurations in index {index_name}")
            return False

        config = next(
            (c for c in index.semantic_configurations if c.name == config_name),
            None
        )

        if not config:
            logger.error(f"Semantic config {config_name} not found")
            return False

        # Validate prioritized fields are set
        if not config.prioritized_fields:
            logger.warning("Semantic config has no prioritized fields")
            return False

        return True

    except Exception as e:
        logger.error(f"Failed to validate semantic config: {e}")
        return False
```

**Don't**: Trust scores blindly, skip validation, or allow unlimited queries

```python
# VULNERABLE: No score validation
def search(client, query):
    results = client.search(
        search_text=query,  # Unsanitized
        query_type=QueryType.SEMANTIC
    )
    return list(results)  # Return all results without validation

# VULNERABLE: No rate limiting on expensive semantic queries
def unlimited_semantic_search(query):
    # Semantic ranking is computationally expensive
    # No rate limiting allows resource exhaustion
    return client.search(
        search_text=query,
        query_type=QueryType.SEMANTIC,
        top=1000  # Excessive results
    )

# VULNERABLE: Trusting captions without sanitization
def get_answer(result):
    # Captions could contain sensitive data from indexed content
    return result["@search.captions"][0]["text"]  # Direct return
```

**Why**: Semantic ranking uses AI models that can be resource-intensive. Low-score results may indicate adversarial inputs or noise. Captions are extracted from indexed content and may expose sensitive information if not validated.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-20, Azure AI Search Semantic Ranking documentation

---

## Rule: Hybrid Search Security

**Level**: `warning`

**When**: Combining BM25 keyword search with vector similarity search

**Do**: Validate both search paths, enforce consistent filtering, normalize scores

```python
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery, VectorFilterMode
import numpy as np

def secure_hybrid_search(
    client: SearchClient,
    query_text: str,
    query_vector: list,
    tenant_id: str,
    filters: dict = None,
    top_k: int = 10
) -> list:
    """Execute hybrid search with security validations."""

    # Validate inputs
    if not query_text or len(query_text) > 10000:
        raise ValueError("Invalid query text")

    if not query_vector or len(query_vector) != 1536:  # ada-002 dimension
        raise ValueError("Invalid vector dimension")

    # Validate vector values
    if not all(isinstance(v, (int, float)) for v in query_vector):
        raise ValueError("Invalid vector values")

    # Normalize vector for consistent scoring
    vector_array = np.array(query_vector)
    normalized_vector = (vector_array / np.linalg.norm(vector_array)).tolist()

    # Build mandatory tenant filter
    tenant_filter = f"tenant_id eq '{tenant_id}'"

    # Combine with user filters safely
    if filters:
        user_filter = build_safe_odata_filter(filters)
        combined_filter = f"({tenant_filter}) and ({user_filter})"
    else:
        combined_filter = tenant_filter

    # Create vector query
    vector_query = VectorizedQuery(
        vector=normalized_vector,
        k_nearest_neighbors=min(top_k * 2, 100),  # Over-fetch for reranking
        fields="content_vector",
        exhaustive=False,  # Use HNSW index for performance
        filter_mode=VectorFilterMode.PRE_FILTER  # Filter before vector search
    )

    # Execute hybrid search
    results = client.search(
        search_text=sanitize_search_query(query_text),
        vector_queries=[vector_query],
        filter=combined_filter,
        top=min(top_k, 50),
        select=["id", "title", "content", "tenant_id"],  # Explicit field selection
        include_total_count=True
    )

    # Validate and process results
    validated_results = []
    for result in results:
        # Verify tenant isolation
        if result.get("tenant_id") != tenant_id:
            logger.error(f"Tenant leak detected: expected {tenant_id}, got {result.get('tenant_id')}")
            continue

        validated_results.append({
            "id": result["id"],
            "bm25_score": result.get("@search.score", 0),
            "title": result.get("title", ""),
            "content": result.get("content", "")
        })

    return validated_results

def build_safe_odata_filter(filters: dict) -> str:
    """Build OData filter from validated user inputs."""
    ALLOWED_FIELDS = {"category", "date", "status", "language"}
    ALLOWED_OPERATORS = {"eq", "ne", "gt", "ge", "lt", "le"}

    conditions = []

    for field, condition in filters.items():
        # Validate field
        if field not in ALLOWED_FIELDS:
            raise ValueError(f"Invalid filter field: {field}")

        if isinstance(condition, dict):
            for op, value in condition.items():
                if op not in ALLOWED_OPERATORS:
                    raise ValueError(f"Invalid operator: {op}")

                # Escape string values
                if isinstance(value, str):
                    escaped = value.replace("'", "''")
                    conditions.append(f"{field} {op} '{escaped}'")
                elif isinstance(value, (int, float, bool)):
                    conditions.append(f"{field} {op} {str(value).lower()}")
        else:
            # Simple equality
            if isinstance(condition, str):
                escaped = condition.replace("'", "''")
                conditions.append(f"{field} eq '{escaped}'")
            else:
                conditions.append(f"{field} eq {str(condition).lower()}")

    return " and ".join(conditions)

# Vector search with integrated vectorization
def secure_integrated_vector_search(
    client: SearchClient,
    query_text: str,
    tenant_id: str,
    top_k: int = 10
) -> list:
    """Use integrated vectorization (Azure handles embedding)."""
    from azure.search.documents.models import VectorizableTextQuery

    # Input validation
    if not query_text or len(query_text) > 8000:  # Token limit consideration
        raise ValueError("Invalid query text")

    # Create vectorizable query (Azure generates embedding)
    vector_query = VectorizableTextQuery(
        text=sanitize_search_query(query_text),
        k_nearest_neighbors=min(top_k, 50),
        fields="content_vector"
    )

    # Enforce tenant filter
    tenant_filter = f"tenant_id eq '{tenant_id}'"

    results = client.search(
        search_text=None,  # Vector-only search
        vector_queries=[vector_query],
        filter=tenant_filter,
        top=top_k
    )

    return process_results(results, tenant_id)
```

**Don't**: Mix unfiltered results, skip tenant validation, or use unsafe filter construction

```python
# VULNERABLE: No tenant isolation in hybrid search
def hybrid_search(client, query_text, query_vector):
    vector_query = VectorizedQuery(
        vector=query_vector,
        k_nearest_neighbors=50,
        fields="content_vector"
        # No filter_mode specified
    )

    results = client.search(
        search_text=query_text,
        vector_queries=[vector_query]
        # No filter - returns all tenants' data
    )
    return list(results)

# VULNERABLE: Unsafe OData filter construction
def search_with_filter(client, user_category):
    # OData injection vulnerability
    filter_str = f"category eq '{user_category}'"  # user_category = "' or 1 eq 1 or '"
    return client.search(search_text="*", filter=filter_str)

# VULNERABLE: Post-filter vector results (inefficient and insecure)
def insecure_hybrid(client, query_vector, tenant_id):
    vector_query = VectorizedQuery(
        vector=query_vector,
        k_nearest_neighbors=1000,  # Fetch everything
        fields="content_vector",
        filter_mode=VectorFilterMode.POST_FILTER  # Filter after - sees all data
    )

    results = client.search(vector_queries=[vector_query])
    # Client-side filtering - vector search already accessed all data
    return [r for r in results if r["tenant_id"] == tenant_id]
```

**Why**: Hybrid search combines two retrieval paths that must both enforce access controls. Pre-filtering ensures vector search only accesses authorized documents. OData injection can bypass filters and expose unauthorized data.

**Refs**: OWASP A03:2025 (Injection), CWE-89, Azure AI Search Vector Search documentation

---

## Rule: Azure OpenAI Integration

**Level**: `strict`

**When**: Connecting Azure AI Search with Azure OpenAI for integrated vectorization or semantic ranker

**Do**: Use Managed Identity for service-to-service auth, secure endpoint configuration, validate connections

```python
from azure.identity import DefaultAzureCredential
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SearchField,
    SearchFieldDataType,
    VectorSearch,
    HnswAlgorithmConfiguration,
    VectorSearchProfile,
    AzureOpenAIVectorizer,
    AzureOpenAIParameters
)
import os

def create_index_with_secure_vectorizer(
    index_client: SearchIndexClient,
    index_name: str
) -> SearchIndex:
    """Create index with secure Azure OpenAI integrated vectorization."""

    # Validate environment configuration
    aoai_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    deployment_name = os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT")

    if not aoai_endpoint or not aoai_endpoint.startswith("https://"):
        raise ValueError("Invalid Azure OpenAI endpoint")

    if not deployment_name:
        raise ValueError("Embedding deployment not configured")

    # Configure vectorizer with Managed Identity
    vectorizer = AzureOpenAIVectorizer(
        name="aoai-vectorizer",
        parameters=AzureOpenAIParameters(
            resource_uri=aoai_endpoint,
            deployment_id=deployment_name,
            model_name="text-embedding-ada-002"
            # No API key - uses Managed Identity
        )
    )

    # Define secure index schema
    fields = [
        SearchField(
            name="id",
            type=SearchFieldDataType.String,
            key=True
        ),
        SearchField(
            name="content",
            type=SearchFieldDataType.String,
            searchable=True
        ),
        SearchField(
            name="content_vector",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=1536,
            vector_search_profile_name="vector-profile"
        ),
        SearchField(
            name="tenant_id",
            type=SearchFieldDataType.String,
            filterable=True  # Required for tenant isolation
        )
    ]

    # Vector search configuration
    vector_search = VectorSearch(
        algorithms=[
            HnswAlgorithmConfiguration(
                name="hnsw-config",
                parameters={
                    "m": 4,
                    "efConstruction": 400,
                    "efSearch": 500,
                    "metric": "cosine"
                }
            )
        ],
        profiles=[
            VectorSearchProfile(
                name="vector-profile",
                algorithm_configuration_name="hnsw-config",
                vectorizer="aoai-vectorizer"
            )
        ],
        vectorizers=[vectorizer]
    )

    index = SearchIndex(
        name=index_name,
        fields=fields,
        vector_search=vector_search
    )

    return index_client.create_or_update_index(index)

# Secure configuration for skill-based vectorization
def create_embedding_skill_config() -> dict:
    """Create secure embedding skill configuration for skillset."""

    return {
        "@odata.type": "#Microsoft.Skills.Text.AzureOpenAIEmbeddingSkill",
        "name": "embedding-skill",
        "description": "Generate embeddings using Azure OpenAI",
        "resourceUri": os.environ["AZURE_OPENAI_ENDPOINT"],
        "deploymentId": os.environ["AZURE_OPENAI_EMBEDDING_DEPLOYMENT"],
        "modelName": "text-embedding-ada-002",
        # Authentication via Search service's Managed Identity
        "authIdentity": {
            "@odata.type": "#Microsoft.Azure.Search.DataUserAssignedIdentity",
            "userAssignedIdentity": os.environ["USER_ASSIGNED_IDENTITY_ID"]
        },
        "context": "/document/content",
        "inputs": [
            {"name": "text", "source": "/document/content"}
        ],
        "outputs": [
            {"name": "embedding", "targetName": "content_vector"}
        ]
    }

# Validate Azure OpenAI connection before use
def validate_aoai_connection(endpoint: str, deployment: str) -> bool:
    """Validate Azure OpenAI connection is properly configured."""
    from azure.ai.openai import AzureOpenAI

    try:
        credential = DefaultAzureCredential()
        client = AzureOpenAI(
            azure_endpoint=endpoint,
            azure_deployment=deployment,
            api_version="2024-02-15-preview",
            azure_ad_token_provider=credential.get_token
        )

        # Test connection with minimal input
        response = client.embeddings.create(
            input=["test"],
            model=deployment
        )

        if response.data and len(response.data[0].embedding) == 1536:
            return True

        return False

    except Exception as e:
        logger.error(f"Azure OpenAI validation failed: {e}")
        return False
```

**Don't**: Hardcode Azure OpenAI keys, use insecure endpoints, or skip connection validation

```python
# VULNERABLE: Hardcoded Azure OpenAI API key
vectorizer = AzureOpenAIVectorizer(
    name="aoai-vectorizer",
    parameters=AzureOpenAIParameters(
        resource_uri="https://myaoai.openai.azure.com",
        deployment_id="ada-002",
        api_key="sk-abc123xyz789"  # Hardcoded key
    )
)

# VULNERABLE: HTTP endpoint (not HTTPS)
vectorizer = AzureOpenAIVectorizer(
    name="aoai-vectorizer",
    parameters=AzureOpenAIParameters(
        resource_uri="http://myaoai.openai.azure.com",  # Not encrypted
        deployment_id="ada-002"
    )
)

# VULNERABLE: No validation of Azure OpenAI configuration
def create_index(index_client, index_name):
    # Assumes Azure OpenAI is configured correctly
    # No validation before creating index
    return index_client.create_index(index)
```

**Why**: Azure OpenAI API keys provide full access to embedding and completion models. Exposed keys enable attackers to generate malicious content or exhaust quotas. Managed Identity provides secure, credential-free authentication between Azure services.

**Refs**: OWASP A07:2025 (Identification and Authentication Failures), CWE-798, Azure OpenAI Security Best Practices

---

## Rule: Index Schema Security

**Level**: `warning`

**When**: Defining index schemas with fields and analyzers

**Do**: Mark sensitive fields appropriately, use security-aware analyzers, validate field types

```python
from azure.search.documents.indexes.models import (
    SearchIndex,
    SearchField,
    SearchFieldDataType,
    SearchableField,
    SimpleField,
    LexicalAnalyzerName
)

def create_secure_index_schema(index_name: str) -> SearchIndex:
    """Create index with security-conscious field configuration."""

    fields = [
        # Key field
        SimpleField(
            name="id",
            type=SearchFieldDataType.String,
            key=True
        ),

        # Searchable content with appropriate analyzer
        SearchableField(
            name="content",
            type=SearchFieldDataType.String,
            searchable=True,
            analyzer_name=LexicalAnalyzerName.STANDARD_LUCENE
        ),

        # Tenant isolation field - MUST be filterable
        SimpleField(
            name="tenant_id",
            type=SearchFieldDataType.String,
            filterable=True,  # Required for security filtering
            facetable=False   # Don't expose tenant list
        ),

        # Sensitive metadata - not searchable or retrievable by default
        SimpleField(
            name="internal_classification",
            type=SearchFieldDataType.String,
            filterable=True,
            searchable=False,   # Don't include in full-text search
            retrievable=False,  # Don't return in results
            hidden=True
        ),

        # Date fields with proper typing
        SimpleField(
            name="created_date",
            type=SearchFieldDataType.DateTimeOffset,
            filterable=True,
            sortable=True
        ),

        # User-facing metadata
        SearchableField(
            name="title",
            type=SearchFieldDataType.String,
            searchable=True
        ),

        # Tags with collection type
        SearchField(
            name="tags",
            type=SearchFieldDataType.Collection(SearchFieldDataType.String),
            filterable=True,
            facetable=True
        ),

        # Vector field
        SearchField(
            name="content_vector",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=1536,
            vector_search_profile_name="vector-profile"
        ),

        # Access control list for document-level security
        SearchField(
            name="allowed_groups",
            type=SearchFieldDataType.Collection(SearchFieldDataType.String),
            filterable=True,
            searchable=False
        )
    ]

    return SearchIndex(
        name=index_name,
        fields=fields,
        # Additional configurations...
    )

# Document-level security filtering
def search_with_document_security(
    client: SearchClient,
    query: str,
    user_groups: list,
    tenant_id: str
) -> list:
    """Search with document-level security trimming."""

    # Build security filter
    group_filters = " or ".join([
        f"allowed_groups/any(g: g eq '{group}')"
        for group in user_groups
    ])

    security_filter = f"tenant_id eq '{tenant_id}' and ({group_filters})"

    results = client.search(
        search_text=query,
        filter=security_filter,
        select=["id", "title", "content"]  # Explicit field selection
    )

    return list(results)

# Validate index schema security
def validate_index_security(index: SearchIndex) -> list:
    """Check index schema for security issues."""
    issues = []

    # Check for tenant isolation field
    tenant_field = next(
        (f for f in index.fields if f.name == "tenant_id"),
        None
    )
    if not tenant_field:
        issues.append("Missing tenant_id field for isolation")
    elif not tenant_field.filterable:
        issues.append("tenant_id field must be filterable")

    # Check for sensitive fields exposure
    for field in index.fields:
        if any(keyword in field.name.lower() for keyword in
               ["password", "secret", "key", "token", "ssn", "credit"]):
            if field.searchable:
                issues.append(f"Sensitive field '{field.name}' should not be searchable")
            if field.retrievable != False:
                issues.append(f"Sensitive field '{field.name}' should be hidden")

    return issues
```

**Don't**: Make sensitive fields searchable, skip tenant isolation fields, or expose internal metadata

```python
# VULNERABLE: Sensitive data in searchable fields
fields = [
    SearchableField(
        name="user_ssn",
        type=SearchFieldDataType.String,
        searchable=True  # SSN searchable!
    ),
    SearchableField(
        name="internal_notes",
        type=SearchFieldDataType.String,
        searchable=True,
        retrievable=True  # Internal notes exposed
    )
]

# VULNERABLE: No tenant isolation capability
fields = [
    SearchableField(name="content", ...),
    # No tenant_id field - cannot filter by tenant
]

# VULNERABLE: Exposing classification metadata
fields = [
    SimpleField(
        name="security_classification",
        type=SearchFieldDataType.String,
        filterable=True,
        facetable=True,  # Exposes all classification levels
        retrievable=True  # Returns in results
    )
]
```

**Why**: Index schema determines what can be searched, filtered, and returned. Sensitive fields must be marked non-searchable and non-retrievable. Facetable fields expose distinct values to users. Tenant isolation requires filterable fields.

**Refs**: OWASP A01:2025 (Broken Access Control), CWE-200, Azure AI Search Field Attributes documentation

---

## Rule: Skillset Security

**Level**: `warning`

**When**: Creating skillsets with built-in or custom skills for enrichment

**Do**: Validate custom skill endpoints, secure cognitive service keys, limit skill permissions

```python
from azure.search.documents.indexes import SearchIndexerClient
from azure.search.documents.indexes.models import (
    SearchIndexerSkillset,
    OcrSkill,
    SplitSkill,
    WebApiSkill,
    CognitiveServicesAccountKey
)
import os

def create_secure_skillset(
    indexer_client: SearchIndexerClient,
    skillset_name: str
) -> SearchIndexerSkillset:
    """Create skillset with security best practices."""

    # Built-in OCR skill with cognitive services
    ocr_skill = OcrSkill(
        name="ocr-skill",
        description="Extract text from images",
        context="/document/normalized_images/*",
        inputs=[
            {"name": "image", "source": "/document/normalized_images/*"}
        ],
        outputs=[
            {"name": "text", "targetName": "extractedText"}
        ]
    )

    # Text splitting skill
    split_skill = SplitSkill(
        name="split-skill",
        description="Split text into chunks",
        context="/document",
        text_split_mode="pages",
        maximum_page_length=2000,
        page_overlap_length=200,
        inputs=[
            {"name": "text", "source": "/document/content"}
        ],
        outputs=[
            {"name": "textItems", "targetName": "chunks"}
        ]
    )

    # Custom Web API skill with security validation
    custom_skill = create_secure_custom_skill()

    # Cognitive services configuration
    cognitive_services = None
    cog_key = os.environ.get("COGNITIVE_SERVICES_KEY")
    if cog_key:
        cognitive_services = CognitiveServicesAccountKey(
            key=cog_key  # From environment, not hardcoded
        )

    skillset = SearchIndexerSkillset(
        name=skillset_name,
        skills=[ocr_skill, split_skill, custom_skill],
        cognitive_services_account=cognitive_services,
        description="Secure document processing skillset"
    )

    return indexer_client.create_or_update_skillset(skillset)

def create_secure_custom_skill() -> WebApiSkill:
    """Create custom Web API skill with security validation."""

    # Validate custom skill endpoint
    custom_endpoint = os.environ.get("CUSTOM_SKILL_ENDPOINT")

    if not custom_endpoint:
        raise ValueError("Custom skill endpoint not configured")

    if not custom_endpoint.startswith("https://"):
        raise ValueError("Custom skill endpoint must use HTTPS")

    # Validate endpoint is in allowed list
    allowed_domains = os.environ.get("ALLOWED_SKILL_DOMAINS", "").split(",")
    endpoint_domain = custom_endpoint.split("/")[2]

    if endpoint_domain not in allowed_domains:
        raise ValueError(f"Custom skill domain not allowed: {endpoint_domain}")

    return WebApiSkill(
        name="custom-enrichment",
        description="Custom enrichment skill",
        uri=custom_endpoint,
        http_method="POST",
        timeout="PT60S",  # 60 second timeout
        batch_size=10,
        degree_of_parallelism=5,
        # Use managed identity for auth to custom skill
        auth_identity={
            "@odata.type": "#Microsoft.Azure.Search.DataUserAssignedIdentity",
            "userAssignedIdentity": os.environ["USER_ASSIGNED_IDENTITY_ID"]
        },
        context="/document",
        inputs=[
            {"name": "text", "source": "/document/content"}
        ],
        outputs=[
            {"name": "enriched", "targetName": "customEnrichment"}
        ]
    )

# Validate skillset before deployment
def validate_skillset_security(skillset: SearchIndexerSkillset) -> list:
    """Check skillset for security issues."""
    issues = []

    for skill in skillset.skills:
        # Check custom skills
        if isinstance(skill, WebApiSkill):
            if not skill.uri.startswith("https://"):
                issues.append(f"Custom skill '{skill.name}' uses insecure HTTP")

            if skill.http_headers:
                for header in skill.http_headers:
                    if "key" in header.name.lower() or "auth" in header.name.lower():
                        issues.append(f"Custom skill '{skill.name}' has auth in headers (use managed identity)")

    return issues

# Monitor custom skill calls
def audit_custom_skill_execution(skill_name: str, endpoint: str,
                                  input_count: int, success: bool):
    """Audit custom skill executions."""
    audit_logger.info(
        "custom_skill_execution",
        extra={
            "skill_name": skill_name,
            "endpoint_domain": endpoint.split("/")[2],
            "input_count": input_count,
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

**Don't**: Use HTTP endpoints for custom skills, hardcode cognitive service keys, or skip validation

```python
# VULNERABLE: Custom skill with HTTP endpoint
custom_skill = WebApiSkill(
    name="custom",
    uri="http://my-function.azurewebsites.net/api/enrich",  # Not HTTPS
    ...
)

# VULNERABLE: Hardcoded cognitive services key
cognitive_services = CognitiveServicesAccountKey(
    key="abc123xyz789"  # Hardcoded
)

# VULNERABLE: API key in custom skill headers
custom_skill = WebApiSkill(
    name="custom",
    uri="https://api.example.com/enrich",
    http_headers={"api-key": "hardcoded-key"},  # Exposed
    ...
)

# VULNERABLE: No validation of custom skill endpoint
def create_skill(user_provided_url):
    return WebApiSkill(
        uri=user_provided_url  # SSRF vulnerability
    )
```

**Why**: Custom skills execute arbitrary code with access to indexed content. Insecure endpoints can leak data or be exploited via SSRF. Cognitive service keys grant access to expensive AI services. Managed Identity eliminates credential exposure.

**Refs**: OWASP A10:2025 (Server-Side Request Forgery), CWE-918, Azure AI Search Skills documentation

---

## Rule: Data Source Connection

**Level**: `strict`

**When**: Configuring data sources for indexers (Blob Storage, SQL, Cosmos DB)

**Do**: Use Managed Identity, secure connection strings in Key Vault, validate data source access

```python
from azure.search.documents.indexes import SearchIndexerClient
from azure.search.documents.indexes.models import (
    SearchIndexerDataSourceConnection,
    SearchIndexerDataContainer
)
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import os

def create_secure_blob_datasource(
    indexer_client: SearchIndexerClient,
    datasource_name: str,
    container_name: str
) -> SearchIndexerDataSourceConnection:
    """Create Blob Storage data source with Managed Identity."""

    storage_account = os.environ["STORAGE_ACCOUNT_NAME"]
    resource_id = os.environ["STORAGE_RESOURCE_ID"]

    # Connection string using Managed Identity
    connection_string = (
        f"ResourceId={resource_id};"
        f"Storage={storage_account}"
    )

    datasource = SearchIndexerDataSourceConnection(
        name=datasource_name,
        type="azureblob",
        connection_string=connection_string,
        container=SearchIndexerDataContainer(
            name=container_name,
            query=None  # Index entire container
        ),
        identity={
            "@odata.type": "#Microsoft.Azure.Search.DataUserAssignedIdentity",
            "userAssignedIdentity": os.environ["USER_ASSIGNED_IDENTITY_ID"]
        }
    )

    return indexer_client.create_or_update_data_source_connection(datasource)

def create_secure_sql_datasource(
    indexer_client: SearchIndexerClient,
    datasource_name: str
) -> SearchIndexerDataSourceConnection:
    """Create SQL data source with Key Vault connection string."""

    # Retrieve connection string from Key Vault
    credential = DefaultAzureCredential()
    keyvault_uri = os.environ["KEYVAULT_URI"]
    secret_name = os.environ["SQL_CONNECTION_STRING_SECRET"]

    secret_client = SecretClient(
        vault_url=keyvault_uri,
        credential=credential
    )

    connection_string = secret_client.get_secret(secret_name).value

    # Validate connection string format (basic check)
    if "Password=" in connection_string:
        logger.warning("Consider using Managed Identity instead of SQL password")

    datasource = SearchIndexerDataSourceConnection(
        name=datasource_name,
        type="azuresql",
        connection_string=connection_string,
        container=SearchIndexerDataContainer(
            name="documents",  # Table or view name
            query="SELECT * FROM documents WHERE is_deleted = 0"  # Filter deleted
        )
    )

    return indexer_client.create_or_update_data_source_connection(datasource)

def create_cosmosdb_datasource_with_identity(
    indexer_client: SearchIndexerClient,
    datasource_name: str
) -> SearchIndexerDataSourceConnection:
    """Create Cosmos DB data source with Managed Identity."""

    cosmos_endpoint = os.environ["COSMOS_ENDPOINT"]
    database_name = os.environ["COSMOS_DATABASE"]

    # Connection string for Managed Identity
    connection_string = (
        f"AccountEndpoint={cosmos_endpoint};"
        f"Database={database_name}"
    )

    datasource = SearchIndexerDataSourceConnection(
        name=datasource_name,
        type="cosmosdb",
        connection_string=connection_string,
        container=SearchIndexerDataContainer(
            name="documents",
            query="SELECT * FROM c WHERE c._ts > @HighWaterMark ORDER BY c._ts"
        ),
        identity={
            "@odata.type": "#Microsoft.Azure.Search.DataUserAssignedIdentity",
            "userAssignedIdentity": os.environ["USER_ASSIGNED_IDENTITY_ID"]
        },
        data_change_detection_policy={
            "@odata.type": "#Microsoft.Azure.Search.HighWaterMarkChangeDetectionPolicy",
            "highWaterMarkColumnName": "_ts"
        }
    )

    return indexer_client.create_or_update_data_source_connection(datasource)

# Validate data source security configuration
def validate_datasource_security(datasource: SearchIndexerDataSourceConnection) -> list:
    """Check data source for security issues."""
    issues = []

    # Check for embedded credentials
    conn_str = datasource.connection_string or ""

    if "AccountKey=" in conn_str:
        issues.append("Storage account key in connection string (use Managed Identity)")

    if "Password=" in conn_str and "Managed Identity" not in conn_str:
        issues.append("SQL password in connection string (use Managed Identity)")

    # Check for identity configuration
    if not datasource.identity and "ResourceId=" not in conn_str:
        issues.append("No Managed Identity configured for data source")

    # Check for overly broad queries
    if datasource.container and datasource.container.query:
        query = datasource.container.query.upper()
        if "SELECT *" in query and "WHERE" not in query:
            issues.append("Data source query selects all data without filter")

    return issues

# Audit data source access
def audit_datasource_creation(datasource_name: str, datasource_type: str,
                               uses_identity: bool):
    """Audit data source creation."""
    audit_logger.info(
        "datasource_created",
        extra={
            "datasource_name": datasource_name,
            "type": datasource_type,
            "uses_managed_identity": uses_identity,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

**Don't**: Embed credentials in connection strings, store secrets in code, or skip access validation

```python
# VULNERABLE: Hardcoded storage account key
datasource = SearchIndexerDataSourceConnection(
    name="blob-source",
    type="azureblob",
    connection_string=(
        "DefaultEndpointsProtocol=https;"
        "AccountName=mystorage;"
        "AccountKey=abc123xyz789=="  # Hardcoded key
    ),
    ...
)

# VULNERABLE: SQL password in connection string
datasource = SearchIndexerDataSourceConnection(
    name="sql-source",
    type="azuresql",
    connection_string=(
        "Server=myserver.database.windows.net;"
        "Database=mydb;"
        "User=admin;"
        "Password=SuperSecret123!"  # Password in code
    ),
    ...
)

# VULNERABLE: Cosmos DB with hardcoded key
datasource = SearchIndexerDataSourceConnection(
    name="cosmos-source",
    type="cosmosdb",
    connection_string=(
        f"AccountEndpoint=https://mycosmos.documents.azure.com:443/;"
        f"AccountKey=abc123xyz789==;"  # Hardcoded
        f"Database=mydb"
    ),
    ...
)

# VULNERABLE: No query filter - indexes everything
datasource = SearchIndexerDataSourceConnection(
    container=SearchIndexerDataContainer(
        name="alldocuments",
        query=None  # No filter - includes deleted/sensitive data
    )
)
```

**Why**: Connection strings with embedded keys can be extracted from Azure Resource Manager, logs, or error messages. Compromised keys grant full access to underlying data stores. Managed Identity eliminates credential exposure and enables automatic key rotation.

**Refs**: OWASP A07:2025 (Identification and Authentication Failures), CWE-798, CWE-312, Azure AI Search Indexer Connections documentation

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-15 | Initial release with 7 core rules |

---

## Additional Resources

- [Azure AI Search Security Overview](https://learn.microsoft.com/en-us/azure/search/search-security-overview)
- [Azure AI Search RBAC](https://learn.microsoft.com/en-us/azure/search/search-security-rbac)
- [Azure AI Search Managed Identity](https://learn.microsoft.com/en-us/azure/search/search-howto-managed-identities-data-sources)
- [Azure OpenAI Service Security](https://learn.microsoft.com/en-us/azure/cognitive-services/openai/how-to/managed-identity)
- [OWASP Top 10 2025](https://owasp.org/Top10/)
