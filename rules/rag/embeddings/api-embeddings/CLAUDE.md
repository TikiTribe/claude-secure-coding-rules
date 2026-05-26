# API-Based Embeddings Security Rules

Security patterns for cloud embedding APIs: OpenAI, Cohere, Voyage AI, and Jina.

## Quick Reference

| Rule | Level | Provider | Trigger |
|------|-------|----------|---------|
| API Key Security | `strict` | All | Any API-based embedding usage |
| PII Redaction Before API Send | `strict` | All | Any text sent to third-party embedding API |
| Per-Tenant API Key Isolation | `strict` | All | Multi-tenant / SaaS deployments |
| Data Residency and Vendor Retention | `strict` | All | DPA scope, cross-border data |
| Model Selection Security | `warning` | OpenAI | Model configuration |
| Batch Processing Security | `warning` | OpenAI | Bulk embedding operations |
| Input Type Validation | `warning` | Cohere | Search/retrieval embedding |
| Compression-Aware Security | `warning` | Cohere | Compressed embedding types |
| Domain Model Security | `warning` | Voyage | Domain-specific embeddings |
| Long Context Security | `warning` | Jina | Documents >4K tokens |
| Rate Limiting Implementation | `strict` | All | Production API usage |
| Cost Tracking and Alerts | `warning` | All | Paid API usage |
| Response Validation | `warning` | All | Any embedding response |

**Prerequisites**: See `rules/rag/_core/embedding-security.md` for foundational patterns.

---

## Rule: API Key Security

**Level**: `strict`

**When**: Using any cloud embedding API (OpenAI, Cohere, Voyage, Jina)

**Do**: Use environment variables with organization scoping and secret rotation

```python
import os
from typing import Optional
from functools import cached_property

class SecureEmbeddingClients:
    """Secure API client initialization for multiple providers."""

    @cached_property
    def openai(self):
        """OpenAI client with organization scoping."""
        from openai import OpenAI

        api_key = os.environ.get("OPENAI_API_KEY")
        org_id = os.environ.get("OPENAI_ORG_ID")

        if not api_key:
            raise ValueError("OPENAI_API_KEY not configured in environment")

        # Organization ID scopes API key to specific org.
        # Prevents cross-org billing and access.
        return OpenAI(
            api_key=api_key,
            organization=org_id,
            timeout=30.0,
            max_retries=3
        )

    @cached_property
    def cohere(self):
        """Cohere client with secure initialization."""
        import cohere

        api_key = os.environ.get("COHERE_API_KEY")
        if not api_key:
            raise ValueError("COHERE_API_KEY not configured in environment")

        return cohere.Client(
            api_key=api_key,
            timeout=30
        )

    @cached_property
    def voyage(self):
        """Voyage AI client with secure initialization."""
        import voyageai

        api_key = os.environ.get("VOYAGE_API_KEY")
        if not api_key:
            raise ValueError("VOYAGE_API_KEY not configured in environment")

        return voyageai.Client(api_key=api_key)

    @cached_property
    def jina(self):
        """Jina embeddings client with secure initialization."""
        import requests

        api_key = os.environ.get("JINA_API_KEY")
        if not api_key:
            raise ValueError("JINA_API_KEY not configured in environment")

        return {
            "base_url": "https://api.jina.ai/v1/embeddings",
            "headers": {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
        }


# Production usage with secrets manager
def load_api_key_from_vault(secret_name: str) -> str:
    """Load API key from HashiCorp Vault or AWS Secrets Manager."""
    try:
        import boto3
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except Exception:
        # Fallback to environment variable
        return os.environ.get(secret_name.upper().replace("-", "_"), "")
```

**Don't**: Hardcode keys, log them, or skip organization scoping

```python
# VULNERABLE: Hardcoded API key
client = OpenAI(api_key="sk-proj-abc123xyz...")

# VULNERABLE: No organization scoping (bills to default org)
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
# Without org_id, key could be used across orgs

# VULNERABLE: Key exposure in error handling
try:
    response = client.embeddings.create(...)
except Exception as e:
    logger.error(f"Failed with key {api_key}: {e}")  # Key in logs

# VULNERABLE: Key in configuration files
config = {"openai_key": "sk-proj-..."}  # Will be committed to git
```

**Why**: Exposed API keys enable unauthorized access, cost abuse, and data exfiltration. Organization scoping prevents cross-org billing and limits blast radius. Attackers actively scan repositories and logs for leaked credentials.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-532 (Log Exposure), OWASP LLM06:2025 (Sensitive Information Disclosure)

---

## Rule: PII Redaction Before API Send

**Level**: `strict`

**When**: Sending any text to a third-party embedding API (OpenAI, Cohere, Voyage, Jina)

**Do**: Scan and redact PII before the text leaves your trust boundary

```python
from typing import List
import logging

logger = logging.getLogger(__name__)

def redact_pii(texts: List[str]) -> List[str]:
    """
    Redact PII from texts using Microsoft Presidio before sending to
    any third-party embedding API. Raises on error rather than silently
    forwarding raw text.
    """
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine
    except ImportError:
        raise RuntimeError(
            "presidio-analyzer and presidio-anonymizer are required. "
            "Install: pip install presidio-analyzer presidio-anonymizer"
        )

    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    redacted = []
    for text in texts:
        results = analyzer.analyze(
            text=text,
            entities=[
                "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                "CREDIT_CARD", "US_SSN", "IBAN_CODE",
                "IP_ADDRESS", "LOCATION", "DATE_TIME",
                "NRP",  # Nationality, religion, political group
            ],
            language="en"
        )

        if results:
            logger.info(
                "PII detected and redacted before embedding API call: "
                "%d entities across %d characters",
                len(results), len(text)
            )

        anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
        redacted.append(anonymized.text)

    return redacted


def embed_with_pii_redaction(
    texts: List[str],
    embed_fn,
    skip_redaction: bool = False
) -> list:
    """
    Wrapper that enforces PII redaction before any embedding API call.
    Set skip_redaction=True only for clearly non-personal corpora (e.g.,
    public documentation) and document the justification at call sites.
    """
    if skip_redaction:
        logger.warning(
            "PII redaction bypassed — confirm corpus contains no personal data"
        )
        clean_texts = texts
    else:
        clean_texts = redact_pii(texts)

    return embed_fn(clean_texts)
```

**Don't**: Send raw user-supplied or document text to third-party APIs without scanning

```python
# VULNERABLE: Raw PII forwarded to OpenAI
response = client.embeddings.create(
    model="text-embedding-3-small",
    input=user_documents  # May contain SSNs, emails, medical data
)

# VULNERABLE: Redaction only in logging, not in API payload
logger.info("Embedding: %s", redact_for_log(text))
client.embed(text)  # Original PII still sent

# VULNERABLE: Regex-only redaction misses entity types
import re
clean = re.sub(r"\d{3}-\d{2}-\d{4}", "[SSN]", text)
client.embed(clean)  # Misses names, locations, account numbers
```

**Why**: Text sent to third-party APIs leaves your trust boundary and may be used for provider training, stored in provider logs, or disclosed in a breach. GDPR Art. 28, HIPAA, and most DPAs restrict cross-boundary transfer of personal data without a lawful basis and appropriate controls. NER-based redaction (Presidio) catches structured and unstructured PII that regex cannot.

**Refs**: OWASP LLM06:2025 (Sensitive Information Disclosure), CWE-200 (Exposure of Sensitive Information), GDPR Art. 28 (Processor obligations), NIST AI RMF (GOVERN 6.1)

---

## Rule: Per-Tenant API Key Isolation

**Level**: `strict`

**When**: Building multi-tenant or SaaS applications that embed text on behalf of multiple customers

**Do**: Issue a separate API key (or project-scoped key) per tenant and enforce key-to-tenant binding at request time

```python
import os
from typing import Optional
from functools import lru_cache

class TenantKeyStore:
    """
    Resolves the correct API key for each tenant.
    Backed by a secrets manager; never stores keys in application memory
    beyond the scope of a single request.
    """

    def __init__(self, secrets_backend: str = "aws"):
        self.secrets_backend = secrets_backend

    def get_key(self, tenant_id: str, provider: str) -> str:
        """
        Fetch tenant-specific API key from the secrets manager.
        Secret naming convention: embedding/{provider}/{tenant_id}
        """
        if not tenant_id or "/" in tenant_id:
            raise ValueError(f"Invalid tenant_id: {tenant_id!r}")

        secret_name = f"embedding/{provider}/{tenant_id}"

        if self.secrets_backend == "aws":
            import boto3
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_name)
            return response["SecretString"]

        if self.secrets_backend == "vault":
            import hvac
            vault = hvac.Client(url=os.environ["VAULT_ADDR"])
            secret = vault.secrets.kv.v2.read_secret_version(
                path=f"embedding/{provider}/{tenant_id}"
            )
            return secret["data"]["data"]["api_key"]

        raise ValueError(f"Unknown secrets backend: {self.secrets_backend}")


class TenantScopedEmbedder:
    """
    Embedder that binds each request to the requesting tenant's own API key.
    Prevents key sharing across tenant boundaries.
    """

    def __init__(self, key_store: TenantKeyStore, provider: str = "openai"):
        self.key_store = key_store
        self.provider = provider

    def embed(
        self,
        texts: list[str],
        tenant_id: str
    ) -> list[list[float]]:
        """Embed using only the key allocated to tenant_id."""
        api_key = self.key_store.get_key(tenant_id, self.provider)

        if self.provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            response = client.embeddings.create(
                model="text-embedding-3-small",
                input=texts
            )
            return [e.embedding for e in response.data]

        raise ValueError(f"Unsupported provider: {self.provider}")
```

**Don't**: Share a single org-level key across all tenants

```python
# VULNERABLE: One key for all tenants — cost, quota, and audit conflation
OPENAI_KEY = os.environ["OPENAI_API_KEY"]

def embed_for_tenant(texts, tenant_id):
    client = OpenAI(api_key=OPENAI_KEY)  # Same key regardless of tenant
    return client.embeddings.create(model="text-embedding-3-small", input=texts)

# VULNERABLE: Tenant passed as metadata only — key still shared
def embed_for_tenant(texts, tenant_id):
    response = shared_client.embeddings.create(
        model="text-embedding-3-small",
        input=texts,
        user=tenant_id  # Metadata only; does not isolate spend or quota
    )
```

**Why**: A shared key means one tenant's data is billed against another's quota, rate-limit exhaustion by one tenant disrupts others, and a compromised key exposes all tenants. Per-tenant keys allow independent revocation, quota management, and audit attribution. Org-level scoping alone does not prevent cross-tenant blast radius.

**Refs**: OWASP LLM06:2025 (Sensitive Information Disclosure), CWE-284 (Improper Access Control), NIST SP 800-204B (API security), SOC 2 CC6.1 (Logical access controls)

---

## Rule: Data Residency and Vendor Retention

**Level**: `strict`

**When**: Sending text to any third-party embedding API, especially under GDPR, HIPAA, or data sovereignty requirements

**Do**: Review provider DPA, configure data residency options, and set retention to zero where available

```python
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class ProviderDataPolicy:
    """
    Documented data-handling properties for an embedding provider.
    Populate from the provider's DPA and API documentation.
    Update when you renew or renegotiate the DPA.
    """
    provider: str
    dpa_url: str
    # Regions where data is processed; None = provider chooses
    processing_regions: list[str]
    # Days provider retains request data; 0 = no retention claimed
    retention_days: int
    # Whether training opt-out is available and configured
    training_opt_out: bool
    # SCCs or equivalent in place for cross-border transfers
    cross_border_mechanism: Optional[str]
    # Date this entry was last verified against provider docs
    last_verified: str


# Keep this registry in version control and review on each DPA renewal.
PROVIDER_POLICIES: dict[str, ProviderDataPolicy] = {
    "openai": ProviderDataPolicy(
        provider="openai",
        dpa_url="https://openai.com/policies/data-processing-addendum",
        processing_regions=["US"],
        retention_days=30,   # Verify current value in DPA
        training_opt_out=True,
        cross_border_mechanism="SCCs",
        last_verified="2025-04-01"
    ),
    "cohere": ProviderDataPolicy(
        provider="cohere",
        dpa_url="https://cohere.com/data-processing-agreement",
        processing_regions=["US", "EU"],
        retention_days=30,
        training_opt_out=True,
        cross_border_mechanism="SCCs",
        last_verified="2025-04-01"
    ),
    "voyage": ProviderDataPolicy(
        provider="voyage",
        dpa_url="https://www.voyageai.com/privacy",
        processing_regions=["US"],
        retention_days=30,
        training_opt_out=True,
        cross_border_mechanism="SCCs",
        last_verified="2025-04-01"
    ),
    "jina": ProviderDataPolicy(
        provider="jina",
        dpa_url="https://jina.ai/privacy-policy",
        processing_regions=["EU", "US"],
        retention_days=0,
        training_opt_out=True,
        cross_border_mechanism="SCCs",
        last_verified="2025-04-01"
    ),
}


def assert_residency_compliant(
    provider: str,
    allowed_regions: list[str],
    require_training_opt_out: bool = True,
    max_retention_days: int = 0,
) -> None:
    """
    Raise if the provider policy does not satisfy the caller's requirements.
    Call this at service startup, not per-request, to catch misconfigurations
    before any data is sent.
    """
    policy = PROVIDER_POLICIES.get(provider)
    if policy is None:
        raise ValueError(
            f"No data policy on record for provider '{provider}'. "
            "Add an entry to PROVIDER_POLICIES before use."
        )

    disallowed = [r for r in policy.processing_regions if r not in allowed_regions]
    if disallowed:
        raise RuntimeError(
            f"Provider '{provider}' processes data in {disallowed}, "
            f"which are outside allowed regions {allowed_regions}. "
            "Use a provider with a compliant region or add a cross-border mechanism."
        )

    if require_training_opt_out and not policy.training_opt_out:
        raise RuntimeError(
            f"Provider '{provider}' does not offer training opt-out. "
            "Configure the opt-out header/flag or choose a different provider."
        )

    if policy.retention_days > max_retention_days:
        raise RuntimeError(
            f"Provider '{provider}' retains data for {policy.retention_days} days, "
            f"exceeding the allowed maximum of {max_retention_days} days. "
            "Negotiate zero-retention terms or redact before sending."
        )

    logger.info(
        "Data residency check passed for provider '%s' (regions=%s, "
        "retention=%d days, opt-out=%s, last_verified=%s)",
        provider,
        policy.processing_regions,
        policy.retention_days,
        policy.training_opt_out,
        policy.last_verified,
    )
```

**Don't**: Send data to a provider without verifying residency and retention terms

```python
# VULNERABLE: No residency check; EU personal data may flow to non-adequate country
response = openai_client.embeddings.create(
    model="text-embedding-3-small",
    input=eu_customer_documents
)

# VULNERABLE: Relying on provider default; may enable training on your data
response = cohere_client.embed(
    texts=confidential_texts,
    model="embed-english-v3.0"
    # No opt-out flag; provider may use data for model improvement
)

# VULNERABLE: Assuming zero retention without verifying the DPA
for doc in sensitive_docs:
    client.embed(doc)  # Retention terms unchecked; data may persist 30+ days
```

**Why**: Third-party embedding APIs receive your plaintext. If the provider stores it, trains on it, or processes it in a jurisdiction outside your DPA scope, you incur regulatory liability (GDPR Art. 46 cross-border transfers, HIPAA BA requirements). Zero-retention and training opt-out eliminate the residual risk; where those are unavailable, redact first (see PII Redaction rule).

**Refs**: OWASP LLM06:2025 (Sensitive Information Disclosure), GDPR Art. 46 (Cross-border transfers), HIPAA § 164.308(b) (Business associate contracts), NIST AI RMF (GOVERN 6.2)

---

## Rule: Model Selection Security

**Level**: `warning`

**When**: Configuring OpenAI embedding models

**Do**: Pin to a current, supported model and validate output dimensions

```python
from dataclasses import dataclass
from typing import List
import hashlib

@dataclass
class OpenAIEmbeddingConfig:
    """Secure OpenAI embedding configuration with version pinning."""
    model: str
    dimensions: int
    max_input_tokens: int

    # Current supported models.
    # text-embedding-ada-002 was retired by OpenAI in April 2025;
    # migrate existing indexes to text-embedding-3-small or text-embedding-3-large.
    MODELS = {
        "text-embedding-3-small": {"dimensions": 1536, "max_tokens": 8191},
        "text-embedding-3-large": {"dimensions": 3072, "max_tokens": 8191},
    }

    def __post_init__(self):
        if self.model not in self.MODELS:
            raise ValueError(f"Unknown model: {self.model}. Supported: {list(self.MODELS.keys())}")

        expected = self.MODELS[self.model]
        if self.dimensions != expected["dimensions"]:
            raise ValueError(
                f"Dimension mismatch for {self.model}: "
                f"got {self.dimensions}, expected {expected['dimensions']}"
            )

    @property
    def fingerprint(self) -> str:
        """Version fingerprint for index compatibility tracking."""
        return hashlib.sha256(
            f"openai:{self.model}:{self.dimensions}".encode()
        ).hexdigest()[:16]


def create_openai_embeddings(
    texts: List[str],
    client,
    config: OpenAIEmbeddingConfig
) -> dict:
    """Create embeddings with dimension validation."""

    # Validate input length
    for i, text in enumerate(texts):
        # Rough token estimate: 4 chars per token
        estimated_tokens = len(text) // 4
        if estimated_tokens > config.max_input_tokens:
            raise ValueError(
                f"Text {i} exceeds max tokens: ~{estimated_tokens} > {config.max_input_tokens}"
            )

    response = client.embeddings.create(
        model=config.model,
        input=texts,
        encoding_format="float"
    )

    embeddings = [e.embedding for e in response.data]

    # Validate output dimensions
    for i, emb in enumerate(embeddings):
        if len(emb) != config.dimensions:
            raise ValueError(
                f"Unexpected dimension for embedding {i}: "
                f"got {len(emb)}, expected {config.dimensions}"
            )

    return {
        "embeddings": embeddings,
        "model_fingerprint": config.fingerprint,
        "usage": {
            "prompt_tokens": response.usage.prompt_tokens,
            "total_tokens": response.usage.total_tokens
        }
    }


# Usage
config = OpenAIEmbeddingConfig(
    model="text-embedding-3-small",
    dimensions=1536,
    max_input_tokens=8191
)

result = create_openai_embeddings(texts, client, config)
```

**Don't**: Use retired models or skip dimension validation

```python
# VULNERABLE: text-embedding-ada-002 was retired April 2025 — requests will fail
embeddings = client.embeddings.create(
    model="text-embedding-ada-002",
    input=texts
)

# VULNERABLE: No dimension validation
embedding = response.data[0].embedding
vector_store.add(embedding)  # Dimension mismatch breaks retrieval

# VULNERABLE: Hardcoded dimensions without verification
EMBEDDING_DIM = 1536  # Assumed, not verified
index = faiss.IndexFlatL2(EMBEDDING_DIM)  # May not match actual output
```

**Why**: OpenAI retired `text-embedding-ada-002` in April 2025; calls to it will fail in production. `text-embedding-3-small` delivers equal or better quality at lower cost. Dimension mismatches cause silent retrieval failures as embeddings map to wrong vector space indices.

**Refs**: CWE-1188 (Insecure Default Initialization), NIST AI RMF (Version Control), OWASP LLM04:2025 (Model Misconfiguration)

---

## Rule: Batch Processing Security

**Level**: `warning`

**When**: Performing bulk OpenAI embedding operations

**Do**: Implement batch size limits, timeouts, and partial failure handling

```python
from typing import List, Tuple
import time

class SecureBatchEmbedder:
    """Secure batch embedding with size limits and timeout handling."""

    # OpenAI limits
    MAX_BATCH_SIZE = 2048  # Maximum texts per request
    MAX_TOTAL_TOKENS = 8191 * 100  # Rough total token limit

    def __init__(self, client, config: OpenAIEmbeddingConfig):
        self.client = client
        self.config = config

    def embed_batch(
        self,
        texts: List[str],
        timeout: float = 60.0
    ) -> Tuple[List[List[float]], dict]:
        """Embed with batch safety controls."""

        if len(texts) > self.MAX_BATCH_SIZE:
            raise ValueError(
                f"Batch size {len(texts)} exceeds limit {self.MAX_BATCH_SIZE}"
            )

        # Estimate total tokens
        total_chars = sum(len(t) for t in texts)
        estimated_tokens = total_chars // 4

        if estimated_tokens > self.MAX_TOTAL_TOKENS:
            raise ValueError(
                f"Estimated tokens {estimated_tokens} exceeds limit {self.MAX_TOTAL_TOKENS}"
            )

        start_time = time.time()

        try:
            response = self.client.embeddings.create(
                model=self.config.model,
                input=texts,
                timeout=timeout
            )
        except Exception as e:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise TimeoutError(f"Embedding request timed out after {timeout}s")
            raise

        embeddings = [e.embedding for e in response.data]

        return embeddings, {
            "batch_size": len(texts),
            "total_tokens": response.usage.total_tokens,
            "elapsed_seconds": time.time() - start_time
        }

    def embed_large_corpus(
        self,
        texts: List[str],
        batch_size: int = 100
    ) -> Tuple[List[List[float]], dict]:
        """Process large corpus with chunking and progress tracking."""

        all_embeddings = []
        total_tokens = 0
        failed_batches = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            batch_num = i // batch_size

            try:
                embeddings, stats = self.embed_batch(batch)
                all_embeddings.extend(embeddings)
                total_tokens += stats["total_tokens"]

            except Exception as e:
                # Log failure but continue processing
                failed_batches.append({
                    "batch_num": batch_num,
                    "start_idx": i,
                    "error": str(e)
                })
                # Add placeholder embeddings for failed batch
                all_embeddings.extend([None] * len(batch))

        return all_embeddings, {
            "total_processed": len(texts),
            "total_tokens": total_tokens,
            "failed_batches": failed_batches,
            "success_rate": (len(texts) - len(failed_batches) * batch_size) / len(texts)
        }
```

**Don't**: Process unlimited batch sizes without timeout handling

```python
# VULNERABLE: No batch size limit
def embed_all(texts: List[str]):
    return client.embeddings.create(
        model="text-embedding-3-small",
        input=texts  # Could be 10,000+ texts - will fail
    )

# VULNERABLE: No timeout
embeddings = client.embeddings.create(
    model="text-embedding-3-small",
    input=huge_batch  # May hang indefinitely
)

# VULNERABLE: No partial failure handling
for batch in batches:
    embeddings = client.embeddings.create(input=batch)
    # Single failure loses all subsequent batches
```

**Why**: Large batches can exceed API limits, causing failures and wasted tokens. Missing timeouts cause hung requests. Without partial failure handling, a single error loses progress on entire corpus.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-754 (Improper Check for Unusual Conditions), OWASP LLM10:2025 (Model Denial of Service)

---

## Rule: Input Type Validation

**Level**: `warning`

**When**: Using Cohere embeddings for search/retrieval

**Do**: Use correct input_type for documents vs queries

```python
from typing import List, Literal

class CohereEmbeddingClient:
    """Secure Cohere embedding client with input type validation."""

    VALID_INPUT_TYPES = {
        "search_document",   # For documents to be searched
        "search_query",      # For search queries
        "classification",    # For classification tasks
        "clustering"         # For clustering tasks
    }

    def __init__(self, client, model: str = "embed-english-v3.0"):
        self.client = client
        self.model = model

    def embed_documents(
        self,
        documents: List[str],
        truncate: str = "END"
    ) -> List[List[float]]:
        """Embed documents for indexing (search_document type)."""

        response = self.client.embed(
            texts=documents,
            model=self.model,
            input_type="search_document",  # CRITICAL: Must match usage
            truncate=truncate
        )

        return response.embeddings

    def embed_query(
        self,
        query: str,
        truncate: str = "END"
    ) -> List[float]:
        """Embed query for search (search_query type)."""

        response = self.client.embed(
            texts=[query],
            model=self.model,
            input_type="search_query",  # CRITICAL: Must match documents
            truncate=truncate
        )

        return response.embeddings[0]

    def embed_for_classification(
        self,
        texts: List[str]
    ) -> List[List[float]]:
        """Embed for classification tasks."""

        response = self.client.embed(
            texts=texts,
            model=self.model,
            input_type="classification"
        )

        return response.embeddings


# Usage - correct pairing
client = CohereEmbeddingClient(cohere_client)

# Index documents
doc_embeddings = client.embed_documents(documents)
for doc, emb in zip(documents, doc_embeddings):
    index.add(doc_id, emb)

# Search - MUST use search_query for queries
query_embedding = client.embed_query(user_query)
results = index.search(query_embedding, top_k=10)
```

**Don't**: Mix input types or use wrong type for use case

```python
# VULNERABLE: Wrong input type for queries
query_embedding = client.embed(
    texts=[query],
    model="embed-english-v3.0",
    input_type="search_document"  # Should be "search_query"
)
# Results in poor retrieval quality

# VULNERABLE: Documents embedded as queries
doc_embeddings = client.embed(
    texts=documents,
    model="embed-english-v3.0",
    input_type="search_query"  # Should be "search_document"
)
# Documents won't match query embeddings properly

# VULNERABLE: No input type specified
embedding = client.embed(
    texts=texts,
    model="embed-english-v3.0"
    # Missing input_type - uses default which may be wrong
)
```

**Why**: Cohere's v3 models use asymmetric embeddings - documents and queries are embedded differently for optimal retrieval. Using wrong input types degrades search quality by 10-30% and can cause complete retrieval failures.

**Refs**: OWASP LLM04:2025 (Model Misconfiguration), CWE-1188 (Insecure Default Initialization), Cohere Documentation

---

## Rule: Compression-Aware Security

**Level**: `warning`

**When**: Using Cohere compressed embedding types

**Do**: Validate embedding format and handle truncation properly

```python
from typing import List, Literal
import numpy as np

class CohereCompressionHandler:
    """Handle Cohere's compressed embedding types securely."""

    EMBEDDING_TYPES = {
        "float": {"dtype": np.float32, "bits_per_dim": 32},
        "int8": {"dtype": np.int8, "bits_per_dim": 8},
        "uint8": {"dtype": np.uint8, "bits_per_dim": 8},
        "binary": {"dtype": np.uint8, "bits_per_dim": 1},
        "ubinary": {"dtype": np.uint8, "bits_per_dim": 1},
    }

    def __init__(self, client, model: str = "embed-english-v3.0"):
        self.client = client
        self.model = model

    def embed_with_compression(
        self,
        texts: List[str],
        input_type: str,
        embedding_types: List[str]
    ) -> dict:
        """Embed with explicit compression type validation."""

        # Validate embedding types
        for etype in embedding_types:
            if etype not in self.EMBEDDING_TYPES:
                raise ValueError(f"Invalid embedding type: {etype}")

        response = self.client.embed(
            texts=texts,
            model=self.model,
            input_type=input_type,
            embedding_types=embedding_types
        )

        result = {}

        # Validate and convert each embedding type
        for etype in embedding_types:
            embeddings = getattr(response, f"embeddings")

            if etype == "float":
                result[etype] = [np.array(e, dtype=np.float32) for e in embeddings]
            elif etype in ["int8", "uint8"]:
                result[etype] = [np.array(e, dtype=self.EMBEDDING_TYPES[etype]["dtype"]) for e in embeddings]
            elif etype in ["binary", "ubinary"]:
                # Binary embeddings need special handling
                result[etype] = self._unpack_binary(embeddings)

        return result

    def _unpack_binary(self, binary_embeddings: List[List[int]]) -> List[np.ndarray]:
        """Unpack binary embeddings to bit arrays."""
        unpacked = []
        for emb in binary_embeddings:
            bits = np.unpackbits(np.array(emb, dtype=np.uint8))
            unpacked.append(bits)
        return unpacked

    def validate_truncation(
        self,
        text: str,
        max_tokens: int = 512
    ) -> dict:
        """Check if text will be truncated and warn."""

        # Rough token estimate
        estimated_tokens = len(text.split())

        will_truncate = estimated_tokens > max_tokens

        return {
            "estimated_tokens": estimated_tokens,
            "max_tokens": max_tokens,
            "will_truncate": will_truncate,
            "truncation_warning": (
                f"Text ({estimated_tokens} tokens) will be truncated to {max_tokens} tokens"
                if will_truncate else None
            )
        }


# Usage
handler = CohereCompressionHandler(client)

# Check for truncation before embedding
for doc in documents:
    truncation = handler.validate_truncation(doc)
    if truncation["will_truncate"]:
        logger.warning(truncation["truncation_warning"])

# Embed with compression
result = handler.embed_with_compression(
    texts=documents,
    input_type="search_document",
    embedding_types=["float", "int8"]  # Get both formats
)

# Use int8 for storage efficiency, float for computation
storage_embeddings = result["int8"]
compute_embeddings = result["float"]
```

**Don't**: Ignore truncation or mishandle compressed formats

```python
# VULNERABLE: Long text silently truncated
long_document = "..." * 10000  # Way over token limit
embedding = client.embed(
    texts=[long_document],
    model="embed-english-v3.0"
)  # Silently truncated - critical info lost

# VULNERABLE: Wrong dtype handling
int8_embeddings = response.int8_embeddings
# Stored as float - loses compression benefit and wastes storage
stored = [list(e) for e in int8_embeddings]

# VULNERABLE: Binary embeddings mishandled
binary_emb = response.ubinary_embeddings[0]
# Used directly without unpacking - wrong similarity computation
similarity = np.dot(binary_emb, other_binary)
```

**Why**: Silent truncation loses critical document content without warning. Mishandled compression wastes storage or corrupts embeddings. Binary embeddings require proper unpacking for correct similarity computation.

**Refs**: CWE-131 (Incorrect Calculation of Buffer Size), CWE-704 (Incorrect Type Conversion), OWASP LLM04:2025 (Model Misconfiguration)

---

## Rule: Domain Model Security

**Level**: `warning`

**When**: Using Voyage AI for domain-specific embeddings

**Do**: Select appropriate domain model for data type

```python
from typing import List, Literal

class VoyageModelSelector:
    """Secure Voyage AI model selection by domain."""

    DOMAIN_MODELS = {
        "general": {
            "model": "voyage-large-2",
            "use_case": "General text, mixed content",
            "max_tokens": 16000
        },
        "code": {
            "model": "voyage-code-2",
            "use_case": "Source code, technical documentation",
            "max_tokens": 16000
        },
        "legal": {
            "model": "voyage-law-2",
            "use_case": "Legal documents, contracts, case law",
            "max_tokens": 16000
        },
        "finance": {
            "model": "voyage-finance-1",
            "use_case": "Financial documents, earnings reports",
            "max_tokens": 16000
        },
        "multilingual": {
            "model": "voyage-multilingual-2",
            "use_case": "Non-English or mixed-language content",
            "max_tokens": 16000
        }
    }

    def __init__(self, client):
        self.client = client

    def select_model(self, domain: str) -> dict:
        """Select model with validation."""
        if domain not in self.DOMAIN_MODELS:
            raise ValueError(
                f"Unknown domain: {domain}. "
                f"Supported: {list(self.DOMAIN_MODELS.keys())}"
            )
        return self.DOMAIN_MODELS[domain]

    def embed(
        self,
        texts: List[str],
        domain: str,
        input_type: Literal["document", "query"] = "document"
    ) -> dict:
        """Embed with domain-appropriate model."""

        model_config = self.select_model(domain)

        # Validate input length
        for i, text in enumerate(texts):
            tokens = len(text.split())  # Rough estimate
            if tokens > model_config["max_tokens"]:
                raise ValueError(
                    f"Text {i} exceeds {domain} model limit: "
                    f"{tokens} > {model_config['max_tokens']}"
                )

        result = self.client.embed(
            texts,
            model=model_config["model"],
            input_type=input_type
        )

        return {
            "embeddings": result.embeddings,
            "model": model_config["model"],
            "domain": domain,
            "total_tokens": result.total_tokens
        }


# Usage
selector = VoyageModelSelector(voyage_client)

# Correct: Use code model for code
code_embeddings = selector.embed(
    source_files,
    domain="code",
    input_type="document"
)

# Correct: Use legal model for contracts
legal_embeddings = selector.embed(
    contracts,
    domain="legal",
    input_type="document"
)

# Ensure query uses same domain model
code_query_emb = selector.embed(
    [code_search_query],
    domain="code",  # Must match indexed documents
    input_type="query"
)
```

**Don't**: Use mismatched domain models

```python
# VULNERABLE: Wrong model for content type
code_embedding = client.embed(
    code_snippets,
    model="voyage-large-2"  # Should use voyage-code-2
)
# Suboptimal code understanding and retrieval

# VULNERABLE: Domain mismatch between index and query
# Documents indexed with:
doc_emb = client.embed(texts, model="voyage-code-2")

# Query embedded with:
query_emb = client.embed(query, model="voyage-large-2")
# Different embedding spaces - poor retrieval

# VULNERABLE: General model for specialized content
legal_emb = client.embed(
    legal_documents,
    model="voyage-large-2"  # Should use voyage-law-2
)
# Misses legal terminology and concepts
```

**Why**: Domain-specific models are trained on specialized corpora and understand domain terminology, structure, and relationships. Using mismatched models degrades retrieval quality by 15-40% for specialized content.

**Refs**: OWASP LLM04:2025 (Model Misconfiguration), NIST AI RMF (Model Selection), CWE-1188 (Insecure Default Initialization)

---

## Rule: Long Context Security

**Level**: `warning`

**When**: Using Jina embeddings for long documents (>4K tokens)

**Do**: Implement proper chunking strategy for 8K context window

```python
from typing import List, Tuple
import requests

class JinaLongContextHandler:
    """Secure handling of Jina's 8K context window."""

    MAX_TOKENS = 8192
    OVERLAP_TOKENS = 200  # Overlap between chunks

    def __init__(self, api_config: dict, model: str = "jina-embeddings-v2-base-en"):
        self.api_config = api_config
        self.model = model

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count (Jina uses ~4 chars per token)."""
        return len(text) // 4

    def chunk_document(
        self,
        text: str,
        max_chunk_tokens: int = 8000  # Leave buffer
    ) -> List[Tuple[str, dict]]:
        """Chunk long document with overlap and metadata."""

        chunks = []

        # If fits in single chunk, return as-is
        if self.estimate_tokens(text) <= max_chunk_tokens:
            return [(text, {"chunk_index": 0, "total_chunks": 1})]

        # Split into sentences for better chunk boundaries
        sentences = text.replace(".", ".\n").split("\n")

        current_chunk = []
        current_tokens = 0
        chunk_index = 0

        for sentence in sentences:
            sentence_tokens = self.estimate_tokens(sentence)

            if current_tokens + sentence_tokens > max_chunk_tokens:
                # Save current chunk
                chunk_text = " ".join(current_chunk)
                chunks.append((chunk_text, {
                    "chunk_index": chunk_index,
                    "start_char": sum(len(c[0]) for c in chunks),
                    "token_estimate": current_tokens
                }))
                chunk_index += 1

                # Start new chunk with overlap
                overlap_sentences = current_chunk[-3:] if len(current_chunk) > 3 else current_chunk
                current_chunk = overlap_sentences + [sentence]
                current_tokens = sum(self.estimate_tokens(s) for s in current_chunk)
            else:
                current_chunk.append(sentence)
                current_tokens += sentence_tokens

        # Add final chunk
        if current_chunk:
            chunk_text = " ".join(current_chunk)
            chunks.append((chunk_text, {
                "chunk_index": chunk_index,
                "token_estimate": current_tokens
            }))

        # Add total_chunks to all metadata
        for _, metadata in chunks:
            metadata["total_chunks"] = len(chunks)

        return chunks

    def embed_long_document(
        self,
        text: str,
        document_id: str
    ) -> List[dict]:
        """Embed long document with chunking."""

        chunks = self.chunk_document(text)
        results = []

        for chunk_text, metadata in chunks:
            # Validate chunk size
            estimated_tokens = self.estimate_tokens(chunk_text)
            if estimated_tokens > self.MAX_TOKENS:
                raise ValueError(
                    f"Chunk {metadata['chunk_index']} exceeds max tokens: "
                    f"{estimated_tokens} > {self.MAX_TOKENS}"
                )

            # Embed chunk
            response = requests.post(
                self.api_config["base_url"],
                headers=self.api_config["headers"],
                json={
                    "input": [chunk_text],
                    "model": self.model
                },
                timeout=30
            )
            response.raise_for_status()

            embedding = response.json()["data"][0]["embedding"]

            results.append({
                "document_id": document_id,
                "chunk_id": f"{document_id}_chunk_{metadata['chunk_index']}",
                "embedding": embedding,
                "metadata": metadata
            })

        return results

    def search_with_chunk_aggregation(
        self,
        query_embedding: List[float],
        index,
        top_k: int = 10
    ) -> List[dict]:
        """Search and aggregate results by document."""

        # Get more results to account for chunking
        raw_results = index.search(query_embedding, top_k=top_k * 3)

        # Aggregate by document_id, keeping best chunk score
        doc_scores = {}
        for result in raw_results:
            doc_id = result["document_id"]
            if doc_id not in doc_scores or result["score"] > doc_scores[doc_id]["score"]:
                doc_scores[doc_id] = result

        # Sort by score and return top_k
        sorted_results = sorted(
            doc_scores.values(),
            key=lambda x: x["score"],
            reverse=True
        )

        return sorted_results[:top_k]
```

**Don't**: Embed long documents without chunking or lose chunk context

```python
# VULNERABLE: Long document truncated
long_doc = "..." * 50000  # 50K characters
response = requests.post(
    jina_url,
    json={"input": [long_doc], "model": "jina-embeddings-v2-base-en"}
)
# Silently truncated at 8192 tokens - most content lost

# VULNERABLE: Chunks without overlap
chunks = [text[i:i+8000] for i in range(0, len(text), 8000)]
# Chunks split mid-sentence, lose context at boundaries

# VULNERABLE: No chunk aggregation in search
results = index.search(query_embedding)
# Returns multiple chunks of same document, missing other relevant docs

# VULNERABLE: Lost chunk metadata
embeddings = [embed(chunk) for chunk in chunks]
# Can't reconstruct document or chunk order
```

**Why**: Jina's 8K context is largest among common providers but still requires chunking for long documents. Silent truncation loses critical content. Poor chunking degrades semantic coherence. Missing aggregation returns duplicate documents.

**Refs**: CWE-131 (Incorrect Calculation of Buffer Size), OWASP LLM04:2025 (Model Misconfiguration), CWE-404 (Improper Resource Shutdown)

---

## Rule: Rate Limiting Implementation

**Level**: `strict`

**When**: Using any API-based embedding provider in production

**Do**: Implement RPM/TPM budgets with exponential backoff

```python
import time
import threading
from datetime import datetime, timedelta
from typing import List, Optional
import random

class EmbeddingRateLimiter:
    """Rate limiting for embedding APIs with backoff."""

    # Provider limits (requests per minute, tokens per minute)
    PROVIDER_LIMITS = {
        "openai": {"rpm": 500, "tpm": 1000000},
        "cohere": {"rpm": 100, "tpm": 100000},
        "voyage": {"rpm": 300, "tpm": 1000000},
        "jina": {"rpm": 500, "tpm": 1000000},
    }

    def __init__(
        self,
        provider: str,
        rpm_limit: Optional[int] = None,
        tpm_limit: Optional[int] = None
    ):
        defaults = self.PROVIDER_LIMITS.get(provider, {"rpm": 60, "tpm": 100000})
        self.rpm_limit = rpm_limit or defaults["rpm"]
        self.tpm_limit = tpm_limit or defaults["tpm"]

        self._lock = threading.Lock()
        self._request_times: List[datetime] = []
        self._token_usage: List[tuple] = []
        self._backoff_until: Optional[datetime] = None

    def wait_if_needed(self, estimated_tokens: int) -> dict:
        """Check limits and wait if necessary."""
        with self._lock:
            now = datetime.utcnow()

            # Check if in backoff period
            if self._backoff_until and now < self._backoff_until:
                wait_seconds = (self._backoff_until - now).total_seconds()
                time.sleep(wait_seconds)
                now = datetime.utcnow()

            # Clean old entries (outside 1-minute window)
            cutoff = now - timedelta(minutes=1)
            self._request_times = [t for t in self._request_times if t > cutoff]
            self._token_usage = [(t, c) for t, c in self._token_usage if t > cutoff]

            # Check RPM limit
            if len(self._request_times) >= self.rpm_limit:
                wait_seconds = (self._request_times[0] + timedelta(minutes=1) - now).total_seconds()
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
                    now = datetime.utcnow()

            # Check TPM limit
            current_tokens = sum(c for _, c in self._token_usage)
            if current_tokens + estimated_tokens > self.tpm_limit:
                wait_seconds = (self._token_usage[0][0] + timedelta(minutes=1) - now).total_seconds()
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
                    now = datetime.utcnow()

            # Record this request
            self._request_times.append(now)
            self._token_usage.append((now, estimated_tokens))

            return {
                "requests_in_window": len(self._request_times),
                "tokens_in_window": sum(c for _, c in self._token_usage),
                "rpm_remaining": self.rpm_limit - len(self._request_times),
                "tpm_remaining": self.tpm_limit - sum(c for _, c in self._token_usage)
            }

    def handle_rate_limit_error(self, retry_after: Optional[int] = None):
        """Handle 429 error with exponential backoff."""
        with self._lock:
            if retry_after:
                backoff_seconds = retry_after
            else:
                # Exponential backoff with jitter
                backoff_seconds = min(60, 2 ** len(self._request_times)) + random.uniform(0, 1)

            self._backoff_until = datetime.utcnow() + timedelta(seconds=backoff_seconds)
            return backoff_seconds


class RateLimitedEmbedder:
    """Embedding client with rate limiting."""

    def __init__(self, client, limiter: EmbeddingRateLimiter):
        self.client = client
        self.limiter = limiter
        self.max_retries = 3

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Embed with rate limiting and retry logic."""

        # Estimate tokens
        estimated_tokens = sum(len(t) // 4 for t in texts)

        for attempt in range(self.max_retries):
            # Wait if at limits
            usage = self.limiter.wait_if_needed(estimated_tokens)

            try:
                return self.client.embed(texts)

            except Exception as e:
                error_str = str(e).lower()

                if "429" in error_str or "rate limit" in error_str:
                    # Extract retry-after if available
                    retry_after = self._extract_retry_after(e)
                    backoff = self.limiter.handle_rate_limit_error(retry_after)

                    if attempt < self.max_retries - 1:
                        time.sleep(backoff)
                        continue

                raise

        raise RuntimeError(f"Failed after {self.max_retries} retries")

    def _extract_retry_after(self, error) -> Optional[int]:
        """Extract retry-after header from error if available."""
        if hasattr(error, "response") and error.response:
            return int(error.response.headers.get("retry-after", 0))
        return None


# Usage
limiter = EmbeddingRateLimiter(
    provider="openai",
    rpm_limit=100,  # Conservative limit
    tpm_limit=100000
)

embedder = RateLimitedEmbedder(openai_client, limiter)
embeddings = embedder.embed(texts)
```

**Don't**: Make unlimited requests or ignore rate limit errors

```python
# VULNERABLE: No rate limiting
for batch in batches:
    embeddings = client.embed(batch)  # Will hit 429 errors

# VULNERABLE: No backoff on error
try:
    embeddings = client.embed(texts)
except RateLimitError:
    embeddings = client.embed(texts)  # Immediate retry - same error

# VULNERABLE: Fixed sleep instead of exponential backoff
except RateLimitError:
    time.sleep(1)  # Fixed 1 second - not enough for rate limits
    retry()

# VULNERABLE: No token tracking
for doc in documents:
    embed(doc)  # May hit TPM limit before RPM limit
```

**Why**: All embedding APIs have rate limits (RPM/TPM). Exceeding limits causes 429 errors that can cascade into service unavailability. Exponential backoff prevents retry storms. Token tracking catches TPM limits that occur before RPM limits.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), OWASP LLM10:2025 (Model Denial of Service), CWE-770 (Resource Allocation Without Limits)

---

## Rule: Cost Tracking and Alerts

**Level**: `warning`

**When**: Using paid embedding APIs

**Do**: Implement token usage monitoring with budget alerts

```python
import time
from datetime import datetime, date
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class EmbeddingCostTracker:
    """Track embedding costs with budget alerts."""

    # Pricing per 1K tokens (verify against current provider pricing pages)
    PRICING = {
        "openai": {
            "text-embedding-3-small": 0.00002,
            "text-embedding-3-large": 0.00013,
            # text-embedding-ada-002 retired April 2025 — do not use
        },
        "cohere": {
            "embed-english-v3.0": 0.0001,
            "embed-multilingual-v3.0": 0.0001,
        },
        "voyage": {
            "voyage-large-2": 0.00012,
            "voyage-code-2": 0.00012,
        },
        "jina": {
            "jina-embeddings-v2-base-en": 0.00008,
        }
    }

    def __init__(
        self,
        daily_budget: float,
        monthly_budget: float,
        alert_threshold: float = 0.8
    ):
        self.daily_budget = daily_budget
        self.monthly_budget = monthly_budget
        self.alert_threshold = alert_threshold

        self._daily_cost = 0.0
        self._monthly_cost = 0.0
        self._current_day = date.today()
        self._current_month = date.today().month
        self._usage_log = []

    def get_price(self, provider: str, model: str) -> float:
        """Get price per 1K tokens."""
        if provider not in self.PRICING:
            raise ValueError(f"Unknown provider: {provider}")
        if model not in self.PRICING[provider]:
            raise ValueError(f"Unknown model: {model}")
        return self.PRICING[provider][model]

    def track_usage(
        self,
        provider: str,
        model: str,
        tokens: int,
        metadata: Optional[dict] = None
    ) -> dict:
        """Track usage and check budgets."""

        # Reset counters if needed
        today = date.today()
        if today != self._current_day:
            self._daily_cost = 0.0
            self._current_day = today
        if today.month != self._current_month:
            self._monthly_cost = 0.0
            self._current_month = today.month

        # Calculate cost
        price_per_1k = self.get_price(provider, model)
        cost = (tokens / 1000) * price_per_1k

        self._daily_cost += cost
        self._monthly_cost += cost

        # Log usage
        usage_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "provider": provider,
            "model": model,
            "tokens": tokens,
            "cost": cost,
            "metadata": metadata
        }
        self._usage_log.append(usage_entry)

        # Check budgets and alert
        alerts = []

        daily_usage_pct = self._daily_cost / self.daily_budget
        if daily_usage_pct >= self.alert_threshold:
            alert = f"Daily budget {daily_usage_pct:.0%} used (${self._daily_cost:.4f}/${self.daily_budget})"
            alerts.append(alert)
            logger.warning(alert)

        monthly_usage_pct = self._monthly_cost / self.monthly_budget
        if monthly_usage_pct >= self.alert_threshold:
            alert = f"Monthly budget {monthly_usage_pct:.0%} used (${self._monthly_cost:.4f}/${self.monthly_budget})"
            alerts.append(alert)
            logger.warning(alert)

        # Block if over budget
        if self._daily_cost > self.daily_budget:
            raise RuntimeError(f"Daily budget exceeded: ${self._daily_cost:.4f} > ${self.daily_budget}")
        if self._monthly_cost > self.monthly_budget:
            raise RuntimeError(f"Monthly budget exceeded: ${self._monthly_cost:.4f} > ${self.monthly_budget}")

        return {
            "cost": cost,
            "daily_total": self._daily_cost,
            "monthly_total": self._monthly_cost,
            "daily_remaining": self.daily_budget - self._daily_cost,
            "monthly_remaining": self.monthly_budget - self._monthly_cost,
            "alerts": alerts
        }

    def get_usage_report(self) -> dict:
        """Generate usage report."""
        return {
            "daily_cost": self._daily_cost,
            "monthly_cost": self._monthly_cost,
            "daily_budget": self.daily_budget,
            "monthly_budget": self.monthly_budget,
            "total_requests": len(self._usage_log),
            "recent_usage": self._usage_log[-10:]
        }


# Usage
tracker = EmbeddingCostTracker(
    daily_budget=10.0,     # $10/day
    monthly_budget=200.0,  # $200/month
    alert_threshold=0.8    # Alert at 80%
)

def embed_with_tracking(texts: List[str], client, provider: str, model: str):
    response = client.embed(texts)

    # Track usage
    usage = tracker.track_usage(
        provider=provider,
        model=model,
        tokens=response.usage.total_tokens,
        metadata={"batch_size": len(texts)}
    )

    if usage["alerts"]:
        # Send to monitoring system
        send_alerts(usage["alerts"])

    return response.embeddings
```

**Don't**: Run embeddings without cost monitoring

```python
# VULNERABLE: No cost tracking
for doc in documents:
    embedding = client.embed(doc)
# No visibility into spend - surprise bills

# VULNERABLE: No budget limits
while True:
    process_stream()  # Unbounded API costs

# VULNERABLE: No alerts
cost += calculate_cost(response)
# No warning until monthly bill arrives

# VULNERABLE: Missing usage metadata
track_cost(tokens)  # Can't analyze cost by feature/user
```

**Why**: Embedding API costs accumulate quickly with large corpora. A bug or attack can exhaust monthly budget in hours. Budget alerts enable early intervention. Usage tracking enables cost attribution and optimization.

**Refs**: CWE-770 (Resource Allocation Without Limits), OWASP LLM10:2025 (Model Denial of Service), NIST AI RMF (Resource Management)

---

## Rule: Response Validation

**Level**: `warning`

**When**: Receiving embedding responses from any provider

**Do**: Validate dimensions, detect errors, and handle edge cases

```python
from typing import List, Optional
import numpy as np

class EmbeddingResponseValidator:
    """Validate embedding responses from API providers."""

    def __init__(
        self,
        expected_dimensions: int,
        min_norm: float = 0.1,
        max_norm: float = 10.0
    ):
        self.expected_dimensions = expected_dimensions
        self.min_norm = min_norm
        self.max_norm = max_norm

    def validate(
        self,
        embeddings: List[List[float]],
        raise_on_error: bool = True
    ) -> dict:
        """Validate embedding response."""

        issues = []
        valid_embeddings = []

        for i, emb in enumerate(embeddings):
            # Check dimensions
            if len(emb) != self.expected_dimensions:
                issues.append({
                    "index": i,
                    "issue": "dimension_mismatch",
                    "expected": self.expected_dimensions,
                    "actual": len(emb)
                })
                continue

            # Check for NaN or Inf
            arr = np.array(emb)
            if np.any(np.isnan(arr)):
                issues.append({
                    "index": i,
                    "issue": "contains_nan"
                })
                continue

            if np.any(np.isinf(arr)):
                issues.append({
                    "index": i,
                    "issue": "contains_inf"
                })
                continue

            # Check norm (detects zero vectors and anomalies)
            norm = np.linalg.norm(arr)
            if norm < self.min_norm:
                issues.append({
                    "index": i,
                    "issue": "near_zero_norm",
                    "norm": float(norm)
                })
                continue

            if norm > self.max_norm:
                issues.append({
                    "index": i,
                    "issue": "abnormal_norm",
                    "norm": float(norm)
                })
                continue

            valid_embeddings.append(emb)

        result = {
            "valid": len(issues) == 0,
            "total": len(embeddings),
            "valid_count": len(valid_embeddings),
            "issues": issues
        }

        if issues and raise_on_error:
            raise ValueError(f"Embedding validation failed: {issues}")

        return result

    def validate_response(self, response, provider: str) -> dict:
        """Provider-specific response validation."""

        # Extract embeddings based on provider response format
        if provider == "openai":
            embeddings = [e.embedding for e in response.data]
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "total_tokens": response.usage.total_tokens
            }
        elif provider == "cohere":
            embeddings = response.embeddings
            usage = {"billed_units": response.meta.billed_units}
        elif provider == "voyage":
            embeddings = response.embeddings
            usage = {"total_tokens": response.total_tokens}
        elif provider == "jina":
            embeddings = [e["embedding"] for e in response["data"]]
            usage = {"total_tokens": response["usage"]["total_tokens"]}
        else:
            raise ValueError(f"Unknown provider: {provider}")

        # Validate embeddings
        validation = self.validate(embeddings)
        validation["usage"] = usage

        return validation


# Usage
validator = EmbeddingResponseValidator(
    expected_dimensions=1536,  # text-embedding-3-small
    min_norm=0.1,
    max_norm=10.0
)

def safe_embed(texts: List[str], client) -> List[List[float]]:
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=texts
    )

    # Validate response
    validation = validator.validate_response(response, provider="openai")

    if not validation["valid"]:
        logger.error(f"Embedding validation failed: {validation['issues']}")
        # Handle invalid embeddings (retry, skip, or raise)
        raise ValueError(f"Invalid embeddings: {validation['issues']}")

    embeddings = [e.embedding for e in response.data]
    return embeddings
```

**Don't**: Use embedding responses without validation

```python
# VULNERABLE: No dimension check
embedding = response.data[0].embedding
index.add(embedding)  # Wrong dimensions corrupt index

# VULNERABLE: No error handling
embeddings = response.embeddings
# Could contain None, empty, or malformed data

# VULNERABLE: No norm validation
embedding = response.data[0].embedding
# Zero vector or extreme values cause retrieval failures

# VULNERABLE: Assume success
result = client.embed(texts)
return result.embeddings  # No validation of response structure
```

**Why**: API responses can contain malformed embeddings due to errors, truncation, or edge cases. Invalid embeddings corrupt vector indices silently. Validation catches issues before they cause retrieval failures in production.

**Refs**: CWE-754 (Improper Check for Unusual Conditions), CWE-20 (Improper Input Validation), OWASP LLM04:2025 (Model Misconfiguration)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release with 10 provider-specific rules |
| 2.0.0 | 2025-05-26 | Fix OWASP LLM citations to :2025; retire ada-002; add PII redaction, per-tenant key isolation, and data residency rules |
