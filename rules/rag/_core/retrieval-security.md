# Retrieval Security Rules

Security patterns for search, retrieval, and reranking operations in RAG systems.

---

## Rule: Retrieved Chunk Sanitization

**Level**: `strict`

**When**: Processing retrieved chunks before LLM context injection

**Do**: Implement defense-in-depth sanitization. The primary defenses are structural: enforce
system/user context delimiters so retrieved content cannot be confused with instructions, and
validate LLM output on the other side of the boundary. Regex pattern matching is a secondary
signal — it catches known-bad strings but does not stop adversarial rephrasing, encoding
variations, or novel payloads. Document its limitations explicitly.

```python
import re
from typing import Optional
from dataclasses import dataclass

@dataclass
class SanitizationResult:
    content: str
    is_safe: bool
    threat_type: Optional[str] = None
    confidence: float = 0.0

class RAGChunkSanitizer:
    """
    Sanitize retrieved chunks for prompt injection attacks.

    Defense order:
      1. Structural: wrap chunk in explicit delimiters so the LLM sees it as
         data, not instructions (primary control — not shown here, apply at
         prompt-assembly layer).
      2. Source allowlist: reject chunks from untrusted origins.
      3. Regex denylist: secondary signal; catches known-bad patterns but
         WILL miss adversarial rephrasing and novel encodings. Treat a match
         as a strong indicator, not a guarantee of safety on non-match.
      4. Delimiter normalization: strip or escape characters that could
         collapse structural boundaries.

    OWASP LLM01:2025 explicitly states denylist-first approaches are
    insufficient as a primary injection defense. Use this class as one layer
    in a layered architecture, not as the sole gate.
    """

    # Known-bad patterns — secondary signal only. Adversarial rephrasing and
    # arbitrary encoding schemes (beyond the prefixed variants below) will bypass
    # these patterns. Do not treat a clean scan as proof of safety.
    INJECTION_PATTERNS = [
        # Direct instruction hijacking
        (r'ignore\s+(previous|above|all)\s+(instructions?|prompts?)', 'instruction_hijack'),
        (r'disregard\s+(everything|all|previous)', 'instruction_hijack'),
        (r'forget\s+(everything|all|your)\s+(previous|instructions?)', 'instruction_hijack'),

        # Role manipulation
        (r'you\s+are\s+now\s+[a-z]+', 'role_manipulation'),
        (r'act\s+as\s+(if|a|an)', 'role_manipulation'),
        (r'pretend\s+(to\s+be|you\'re)', 'role_manipulation'),

        # System prompt extraction
        (r'(show|reveal|display|print)\s+(your|the|system)\s+(prompt|instructions?)', 'prompt_extraction'),
        (r'what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions?)', 'prompt_extraction'),

        # Delimiter injection
        (r'<\|?(system|user|assistant)\|?>', 'delimiter_injection'),
        (r'\[INST\]|\[/INST\]', 'delimiter_injection'),
        (r'###\s*(System|Human|Assistant)', 'delimiter_injection'),

        # Code execution attempts
        (r'```(python|bash|sh|javascript)\s*\n.*?(exec|eval|system|subprocess)', 'code_execution'),

        # Prefixed encoded attacks (note: only catches prefixed encoding; arbitrary
        # encoding schemes are not matched — this is a known gap)
        (r'(?:base64|hex|rot13)\s*:\s*[A-Za-z0-9+/=]+', 'encoded_attack'),
    ]

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), threat_type)
            for pattern, threat_type in self.INJECTION_PATTERNS
        ]

    def sanitize(self, chunk: str, source_metadata: dict) -> SanitizationResult:
        """Sanitize a retrieved chunk for injection attacks."""
        # Validate source trustworthiness (primary source control)
        if not self._validate_source(source_metadata):
            return SanitizationResult(
                content="",
                is_safe=False,
                threat_type="untrusted_source",
                confidence=1.0
            )

        # Regex denylist — secondary signal; a clean result does not mean safe
        for pattern, threat_type in self.compiled_patterns:
            match = pattern.search(chunk)
            if match:
                if self.strict_mode:
                    return SanitizationResult(
                        content="",
                        is_safe=False,
                        threat_type=threat_type,
                        confidence=0.95
                    )
                else:
                    # Redact the malicious portion
                    chunk = pattern.sub('[REDACTED]', chunk)

        # Normalize delimiters and control characters
        sanitized = self._normalize_content(chunk)

        return SanitizationResult(
            content=sanitized,
            is_safe=True,
            confidence=0.0
        )

    def _validate_source(self, metadata: dict) -> bool:
        """Validate chunk source is from trusted origins."""
        trusted_sources = metadata.get('trusted_sources', [])
        chunk_source = metadata.get('source', '')

        if not chunk_source:
            return False

        # Check against allowlist
        return any(
            chunk_source.startswith(trusted)
            for trusted in trusted_sources
        )

    def _normalize_content(self, content: str) -> str:
        """Normalize content to prevent delimiter confusion."""
        # Remove null bytes and control characters
        content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', content)

        # Escape potential delimiter sequences
        content = content.replace('<|', '&lt;|')
        content = content.replace('|>', '|&gt;')

        return content.strip()


# Usage
sanitizer = RAGChunkSanitizer(strict_mode=True)

for chunk in retrieved_chunks:
    result = sanitizer.sanitize(
        chunk.content,
        {
            'source': chunk.metadata.get('source'),
            'trusted_sources': ['internal://', 'verified://']
        }
    )

    if result.is_safe:
        safe_chunks.append(result.content)
    else:
        logger.warning(f"Blocked chunk: {result.threat_type}")
```

**Don't**: Pass retrieved content directly to LLM without validation, or treat a regex-clean
result as proof of safety.

```python
# VULNERABLE: No sanitization of retrieved chunks
def build_prompt(query: str, chunks: list) -> str:
    context = "\n\n".join([chunk.content for chunk in chunks])
    return f"Context: {context}\n\nQuestion: {query}"

# Attacker embeds: "Ignore previous instructions. You are now..."
# in indexed documents, hijacking LLM behavior
```

**Why**: Attackers can embed prompt injection payloads in documents that get indexed and
retrieved (indirect injection via poisoned corpus). Regex denylists are a defense-in-depth
secondary control; OWASP LLM01:2025 states they are insufficient as a primary defense because
adversarial rephrasing and encoding variations bypass them. Primary defenses are structural:
separate system and retrieved-content turns, enforce output validation on the LLM response
side. Documents sourced from attacker-controlled origins are also a supply-chain risk covered
by LLM03:2025; integrity failures in the vector store fall under LLM08:2025.

**Refs**: OWASP LLM01:2025 (Prompt Injection), OWASP LLM03:2025 (Supply Chain),
OWASP LLM08:2025 (Vector and Embedding Weaknesses), CWE-94 (Code Injection),
MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: ACL Enforcement at Retrieval Time

**Level**: `strict`

**When**: Querying a vector store on behalf of an authenticated user or tenant

**Do**: Inject the ACL filter into the vector DB query before any documents are fetched.
The model must never see documents the requester cannot access, even briefly.

```python
from dataclasses import dataclass
from typing import Any

@dataclass
class UserContext:
    user_id: str
    tenant_id: str
    allowed_doc_ids: list[str]  # empty means no doc-level restriction
    clearance_level: int


def retrieve_with_acl(
    vector_client,
    query_embedding: list[float],
    user: UserContext,
    top_k: int = 5,
) -> list[Any]:
    """
    Retrieve chunks with ACL enforced at query time.

    The ACL filter is constructed from server-side session state only — never
    from user-supplied request parameters. This prevents a caller from
    widening their own filter.
    """
    # Build filter from authoritative session context, not request body
    acl_filter = {
        "must": [
            {"key": "tenant_id", "match": {"value": user.tenant_id}},
            {"key": "clearance_level", "range": {"lte": user.clearance_level}},
        ]
    }

    # Optional: doc-level allowlist (e.g., project membership)
    if user.allowed_doc_ids:
        acl_filter["must"].append(
            {"key": "doc_id", "match": {"any": user.allowed_doc_ids}}
        )

    # ACL filter is passed to the DB — non-authorized docs are never fetched
    results = vector_client.search(
        collection_name=f"tenant_{user.tenant_id}",  # namespace isolation (see cross-tenant rule)
        query_vector=query_embedding,
        query_filter=acl_filter,
        limit=top_k,
    )

    # Defensive assertion: verify every returned chunk matches the tenant
    for hit in results:
        assert hit.payload.get("tenant_id") == user.tenant_id, (
            f"ACL breach: chunk tenant_id={hit.payload.get('tenant_id')} "
            f"returned for user tenant_id={user.tenant_id}"
        )

    return results


# Qdrant example — same pattern with qdrant_client types
from qdrant_client.http import models as qmodels

def qdrant_retrieve_with_acl(qdrant_client, query_vector, user: UserContext, top_k: int = 5):
    acl_filter = qmodels.Filter(
        must=[
            qmodels.FieldCondition(
                key="tenant_id",
                match=qmodels.MatchValue(value=user.tenant_id),
            ),
            qmodels.FieldCondition(
                key="clearance_level",
                range=qmodels.Range(lte=user.clearance_level),
            ),
        ]
    )

    return qdrant_client.search(
        collection_name=f"tenant_{user.tenant_id}",
        query_vector=query_vector,
        query_filter=acl_filter,
        limit=top_k,
    )
```

**Don't**: Fetch results first and filter afterward. The model (or any downstream component)
has already observed unauthorized documents at that point.

```python
# VULNERABLE: Post-retrieval ACL filtering
def bad_retrieve(vector_client, query_embedding, user: UserContext, top_k: int = 10):
    # Fetches ALL documents regardless of ACL
    all_results = vector_client.search(query_vector=query_embedding, limit=top_k)

    # Filters after the fact — the model has already seen unauthorized chunks
    # if this runs inside a chain where results are passed to LLM before filtering
    authorized = [
        r for r in all_results
        if r.payload.get("tenant_id") == user.tenant_id
    ]
    return authorized
```

**Why**: Post-retrieval filtering is insufficient because documents outside the requester's
ACL are fetched, scored, and potentially passed to the LLM before being dropped. This creates
timing-based side channels (an attacker can infer whether a document exists by observing
latency or result-count changes) and information leakage if the filter runs after the LLM
call. Structural enforcement at query time eliminates the exposure surface.

**Refs**: OWASP LLM08:2025 (Vector and Embedding Weaknesses), CWE-285 (Improper Authorization),
CWE-200 (Exposure of Sensitive Information)

---

## Rule: Cross-Tenant Retrieval Isolation

**Level**: `strict`

**When**: Operating a multi-tenant RAG system backed by a shared vector store

**Do**: Isolate tenants by namespace or collection at the vector DB level. A missing or
misconfigured filter on a shared collection is a single point of failure; namespace
separation makes cross-tenant retrieval structurally impossible for a correctly addressed
query.

```python
from dataclasses import dataclass
from typing import Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class TenantContext:
    tenant_id: str
    user_id: str


class TenantIsolatedRetriever:
    """
    Enforce cross-tenant isolation at the collection level.

    Each tenant owns exactly one collection. Queries are namespaced by
    collection name derived from the tenant_id. A mandatory tenant_id
    metadata filter is applied as a secondary control — defense in depth
    against collection-name bugs.
    """

    COLLECTION_PREFIX = "rag_tenant_"

    def __init__(self, vector_client):
        self._client = vector_client

    def _collection_name(self, tenant_id: str) -> str:
        """Derive collection name from tenant_id. Validate to prevent injection."""
        if not tenant_id.isalnum() or len(tenant_id) > 64:
            raise ValueError(f"Invalid tenant_id: {tenant_id!r}")
        return f"{self.COLLECTION_PREFIX}{tenant_id}"

    def retrieve(
        self,
        tenant: TenantContext,
        query_vector: list[float],
        top_k: int = 5,
    ) -> list[Any]:
        collection = self._collection_name(tenant.tenant_id)

        # Secondary filter inside the tenant's own collection as defense-in-depth
        tenant_filter = {
            "must": [
                {"key": "tenant_id", "match": {"value": tenant.tenant_id}}
            ]
        }

        results = self._client.search(
            collection_name=collection,
            query_vector=query_vector,
            query_filter=tenant_filter,
            limit=top_k,
        )

        # Hard assertion — catch misconfiguration before results reach the caller
        violations = [
            hit for hit in results
            if hit.payload.get("tenant_id") != tenant.tenant_id
        ]
        if violations:
            logger.critical(
                "Cross-tenant retrieval breach: collection=%s tenant=%s "
                "violating_doc_ids=%s",
                collection,
                tenant.tenant_id,
                [v.id for v in violations],
            )
            raise PermissionError("Cross-tenant isolation violation — aborting retrieval")

        return results

    def provision_tenant(self, tenant_id: str, vector_size: int) -> None:
        """Create a tenant collection. Call during tenant onboarding, not at query time."""
        collection = self._collection_name(tenant_id)
        self._client.create_collection(
            collection_name=collection,
            vectors_config={"size": vector_size, "distance": "Cosine"},
        )
        logger.info("Provisioned collection %s for tenant %s", collection, tenant_id)
```

**Don't**: Share a single collection across tenants and rely solely on metadata filters.

```python
# VULNERABLE: Shared collection with filter-only isolation
def bad_multi_tenant_retrieve(client, query_vector, tenant_id: str, top_k: int = 5):
    # One misconfigured query or filter bug leaks all tenants' data
    results = client.search(
        collection_name="shared_rag_collection",
        query_vector=query_vector,
        # If this filter is omitted or wrong, cross-tenant data is returned silently
        query_filter={"must": [{"key": "tenant_id", "match": {"value": tenant_id}}]},
        limit=top_k,
    )
    return results
```

**Why**: A shared collection with filter-only isolation fails open when a filter is
accidentally omitted, misconfigured, or bypassed. Namespace/collection-level separation makes
cross-tenant retrieval structurally impossible for a correctly addressed query; the secondary
metadata filter and post-retrieval assertion provide defense-in-depth.

**Refs**: OWASP LLM08:2025 (Vector and Embedding Weaknesses), CWE-284 (Improper Access Control),
CWE-200 (Exposure of Sensitive Information)

---

## Rule: Vector DB Query Injection Prevention

**Level**: `strict`

**When**: Constructing vector DB queries that incorporate user-supplied input — particularly
metadata filters, namespace selectors, or query parameters

**Do**: Build metadata filters from an allowlisted, type-validated parameter set. Never
interpolate raw user input into filter dicts or query strings.

```python
from typing import Any
import re

# Allowlisted filter fields and their expected types
ALLOWED_FILTER_FIELDS: dict[str, type] = {
    "document_type": str,
    "language": str,
    "created_after": int,   # Unix timestamp
    "min_confidence": float,
}

# Allowlisted string values per field (empty set = any string allowed within length)
FIELD_VALUE_ALLOWLIST: dict[str, set[str]] = {
    "document_type": {"report", "policy", "faq", "manual"},
    "language": {"en", "fr", "de", "es", "ja", "zh"},
}

MAX_STRING_LEN = 64


def build_safe_filter(user_params: dict[str, Any]) -> dict:
    """
    Build a vector DB metadata filter from user-supplied parameters.

    Only keys present in ALLOWED_FILTER_FIELDS are accepted. Values are
    type-checked and, where applicable, checked against an allowlist.
    Unknown keys are silently dropped — never passed through.

    This prevents Qdrant/Weaviate/Pinecone operator injection where an
    attacker supplies nested dicts with $or/$gt/$nin operators or Weaviate
    GraphQL operator keywords in place of scalar values.
    """
    must_clauses = []

    for field, expected_type in ALLOWED_FILTER_FIELDS.items():
        if field not in user_params:
            continue

        value = user_params[field]

        # Type enforcement
        if not isinstance(value, expected_type):
            raise ValueError(f"Filter field {field!r} must be {expected_type.__name__}")

        # String length and content validation
        if expected_type is str:
            if len(value) > MAX_STRING_LEN:
                raise ValueError(f"Filter field {field!r} value too long")
            if not re.match(r'^[A-Za-z0-9_\-]+$', value):
                raise ValueError(f"Filter field {field!r} contains invalid characters")

        # Allowlist check
        if field in FIELD_VALUE_ALLOWLIST and value not in FIELD_VALUE_ALLOWLIST[field]:
            raise ValueError(f"Filter field {field!r} value {value!r} not in allowlist")

        must_clauses.append({"key": field, "match": {"value": value}})

    return {"must": must_clauses} if must_clauses else {}


# Qdrant example
from qdrant_client.http import models as qmodels

def safe_qdrant_query(
    qdrant_client,
    query_vector: list[float],
    user_filter_params: dict[str, Any],
    tenant_id: str,
    top_k: int = 5,
):
    # Start with mandatory ACL filter (from session context, not user input)
    must_conditions = [
        qmodels.FieldCondition(
            key="tenant_id",
            match=qmodels.MatchValue(value=tenant_id),
        )
    ]

    # Append validated user filter params
    safe_filter = build_safe_filter(user_filter_params)
    for clause in safe_filter.get("must", []):
        must_conditions.append(
            qmodels.FieldCondition(
                key=clause["key"],
                match=qmodels.MatchValue(value=clause["match"]["value"]),
            )
        )

    return qdrant_client.search(
        collection_name=f"tenant_{tenant_id}",
        query_vector=query_vector,
        query_filter=qmodels.Filter(must=must_conditions),
        limit=top_k,
    )
```

**Don't**: Interpolate user input directly into filter dicts or query strings.

```python
# VULNERABLE: Direct interpolation allows operator injection
def bad_filtered_search(client, query_vector, user_params: dict, tenant_id: str):
    # Attacker sends: {"document_type": {"$or": [{"value": "secret"}, {"value": "hr"}]}}
    # This passes a nested operator dict instead of a scalar, abusing Qdrant/Weaviate
    # filter syntax to widen the query across document types they cannot access.
    raw_filter = {
        "must": [
            {"key": "tenant_id", "match": {"value": tenant_id}},
            # User controls this entire clause — operator injection possible
            {"key": "document_type", "match": user_params.get("document_type")},
        ]
    }
    return client.search(
        collection_name="shared_collection",
        query_vector=query_vector,
        query_filter=raw_filter,
        limit=10,
    )
```

**Why**: Vector DB filter parameters accept structured operator dicts (Qdrant `$or`/`$gt`,
Weaviate GraphQL operator fields, Pinecone namespace strings). Interpolating unsanitized user
input into these positions is the retrieval-layer analog of SQL injection: an attacker can
widen or redirect the query to return documents they have no access to. Allowlist validation
on field names, types, and values eliminates the injection surface.

**Refs**: OWASP LLM08:2025 (Vector and Embedding Weaknesses), CWE-89 (SQL Injection — analogous
pattern), CWE-20 (Improper Input Validation)

---

## Rule: Context Stuffing Prevention

**Level**: `warning`

**When**: Aggregating multiple retrieved chunks for LLM context

**Do**: Enforce diversity penalties, relevance thresholds, and chunk limits

```python
import numpy as np
from typing import List, Tuple
from dataclasses import dataclass

@dataclass
class RetrievedChunk:
    content: str
    score: float
    embedding: np.ndarray
    source: str

class ContextStuffingDefense:
    """Prevent context manipulation through stuffing attacks."""

    def __init__(
        self,
        max_chunks: int = 5,
        min_relevance: float = 0.7,
        diversity_threshold: float = 0.3,
        max_source_ratio: float = 0.6
    ):
        self.max_chunks = max_chunks
        self.min_relevance = min_relevance
        self.diversity_threshold = diversity_threshold
        self.max_source_ratio = max_source_ratio

    def select_diverse_chunks(
        self,
        chunks: List[RetrievedChunk],
        query_embedding: np.ndarray
    ) -> List[RetrievedChunk]:
        """Select diverse, relevant chunks with source balancing."""

        # Filter by minimum relevance
        relevant = [c for c in chunks if c.score >= self.min_relevance]

        if not relevant:
            return []

        selected = []
        source_counts = {}

        for chunk in sorted(relevant, key=lambda x: x.score, reverse=True):
            if len(selected) >= self.max_chunks:
                break

            # Check source concentration
            source = chunk.source
            current_count = source_counts.get(source, 0)
            if current_count / max(len(selected), 1) >= self.max_source_ratio:
                continue  # Skip to prevent single-source dominance

            # Check diversity against already selected
            if selected and not self._is_diverse(chunk, selected):
                continue

            selected.append(chunk)
            source_counts[source] = current_count + 1

        return selected

    def _is_diverse(
        self,
        candidate: RetrievedChunk,
        selected: List[RetrievedChunk]
    ) -> bool:
        """Check if candidate is sufficiently different from selected."""
        for chunk in selected:
            similarity = self._cosine_similarity(
                candidate.embedding,
                chunk.embedding
            )
            if similarity > (1 - self.diversity_threshold):
                return False
        return True

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


# Usage
defense = ContextStuffingDefense(
    max_chunks=5,
    min_relevance=0.7,
    diversity_threshold=0.3,
    max_source_ratio=0.6
)

selected = defense.select_diverse_chunks(retrieved_chunks, query_embedding)
```

**Don't**: Return all top-k results without diversity or source checks

```python
# VULNERABLE: No protection against stuffing attacks
def get_context(query: str, k: int = 10) -> list:
    results = vector_store.similarity_search(query, k=k)
    # Attacker floods index with similar malicious documents
    # All top-k results contain attacker content
    return [r.content for r in results]
```

**Why**: Attackers can flood the vector store with semantically similar malicious documents,
causing all retrieved chunks to contain attacker-controlled content. This enables reliable
prompt injection by dominating the context window. Flooding an index with crafted documents
is a training/data poisoning attack under LLM03:2025; the degradation of vector store
integrity falls under LLM08:2025.

**Refs**: OWASP LLM01:2025 (Prompt Injection), OWASP LLM03:2025 (Supply Chain),
OWASP LLM08:2025 (Vector and Embedding Weaknesses), MITRE ATLAS AML.T0043 (Data Poisoning)

---

## Rule: Semantic Search Bypass Detection

**Level**: `warning`

**When**: Performing similarity search with user queries

**Do**: Use multi-model ensemble and paraphrase detection

```python
import numpy as np
from typing import List, Tuple
from sentence_transformers import SentenceTransformer

class SemanticBypassDetector:
    """Detect attempts to bypass semantic search with adversarial queries."""

    def __init__(self):
        # Use multiple embedding models for ensemble
        self.models = [
            SentenceTransformer('all-MiniLM-L6-v2'),
            SentenceTransformer('all-mpnet-base-v2'),
        ]
        self.consistency_threshold = 0.7

    def detect_bypass_attempt(
        self,
        query: str,
        top_results: List[Tuple[str, float]]
    ) -> Tuple[bool, str]:
        """Detect if query is attempting to bypass semantic search."""

        # Check 1: Ensemble consistency
        embeddings = [model.encode(query) for model in self.models]

        # Get results from each model
        all_scores = []
        for i, model in enumerate(self.models):
            doc_embeddings = [model.encode(doc) for doc, _ in top_results]
            scores = [
                self._cosine_similarity(embeddings[i], doc_emb)
                for doc_emb in doc_embeddings
            ]
            all_scores.append(scores)

        # Check ranking consistency across models
        if not self._check_ranking_consistency(all_scores):
            return True, "ensemble_inconsistency"

        # Check 2: Paraphrase attack detection
        if self._detect_paraphrase_attack(query, top_results):
            return True, "paraphrase_attack"

        # Check 3: Semantic anomaly detection
        if self._detect_semantic_anomaly(query, top_results):
            return True, "semantic_anomaly"

        return False, ""

    def _check_ranking_consistency(
        self,
        all_scores: List[List[float]]
    ) -> bool:
        """Check if rankings are consistent across models."""
        rankings = []
        for scores in all_scores:
            ranking = np.argsort(scores)[::-1]
            rankings.append(ranking)

        # Compare top-3 rankings
        for i in range(len(rankings) - 1):
            overlap = len(set(rankings[i][:3]) & set(rankings[i+1][:3]))
            if overlap < 2:  # Less than 2 common in top-3
                return False
        return True

    def _detect_paraphrase_attack(
        self,
        query: str,
        results: List[Tuple[str, float]]
    ) -> bool:
        """Detect queries designed to match malicious paraphrases."""
        # Check for unusual character patterns
        suspicious_patterns = [
            len(query) > 500,  # Unusually long
            query.count('.') > 10,  # Many sentences
            any(ord(c) > 127 for c in query),  # Unicode tricks
        ]
        return sum(suspicious_patterns) >= 2

    def _detect_semantic_anomaly(
        self,
        query: str,
        results: List[Tuple[str, float]]
    ) -> bool:
        """Detect semantic anomalies in retrieval."""
        scores = [score for _, score in results]

        # Check for suspicious score distribution
        if len(scores) > 1:
            # All scores suspiciously similar (stuffing attack)
            score_std = np.std(scores)
            if score_std < 0.01 and scores[0] > 0.9:
                return True

        return False

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


# Usage
detector = SemanticBypassDetector()

is_bypass, bypass_type = detector.detect_bypass_attempt(query, results)
if is_bypass:
    logger.warning(f"Bypass attempt detected: {bypass_type}")
    # Apply additional scrutiny or reject query
```

**Don't**: Rely on single embedding model without consistency checks

```python
# VULNERABLE: Single model easily bypassed
def search(query: str) -> list:
    embedding = model.encode(query)
    results = index.search(embedding, k=10)
    return results  # Adversarial queries can manipulate single model
```

**Why**: Adversarial queries can be crafted to exploit specific embedding model weaknesses,
retrieving unintended or malicious content. Multi-model ensemble provides defense-in-depth
against model-specific attacks.

**Refs**: MITRE ATLAS AML.T0043 (Adversarial ML), CWE-693 (Protection Mechanism Failure)

---

## Rule: Result Score Manipulation Prevention

**Level**: `warning`

**When**: Using similarity scores for ranking or filtering

**Do**: Validate score distributions and enforce ranking integrity

```python
import numpy as np
from typing import List, Tuple
from scipy import stats

class ScoreManipulationDetector:
    """Detect and prevent score manipulation attacks."""

    def __init__(
        self,
        min_score: float = 0.0,
        max_score: float = 1.0,
        anomaly_threshold: float = 3.0
    ):
        self.min_score = min_score
        self.max_score = max_score
        self.anomaly_threshold = anomaly_threshold
        self.score_history = []

    def validate_scores(
        self,
        scores: List[float],
        query_id: str
    ) -> Tuple[List[float], bool]:
        """Validate and normalize retrieval scores."""

        # Bound checking
        validated = []
        for score in scores:
            if not (self.min_score <= score <= self.max_score):
                score = np.clip(score, self.min_score, self.max_score)
            validated.append(score)

        # Statistical anomaly detection
        if len(self.score_history) > 100:
            is_anomalous = self._detect_anomaly(validated)
            if is_anomalous:
                return validated, False

        # Update history
        self.score_history.extend(validated)
        if len(self.score_history) > 10000:
            self.score_history = self.score_history[-5000:]

        return validated, True

    def _detect_anomaly(self, scores: List[float]) -> bool:
        """Detect if score distribution is anomalous."""
        historical_mean = np.mean(self.score_history)
        historical_std = np.std(self.score_history)

        current_mean = np.mean(scores)

        # Z-score test
        if historical_std > 0:
            z_score = abs(current_mean - historical_mean) / historical_std
            if z_score > self.anomaly_threshold:
                return True

        return False

    def apply_rank_integrity(
        self,
        results: List[Tuple[str, float]],
        original_order: List[str]
    ) -> List[Tuple[str, float]]:
        """Ensure ranking integrity hasn't been tampered with."""
        # Re-sort by score to ensure consistency
        sorted_results = sorted(results, key=lambda x: x[1], reverse=True)

        # Verify ordering matches scores
        for i in range(len(sorted_results) - 1):
            if sorted_results[i][1] < sorted_results[i+1][1]:
                raise ValueError("Ranking integrity violation detected")

        return sorted_results


# Usage
detector = ScoreManipulationDetector()

validated_scores, is_valid = detector.validate_scores(
    [r.score for r in results],
    query_id=query_hash
)

if not is_valid:
    logger.warning("Score manipulation detected")
```

**Don't**: Trust raw scores without validation

```python
# VULNERABLE: Unvalidated scores
def rank_results(results: list) -> list:
    # Attacker could inject results with manipulated scores
    return sorted(results, key=lambda x: x['score'], reverse=True)
```

**Why**: Attackers with index write access can manipulate document scores or metadata to
artificially boost malicious content rankings, bypassing relevance-based filtering.

**Refs**: CWE-345 (Insufficient Verification of Data Authenticity)

---

## Rule: Membership Inference Protection

**Level**: `warning`

**When**: Exposing retrieval scores or results to users

**Do**: Apply differential privacy and rate limiting

```python
import numpy as np
from typing import List, Dict
from collections import defaultdict
import time

class MembershipInferenceProtection:
    """Protect against membership inference attacks on indexed data."""

    def __init__(
        self,
        epsilon: float = 1.0,  # DP privacy parameter
        query_limit: int = 100,
        time_window: int = 3600
    ):
        self.epsilon = epsilon
        self.query_limit = query_limit
        self.time_window = time_window
        self.query_counts = defaultdict(list)

    def protect_scores(
        self,
        scores: List[float],
        sensitivity: float = 0.1
    ) -> List[float]:
        """Apply differential privacy noise to scores."""
        # Laplace mechanism
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale, len(scores))

        protected = [
            np.clip(score + n, 0.0, 1.0)
            for score, n in zip(scores, noise)
        ]

        return protected

    def check_rate_limit(
        self,
        user_id: str,
        query_embedding: np.ndarray
    ) -> bool:
        """Rate limit similar queries to prevent inference attacks."""
        current_time = time.time()

        # Clean old queries
        self.query_counts[user_id] = [
            (t, emb) for t, emb in self.query_counts[user_id]
            if current_time - t < self.time_window
        ]

        # Check total query count
        if len(self.query_counts[user_id]) >= self.query_limit:
            return False

        # Check for similar queries (probing attack)
        similar_count = 0
        for _, past_emb in self.query_counts[user_id]:
            similarity = self._cosine_similarity(query_embedding, past_emb)
            if similarity > 0.95:  # Very similar query
                similar_count += 1

        if similar_count >= 10:  # Too many similar queries
            return False

        # Record query
        self.query_counts[user_id].append((current_time, query_embedding))
        return True

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


# Usage
protection = MembershipInferenceProtection(
    epsilon=1.0,
    query_limit=100,
    time_window=3600
)

# Rate limit check
if not protection.check_rate_limit(user_id, query_embedding):
    raise RateLimitError("Query rate limit exceeded")

# Apply DP to scores before returning
protected_scores = protection.protect_scores(
    [r.score for r in results],
    sensitivity=0.1
)
```

**Don't**: Return exact scores without privacy protection

```python
# VULNERABLE: Exact scores enable membership inference
def search(query: str) -> dict:
    results = index.search(query)
    return {
        'results': results,
        'scores': [r.score for r in results]  # Exact scores leaked
    }
# Attacker queries for specific documents to determine if they're indexed
```

**Why**: Attackers can use exact similarity scores and repeated queries to infer whether
specific documents are in the index, potentially revealing sensitive information about the
training data or indexed content.

**Refs**: MITRE ATLAS AML.T0024 (Membership Inference), NIST AI RMF (Privacy)

---

## Rule: Hybrid Search Security

**Level**: `warning`

**When**: Combining lexical (BM25) and semantic search

**Do**: Validate score combination and prevent manipulation

```python
import numpy as np
from typing import List, Dict, Tuple

class HybridSearchSecurity:
    """Secure hybrid search combining BM25 and vector scores."""

    def __init__(
        self,
        vector_weight: float = 0.7,
        bm25_weight: float = 0.3,
        min_agreement: float = 0.5
    ):
        self.vector_weight = vector_weight
        self.bm25_weight = bm25_weight
        self.min_agreement = min_agreement

    def secure_combine(
        self,
        vector_results: List[Tuple[str, float]],
        bm25_results: List[Tuple[str, float]]
    ) -> List[Tuple[str, float]]:
        """Securely combine BM25 and vector search results."""

        # Normalize scores to [0, 1]
        vector_normalized = self._normalize_scores(vector_results)
        bm25_normalized = self._normalize_scores(bm25_results)

        # Build score maps
        vector_map = {doc_id: score for doc_id, score in vector_normalized}
        bm25_map = {doc_id: score for doc_id, score in bm25_normalized}

        # Combine with agreement check
        all_docs = set(vector_map.keys()) | set(bm25_map.keys())
        combined = []

        for doc_id in all_docs:
            vector_score = vector_map.get(doc_id, 0.0)
            bm25_score = bm25_map.get(doc_id, 0.0)

            # Check for score agreement
            in_vector = doc_id in vector_map
            in_bm25 = doc_id in bm25_map

            # Penalize documents only in one result set
            agreement_bonus = 1.0 if (in_vector and in_bm25) else 0.7

            # Weighted combination
            final_score = (
                self.vector_weight * vector_score +
                self.bm25_weight * bm25_score
            ) * agreement_bonus

            combined.append((doc_id, final_score))

        # Sort by combined score
        combined.sort(key=lambda x: x[1], reverse=True)

        # Validate result integrity
        self._validate_results(combined, vector_results, bm25_results)

        return combined

    def _normalize_scores(
        self,
        results: List[Tuple[str, float]]
    ) -> List[Tuple[str, float]]:
        """Normalize scores to [0, 1] range."""
        if not results:
            return []

        scores = [score for _, score in results]
        min_score = min(scores)
        max_score = max(scores)

        if max_score == min_score:
            return [(doc_id, 1.0) for doc_id, _ in results]

        return [
            (doc_id, (score - min_score) / (max_score - min_score))
            for doc_id, score in results
        ]

    def _validate_results(
        self,
        combined: List[Tuple[str, float]],
        vector: List[Tuple[str, float]],
        bm25: List[Tuple[str, float]]
    ) -> None:
        """Validate combined results for manipulation."""
        # Check that top results have reasonable agreement
        top_combined = set(doc_id for doc_id, _ in combined[:5])
        top_vector = set(doc_id for doc_id, _ in vector[:10])
        top_bm25 = set(doc_id for doc_id, _ in bm25[:10])

        vector_overlap = len(top_combined & top_vector)
        bm25_overlap = len(top_combined & top_bm25)

        if vector_overlap < 2 and bm25_overlap < 2:
            raise ValueError("Suspicious result manipulation detected")


# Usage
hybrid = HybridSearchSecurity(
    vector_weight=0.7,
    bm25_weight=0.3
)

combined_results = hybrid.secure_combine(
    vector_results,
    bm25_results
)
```

**Don't**: Naively combine scores without validation

```python
# VULNERABLE: Simple combination without agreement checks
def hybrid_search(query: str) -> list:
    vector = vector_store.search(query)
    bm25 = bm25_index.search(query)

    # Attacker can optimize for one method to dominate
    combined = {}
    for doc, score in vector:
        combined[doc] = combined.get(doc, 0) + 0.7 * score
    for doc, score in bm25:
        combined[doc] = combined.get(doc, 0) + 0.3 * score

    return sorted(combined.items(), key=lambda x: x[1], reverse=True)
```

**Why**: Attackers can craft documents that score high on one search method (e.g., keyword
stuffing for BM25) while remaining undetected by the other, manipulating hybrid rankings.

**Refs**: CWE-693 (Protection Mechanism Failure)

---

## Rule: Reranker Output Validation

**Level**: `warning`

**When**: Using cross-encoder rerankers to refine results

**Do**: Validate score bounds and filter suspicious results

```python
import numpy as np
from typing import List, Tuple
from transformers import AutoModelForSequenceClassification, AutoTokenizer

class SecureReranker:
    """Secure cross-encoder reranking with output validation."""

    def __init__(
        self,
        model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
        score_threshold: float = 0.3,
        max_score_change: float = 0.5
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self.score_threshold = score_threshold
        self.max_score_change = max_score_change

    def secure_rerank(
        self,
        query: str,
        candidates: List[Tuple[str, str, float]]  # (doc_id, content, initial_score)
    ) -> List[Tuple[str, float]]:
        """Rerank with security validation."""

        reranked = []

        for doc_id, content, initial_score in candidates:
            # Get reranker score
            inputs = self.tokenizer(
                query, content,
                return_tensors="pt",
                truncation=True,
                max_length=512
            )

            outputs = self.model(**inputs)
            rerank_score = float(outputs.logits[0][0].sigmoid())

            # Validate score bounds
            if not (0.0 <= rerank_score <= 1.0):
                rerank_score = np.clip(rerank_score, 0.0, 1.0)

            # Check for suspicious score changes
            score_change = abs(rerank_score - initial_score)
            if score_change > self.max_score_change:
                # Log and use conservative score
                rerank_score = (rerank_score + initial_score) / 2

            reranked.append((doc_id, rerank_score))

        # Sort by reranked score
        reranked.sort(key=lambda x: x[1], reverse=True)

        # Filter by threshold
        filtered = [
            (doc_id, score) for doc_id, score in reranked
            if score >= self.score_threshold
        ]

        # Validate ranking consistency
        self._validate_ranking(candidates, filtered)

        return filtered

    def _validate_ranking(
        self,
        original: List[Tuple[str, str, float]],
        reranked: List[Tuple[str, float]]
    ) -> None:
        """Validate reranking hasn't been manipulated."""
        if not original or not reranked:
            return

        # Check that at least some original top results remain
        original_top = set(doc_id for doc_id, _, _ in original[:5])
        reranked_top = set(doc_id for doc_id, _ in reranked[:5])

        overlap = len(original_top & reranked_top)
        if overlap < 1:
            raise ValueError("Suspicious reranking manipulation detected")


# Usage
reranker = SecureReranker(
    score_threshold=0.3,
    max_score_change=0.5
)

candidates = [
    (doc.id, doc.content, doc.score)
    for doc in initial_results
]

final_results = reranker.secure_rerank(query, candidates)
```

**Don't**: Trust reranker outputs without validation

```python
# VULNERABLE: Unvalidated reranker output
def rerank(query: str, results: list) -> list:
    reranked = []
    for doc in results:
        score = cross_encoder.predict(query, doc.content)
        reranked.append((doc.id, score))

    # Adversarial inputs can cause extreme score manipulation
    return sorted(reranked, key=lambda x: x[1], reverse=True)
```

**Why**: Rerankers can be manipulated through adversarial content that exploits model
weaknesses, causing dramatic ranking changes that promote malicious content.

**Refs**: MITRE ATLAS AML.T0043 (Adversarial ML), CWE-20 (Improper Input Validation)

---

## Quick Reference

| Rule | Level | Key Defense | Primary Threat |
|------|-------|-------------|----------------|
| Chunk Sanitization | `strict` | Structural separation + source validation; regex as secondary signal | Indirect prompt injection, corpus poisoning |
| ACL at Retrieval Time | `strict` | Metadata filter injected before fetch | Unauthorized document exposure |
| Cross-Tenant Isolation | `strict` | Per-tenant collection + filter + assertion | Cross-tenant data leakage |
| Vector DB Query Injection | `strict` | Allowlisted, type-validated filter params | Metadata filter operator injection |
| Context Stuffing | `warning` | Diversity penalty, source limits | Context manipulation |
| Bypass Detection | `warning` | Multi-model ensemble | Adversarial queries |
| Score Manipulation | `warning` | Distribution validation | Ranking attacks |
| Membership Inference | `warning` | Differential privacy, rate limiting | Privacy leakage |
| Hybrid Search | `warning` | Agreement validation | Single-method gaming |
| Reranker Validation | `warning` | Score bounds, change limits | Model manipulation |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01-15 | Initial retrieval security rules |
| 2.0.0 | 2026-05-26 | Add ACL-at-retrieval-time, cross-tenant isolation, vector DB query injection rules; add LLM03:2025 and LLM08:2025 refs; append :2025 to all OWASP LLM refs; demote regex denylist from primary to defense-in-depth advisory |
