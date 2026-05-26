# RAG Chunking Security Rules

Security rules for text chunking in RAG pipelines: RecursiveCharacterTextSplitter, SemanticChunker, NLTK, spaCy, tiktoken.

## Overview

**Scope**: Text chunking and splitting for RAG systems
**Tools**: LangChain splitters, tiktoken, spaCy, NLTK, SemanticChunker
**Risks**: Resource exhaustion, boundary injection, token overflow, entity leakage, cross-domain chunk leakage, PII exposure before embedding

---

## Rule: Chunk Size Limits

**Level**: `strict`

**When**: Configuring any text splitter (RecursiveCharacterTextSplitter, SemanticChunker, custom splitters).

**Do**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Secure configuration with validated limits
MAX_CHUNK_SIZE = 4000  # Reasonable limit for most models
MAX_OVERLAP_RATIO = 0.25  # Overlap should not exceed 25% of chunk size

def create_secure_splitter(chunk_size: int, chunk_overlap: int) -> RecursiveCharacterTextSplitter:
    # Validate chunk size
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"Chunk size must be between 1 and {MAX_CHUNK_SIZE}")

    # Validate overlap ratio
    if chunk_overlap < 0 or chunk_overlap > chunk_size * MAX_OVERLAP_RATIO:
        raise ValueError(f"Overlap must be between 0 and {int(chunk_size * MAX_OVERLAP_RATIO)}")

    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        is_separator_regex=False,  # Prevent regex DoS
    )

splitter = create_secure_splitter(chunk_size=1000, chunk_overlap=200)
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: No validation - allows resource exhaustion
def create_splitter(chunk_size, chunk_overlap):
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,  # User-controlled, could be 1 (creates millions of chunks)
        chunk_overlap=chunk_overlap,  # Could exceed chunk_size
        is_separator_regex=True,  # Allows regex injection
    )
```

**Why**: Unbounded chunk sizes can cause memory exhaustion (tiny chunks create millions of objects) or context overflow (huge chunks exceed model limits). Excessive overlap wastes resources and can cause duplicate processing.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-20 (Improper Input Validation)

---

## Rule: Cross-Security-Domain Chunk Boundaries

**Level**: `strict`

**When**: Chunking a corpus that contains documents with different access-control classifications (e.g., public, internal, confidential). Applies to all splitter types.

**Do**:
```python
from dataclasses import dataclass
from enum import IntEnum
from typing import List
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
import logging

class AccessTier(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

@dataclass
class ClassifiedDocument:
    doc: Document
    tier: AccessTier

def chunk_classified_corpus(
    classified_docs: List[ClassifiedDocument],
    splitter: RecursiveCharacterTextSplitter,
) -> List[Document]:
    """
    Chunk each document independently so a fixed-size split never merges
    content from different access tiers into a single chunk.
    """
    all_chunks: List[Document] = []

    for classified in classified_docs:
        # Split each document in isolation — never concatenate before splitting
        doc_chunks = splitter.split_documents([classified.doc])

        for chunk in doc_chunks:
            # Stamp every chunk with the source document's access tier
            chunk.metadata["access_tier"] = classified.tier.name
            chunk.metadata["access_tier_value"] = int(classified.tier)
        all_chunks.extend(doc_chunks)

    return all_chunks

def assert_no_cross_domain_chunks(chunks: List[Document]) -> None:
    """
    Guard: verify that every chunk carries exactly one access tier
    and that no chunk metadata is missing a tier tag.
    Call this after chunking, before embedding.
    """
    for i, chunk in enumerate(chunks):
        tier = chunk.metadata.get("access_tier")
        if tier is None:
            raise ValueError(
                f"Chunk {i} is missing access_tier metadata — "
                "reject the batch until provenance is established."
            )
    logging.info(
        "Cross-domain boundary check passed: all %d chunks carry access_tier.",
        len(chunks),
    )
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: concatenating documents from different tiers before splitting
# causes a fixed-size window to straddle the classification boundary,
# copying confidential text into the public chunk's overlap region.
def chunk_corpus(docs):
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    combined_text = "\n\n".join(d.page_content for d in docs)  # tiers mixed
    return splitter.split_text(combined_text)  # no tier tag, no boundary guard
```

**Why**: When documents with different access classifications are concatenated before splitting, a fixed-size chunk window can span the boundary and include confidential text in a chunk later retrieved by a lower-privileged query. Splitting each document independently and tagging every chunk with its source tier prevents cross-domain leakage and enables retrieval-time access filtering.

**Refs**: CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information), OWASP LLM01:2025 (Prompt Injection / Data Leakage)

---

## Rule: Overlap-Domain Isolation

**Level**: `strict`

**When**: Configuring chunk overlap on any splitter used against a multi-tier corpus.

**Do**:
```python
from typing import List
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
import logging

def create_tier_aware_splitter(
    chunk_size: int,
    chunk_overlap: int,
) -> RecursiveCharacterTextSplitter:
    """
    Return a splitter configured for single-document isolation.
    Overlap is safe only when the splitter never sees content from
    two different access tiers in the same split() call.
    """
    if chunk_overlap < 0 or chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be in [0, chunk_size).")
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        is_separator_regex=False,
    )

def validate_overlap_boundaries(chunks: List[Document]) -> None:
    """
    Detect overlap leakage: if two consecutive chunks carry different
    access_tier values, their shared overlap window crossed a classification
    boundary. This should never happen when documents are split in isolation,
    but serves as a defence-in-depth check.
    """
    for i in range(1, len(chunks)):
        prev_tier = chunks[i - 1].metadata.get("access_tier_value")
        curr_tier = chunks[i].metadata.get("access_tier_value")
        if prev_tier is not None and curr_tier is not None and prev_tier != curr_tier:
            raise ValueError(
                f"Overlap boundary violation between chunk {i - 1} "
                f"(tier={prev_tier}) and chunk {i} (tier={curr_tier}). "
                "Consecutive chunks with different tiers indicate the splitter "
                "was called on a mixed-tier input."
            )
    logging.info("Overlap boundary validation passed for %d chunks.", len(chunks))
```

**Don't**:
```python
# VULNERABLE: overlap is validated only for size, not for content classification.
# A 200-char overlap at a confidential/public boundary copies confidential
# text into the adjacent public chunk.
splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
chunks = splitter.split_documents(mixed_tier_docs)  # no boundary check
```

**Why**: Overlap is designed to preserve context across chunk boundaries. When the corpus mixes sensitivity tiers, overlap mechanically copies content from one tier into an adjacent chunk of a different tier. That content is then embedded and indexed under the lower-privileged tier, making it retrievable without the required access level. Splitting per document and validating consecutive chunk tiers closes this vector.

**Refs**: CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information), NIST AI RMF (Govern 1.7 — data access controls)

---

## Rule: Pre-Embedding PII Scan

**Level**: `strict`

**When**: Any chunking pipeline — RecursiveCharacterTextSplitter, SemanticChunker, NER-based, or custom — before chunks are passed to an embedding model. This rule applies regardless of whether NER chunking is used.

**Do**:
```python
import re
import logging
from typing import List
from langchain.schema import Document

# Install: pip install presidio-analyzer presidio-anonymizer
# Presidio is the recommended scanner; regex fallback is provided for environments
# where the spaCy model download is restricted.
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    _PRESIDIO_AVAILABLE = True
except ImportError:
    _PRESIDIO_AVAILABLE = False

# Regex fallback patterns for common PII types
_PII_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), "CREDIT_CARD"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), "EMAIL"),
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "PHONE"),
]

class PIIDetectedError(Exception):
    pass

def scan_chunk_for_pii(
    chunk: Document,
    redact: bool = True,
    raise_on_detection: bool = False,
    language: str = "en",
) -> Document:
    """
    Scan a single chunk for PII before it reaches the embedding model.
    Works with RecursiveCharacter, SemanticChunker, and NER-based splits.

    Args:
        chunk: The Document chunk to scan.
        redact: Replace detected PII with type placeholders when True.
        raise_on_detection: Raise PIIDetectedError instead of redacting.
        language: Language hint for Presidio.
    Returns:
        A Document with PII redacted (or the original if none found).
    """
    text = chunk.page_content
    detections: List[str] = []

    if _PRESIDIO_AVAILABLE:
        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()
        results = analyzer.analyze(text=text, language=language)
        if results:
            detections = [r.entity_type for r in results]
            if raise_on_detection:
                raise PIIDetectedError(f"PII detected before embedding: {detections}")
            if redact:
                anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
                text = anonymized.text
    else:
        # Regex fallback — lower recall; use only when Presidio is unavailable
        for pattern, label in _PII_PATTERNS:
            if pattern.search(text):
                detections.append(label)
                if raise_on_detection:
                    raise PIIDetectedError(f"PII detected before embedding: {detections}")
                if redact:
                    text = pattern.sub(f"[{label}]", text)

    if detections:
        logging.warning(
            "PII types detected in chunk (source=%s): %s",
            chunk.metadata.get("source", "unknown"),
            detections,
        )
        chunk.metadata["pii_detected"] = detections

    return Document(page_content=text, metadata=chunk.metadata)

def scan_chunks_for_pii(
    chunks: List[Document],
    redact: bool = True,
    raise_on_detection: bool = False,
) -> List[Document]:
    """Apply PII scan to every chunk regardless of the splitter used."""
    return [
        scan_chunk_for_pii(c, redact=redact, raise_on_detection=raise_on_detection)
        for c in chunks
    ]
```

**Don't**:
```python
# VULNERABLE: PII scan only runs inside the NER chunking path.
# RecursiveCharacterTextSplitter and SemanticChunker outputs go directly
# to the embedding model, embedding raw SSNs, emails, and card numbers
# into the vector store.
def embed_chunks(chunks):
    from langchain_openai import OpenAIEmbeddings
    embeddings = OpenAIEmbeddings()
    return embeddings.embed_documents([c.page_content for c in chunks])
```

**Why**: NER-based redaction inside the NER chunking rule covers only one code path. Documents processed by RecursiveCharacterTextSplitter or SemanticChunker bypass that control entirely. PII embedded into a vector store is difficult to remove (requires re-indexing), may violate GDPR/CCPA retention limits, and can surface in responses to unrelated queries. A universal pre-embedding scan closes the gap across all splitter paths.

**Refs**: CWE-359 (Exposure of Private Personal Information), OWASP LLM01:2025 (Prompt Injection / Data Leakage), NIST SP 800-188 (De-identifying Government Datasets), GDPR Article 25 (Data Protection by Design)

---

## Rule: Boundary Injection Detection

**Level**: `warning`

**When**: Processing untrusted text that will be chunked and embedded.

**Do**:
```python
import re
from typing import List
from langchain.schema import Document

# Patterns that attackers use to manipulate chunk boundaries
BOUNDARY_INJECTION_PATTERNS = [
    r'\n{10,}',  # Excessive newlines to force splits
    r'\.{50,}',  # Repeated periods
    r'\s{100,}',  # Massive whitespace blocks
    r'(?:ignore|forget|disregard).{0,50}(?:previous|above|prior)',  # Prompt injection at boundaries
]

def detect_boundary_injection(text: str) -> List[str]:
    """Detect potential boundary injection attacks."""
    findings = []
    for pattern in BOUNDARY_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(f"Suspicious pattern detected: {pattern}")
    return findings

def safe_chunk_document(doc: Document, splitter) -> List[Document]:
    warnings = detect_boundary_injection(doc.page_content)
    if warnings:
        # Log for security review, optionally reject
        import logging
        logging.warning(f"Boundary injection indicators in document: {warnings}")

    return splitter.split_documents([doc])
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: No detection of boundary manipulation
def chunk_document(text):
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000)
    # Attacker can inject patterns to control where splits occur
    # placing malicious instructions at chunk boundaries
    return splitter.split_text(text)
```

**Why**: Attackers can manipulate chunk boundaries to place prompt injection payloads at the start of chunks (where they're most effective), split security-relevant content across chunks to evade detection, or cause specific content to be isolated or combined.

**Refs**: CWE-20 (Improper Input Validation), OWASP LLM01:2025 (Prompt Injection)

---

## Rule: Token Counting Security

**Level**: `strict`

**When**: Using tiktoken or other tokenizers for chunk size calculation.

**Do**:
```python
import tiktoken
from typing import Optional

# Allowlist of valid models
ALLOWED_MODELS = {
    'gpt-4', 'gpt-4-turbo', 'gpt-4o', 'gpt-3.5-turbo',
    'text-embedding-ada-002', 'text-embedding-3-small', 'text-embedding-3-large'
}
ALLOWED_ENCODINGS = {'cl100k_base', 'p50k_base', 'r50k_base'}

MAX_TOKEN_INPUT = 100_000  # Prevent DoS on huge documents

def get_secure_tokenizer(model: Optional[str] = None, encoding: Optional[str] = None):
    """Get tokenizer with validation."""
    if model:
        if model not in ALLOWED_MODELS:
            raise ValueError(f"Model '{model}' not in allowlist")
        return tiktoken.encoding_for_model(model)
    elif encoding:
        if encoding not in ALLOWED_ENCODINGS:
            raise ValueError(f"Encoding '{encoding}' not in allowlist")
        return tiktoken.get_encoding(encoding)
    else:
        raise ValueError("Must specify model or encoding")

def count_tokens_safely(text: str, tokenizer) -> int:
    """Count tokens with overflow protection."""
    if len(text) > MAX_TOKEN_INPUT * 4:  # Rough char estimate
        raise ValueError(f"Text too large: {len(text)} chars exceeds limit")

    tokens = tokenizer.encode(text)
    if len(tokens) > MAX_TOKEN_INPUT:
        raise ValueError(f"Token count {len(tokens)} exceeds limit {MAX_TOKEN_INPUT}")

    return len(tokens)

# Usage
tokenizer = get_secure_tokenizer(model='gpt-4')
token_count = count_tokens_safely(document_text, tokenizer)
```

**Don't**:
```python
import tiktoken

# VULNERABLE: No model validation or size limits
def count_tokens(text, model_name):
    # User-controlled model name - could cause errors or unexpected behavior
    enc = tiktoken.encoding_for_model(model_name)
    # No size limit - huge documents cause memory exhaustion
    return len(enc.encode(text))
```

**Why**: Invalid model names can cause errors or fall back to unexpected encodings. Extremely large documents can exhaust memory during tokenization. Token counts are used for billing and rate limiting, so manipulation has financial impact.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-20 (Improper Input Validation)

---

## Rule: NER-Based Chunking Security

**Level**: `warning`

**When**: Using spaCy or NLTK for entity-aware chunking.

**Do**:
```python
import spacy
from typing import List

# Resource limits
MAX_DOC_LENGTH = 100_000  # Characters
ALLOWED_MODELS = {'en_core_web_sm', 'en_core_web_md', 'en_core_web_lg'}
SENSITIVE_ENTITY_TYPES = {'PERSON', 'ORG', 'GPE', 'EMAIL', 'PHONE'}

def load_validated_model(model_name: str):
    """Load spaCy model with validation."""
    if model_name not in ALLOWED_MODELS:
        raise ValueError(f"Model '{model_name}' not in allowlist")

    nlp = spacy.load(model_name)
    # Disable unused components for performance
    nlp.disable_pipes('parser', 'lemmatizer')
    return nlp

def chunk_with_entities(
    text: str,
    nlp,
    redact_sensitive: bool = True
) -> List[dict]:
    """Chunk text while tracking entities securely."""
    if len(text) > MAX_DOC_LENGTH:
        raise ValueError(f"Document exceeds {MAX_DOC_LENGTH} character limit")

    doc = nlp(text)
    chunks = []

    for sent in doc.sents:
        entities = []
        for ent in sent.ents:
            entity_data = {
                'text': ent.text,
                'label': ent.label_,
            }
            # Track but optionally redact sensitive entities
            if redact_sensitive and ent.label_ in SENSITIVE_ENTITY_TYPES:
                entity_data['text'] = f'[{ent.label_}]'
            entities.append(entity_data)

        chunks.append({
            'text': sent.text,
            'entities': entities,
        })

    return chunks
```

**Don't**:
```python
import spacy

# VULNERABLE: No resource limits or entity protection
def chunk_with_ner(text, model_name):
    nlp = spacy.load(model_name)  # Any model, no validation
    doc = nlp(text)  # No size limit

    chunks = []
    for sent in doc.sents:
        # Leaks all entities including PII
        entities = [(ent.text, ent.label_) for ent in sent.ents]
        chunks.append({'text': sent.text, 'entities': entities})

    return chunks
```

**Why**: NLP models are computationally expensive; unbounded input causes DoS. Entity extraction can leak PII (names, locations, organizations) into vector stores where it's harder to delete. Arbitrary model loading can execute malicious pickled code. This rule covers only the NER path; apply the Pre-Embedding PII Scan rule to all other splitter paths as well.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-502 (Deserialization of Untrusted Data), CWE-359 (Exposure of Private Personal Information)

---

## Rule: Semantic Boundary Security

**Level**: `warning`

**When**: Using SemanticChunker or embedding-based splitting.

**Do**:
```python
# langchain-experimental is deprecated in LangChain v0.3+ (2024).
# Pin langchain-experimental to a known-good version and monitor the
# langchain-text-splitters package for a stable promoted replacement.
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings

# Secure semantic chunker configuration
ALLOWED_EMBEDDING_MODELS = {
    'text-embedding-ada-002',
    'text-embedding-3-small',
    'text-embedding-3-large'
}
MAX_SEMANTIC_CHUNK_SIZE = 2000
MIN_CHUNK_SIZE = 50

def create_secure_semantic_chunker(
    model_name: str,
    breakpoint_threshold: float = 0.5
) -> SemanticChunker:
    """Create semantic chunker with validated configuration."""
    if model_name not in ALLOWED_EMBEDDING_MODELS:
        raise ValueError(f"Embedding model '{model_name}' not in allowlist")

    # Validate threshold to prevent manipulation
    if not 0.1 <= breakpoint_threshold <= 0.9:
        raise ValueError("Breakpoint threshold must be between 0.1 and 0.9")

    embeddings = OpenAIEmbeddings(model=model_name)

    return SemanticChunker(
        embeddings=embeddings,
        breakpoint_threshold_type="percentile",
        breakpoint_threshold_amount=int(breakpoint_threshold * 100),
    )

def semantic_chunk_with_validation(text: str, chunker: SemanticChunker) -> list:
    """Chunk with post-processing validation."""
    chunks = chunker.split_text(text)

    validated_chunks = []
    for chunk in chunks:
        # Validate chunk sizes
        if len(chunk) < MIN_CHUNK_SIZE:
            continue  # Skip tiny chunks (likely noise)
        if len(chunk) > MAX_SEMANTIC_CHUNK_SIZE:
            # Re-split oversized chunks
            from langchain.text_splitter import RecursiveCharacterTextSplitter
            fallback = RecursiveCharacterTextSplitter(
                chunk_size=MAX_SEMANTIC_CHUNK_SIZE,
                chunk_overlap=100
            )
            validated_chunks.extend(fallback.split_text(chunk))
        else:
            validated_chunks.append(chunk)

    return validated_chunks
```

**Don't**:
```python
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings

# VULNERABLE: No model validation or output constraints
def semantic_chunk(text, model_name, threshold):
    embeddings = OpenAIEmbeddings(model=model_name)  # Any model
    chunker = SemanticChunker(
        embeddings=embeddings,
        breakpoint_threshold_amount=threshold,  # User-controlled
    )
    # No validation of output chunk sizes
    return chunker.split_text(text)
```

**Why**: Semantic chunking uses embeddings which have cost implications. Manipulated thresholds can create extremely large or small chunks. Arbitrary embedding models may have different dimension sizes causing downstream errors or unexpected behavior. Outputs from this path must pass through the Pre-Embedding PII Scan rule before embedding.

**Refs**: CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption)

---

## Rule: Metadata Preservation

**Level**: `warning`

**When**: Chunking documents that require provenance tracking or integrity verification.

**Do**:
```python
import hashlib
from typing import List
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

def chunk_with_provenance(
    doc: Document,
    splitter: RecursiveCharacterTextSplitter
) -> List[Document]:
    """Chunk document while preserving provenance and integrity."""
    # Hash original document for integrity
    original_hash = hashlib.sha256(doc.page_content.encode()).hexdigest()

    chunks = splitter.split_documents([doc])

    for i, chunk in enumerate(chunks):
        # Preserve original metadata
        chunk.metadata.update({
            'source_hash': original_hash,
            'chunk_index': i,
            'total_chunks': len(chunks),
            'chunk_hash': hashlib.sha256(chunk.page_content.encode()).hexdigest(),
            # Preserve original source
            'original_source': doc.metadata.get('source', 'unknown'),
        })

    return chunks

def verify_chunk_integrity(chunks: List[Document], original_hash: str) -> bool:
    """Verify chunk chain integrity."""
    # Reconstruct and verify
    for chunk in chunks:
        if chunk.metadata.get('source_hash') != original_hash:
            return False
        # Verify individual chunk hash
        computed = hashlib.sha256(chunk.page_content.encode()).hexdigest()
        if computed != chunk.metadata.get('chunk_hash'):
            return False
    return True
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: Loses provenance and integrity information
def chunk_document(text):
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000)
    # All metadata lost - can't trace chunks back to source
    # No integrity verification possible
    return splitter.split_text(text)
```

**Why**: Without provenance tracking, you cannot audit which sources contributed to a response, implement access controls on retrieved content, or detect tampering with vector store contents. Integrity hashes enable detection of chunk modification.

**Refs**: CWE-778 (Insufficient Logging), NIST AI RMF (Traceability)

---

## Rule: Resource Limits

**Level**: `warning`

**When**: Processing documents in chunking pipelines, especially from untrusted sources.

**Do**:
```python
import resource
import signal
from contextlib import contextmanager
from typing import List
from langchain.schema import Document

# Resource limits
MAX_MEMORY_MB = 512
MAX_PROCESSING_TIME_SEC = 30
MAX_DOCUMENT_SIZE = 1_000_000  # 1MB
MAX_CHUNKS_PER_DOC = 1000

class ChunkingResourceError(Exception):
    pass

@contextmanager
def resource_limits(max_memory_mb: int = MAX_MEMORY_MB, timeout_sec: int = MAX_PROCESSING_TIME_SEC):
    """Context manager for resource-limited chunking."""
    def timeout_handler(signum, frame):
        raise ChunkingResourceError(f"Chunking timeout after {timeout_sec}s")

    # Set memory limit (Unix only)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (max_memory_mb * 1024 * 1024, hard))
    except (ValueError, resource.error):
        pass  # Not available on all platforms

    # Set timeout
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_sec)

    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def chunk_with_limits(doc: Document, splitter) -> List[Document]:
    """Chunk document with resource protection."""
    # Pre-check document size
    if len(doc.page_content) > MAX_DOCUMENT_SIZE:
        raise ChunkingResourceError(f"Document exceeds {MAX_DOCUMENT_SIZE} byte limit")

    with resource_limits():
        chunks = splitter.split_documents([doc])

    # Post-check chunk count
    if len(chunks) > MAX_CHUNKS_PER_DOC:
        raise ChunkingResourceError(f"Too many chunks: {len(chunks)} > {MAX_CHUNKS_PER_DOC}")

    return chunks
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: No resource limits - DoS risk
def chunk_document(text):
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=10,  # Tiny chunks = millions of objects
    )
    # No memory limit - can exhaust system memory
    # No timeout - can hang indefinitely
    # No chunk count limit - can create unlimited chunks
    return splitter.split_text(text)
```

**Why**: Chunking is CPU and memory intensive. Malicious documents can be crafted to maximize resource consumption: huge documents, patterns that resist splitting, or configurations that create millions of tiny chunks. Resource limits prevent DoS attacks.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

---

## Security Checklist

Before deploying a chunking pipeline:

- [ ] Chunk size has upper and lower bounds validated
- [ ] Overlap ratio is constrained (typically <25% of chunk size)
- [ ] Tokenizer models are validated against allowlist
- [ ] Document size limits are enforced before processing
- [ ] Memory and timeout limits are configured
- [ ] Chunk count limits prevent resource exhaustion
- [ ] Provenance metadata is preserved through chunking
- [ ] Boundary injection patterns are detected
- [ ] Sensitive entities are redacted or flagged (NER path)
- [ ] Chunk integrity can be verified
- [ ] Every chunk carries an access_tier tag before entering the vector store
- [ ] Overlap windows are never allowed to cross access-control tier boundaries
- [ ] Pre-embedding PII scan runs on all chunks regardless of splitter type
- [ ] Markdown code-block boundaries are respected as hard split points to prevent code leakage across chunks

## References

- CWE-20: Improper Input Validation
- CWE-200: Exposure of Sensitive Information
- CWE-284: Improper Access Control
- CWE-359: Exposure of Private Personal Information
- CWE-400: Uncontrolled Resource Consumption
- CWE-502: Deserialization of Untrusted Data
- CWE-770: Allocation of Resources Without Limits
- CWE-778: Insufficient Logging
- OWASP LLM01:2025: Prompt Injection / Data Leakage
- NIST AI RMF: AI Risk Management Framework
- NIST SP 800-188: De-identifying Government Datasets
- GDPR Article 25: Data Protection by Design
