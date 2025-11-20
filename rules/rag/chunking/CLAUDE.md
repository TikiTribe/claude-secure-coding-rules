# RAG Chunking Security Rules

Security rules for text chunking in RAG pipelines: RecursiveCharacterTextSplitter, SemanticChunker, NLTK, spaCy, tiktoken.

## Overview

**Scope**: Text chunking and splitting for RAG systems
**Tools**: LangChain splitters, tiktoken, spaCy, NLTK, SemanticChunker
**Risks**: Resource exhaustion, boundary injection, token overflow, entity leakage

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

**Refs**: CWE-20 (Improper Input Validation), OWASP LLM01 (Prompt Injection)

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
from typing import List, Set

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

**Why**: NLP models are computationally expensive; unbounded input causes DoS. Entity extraction can leak PII (names, locations, organizations) into vector stores where it's harder to delete. Arbitrary model loading can execute malicious pickled code.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-502 (Deserialization of Untrusted Data)

---

## Rule: Semantic Boundary Security

**Level**: `warning`

**When**: Using SemanticChunker or embedding-based splitting.

**Do**:
```python
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

**Why**: Semantic chunking uses embeddings which have cost implications. Manipulated thresholds can create extremely large or small chunks. Arbitrary embedding models may have different dimension sizes causing downstream errors or unexpected behavior.

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
- [ ] Sensitive entities are redacted or flagged
- [ ] Chunk integrity can be verified

## References

- CWE-20: Improper Input Validation
- CWE-400: Uncontrolled Resource Consumption
- CWE-502: Deserialization of Untrusted Data
- CWE-770: Allocation of Resources Without Limits
- CWE-778: Insufficient Logging
- OWASP LLM01: Prompt Injection
- NIST AI RMF: AI Risk Management Framework
