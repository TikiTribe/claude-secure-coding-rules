# LlamaIndex Security Rules

Security rules for LlamaIndex RAG orchestration framework. These rules extend the core RAG security patterns with LlamaIndex-specific implementations.

## Quick Reference

| Rule | Level | Key Control |
|------|-------|-------------|
| Secure Document Loader Configuration | `strict` | Allowlist file types, size limits, path validation |
| Index Persistence Security | `strict` | Encrypted storage, access control on persisted indexes |
| Query Engine Input Validation | `strict` | Prompt injection prevention, query length limits |
| Response Synthesizer Security | `warning` | Output validation, citation verification |
| Node Parser Security | `warning` | Chunk size limits, metadata preservation |
| Callback Handler Security | `warning` | No sensitive data in callbacks, secure logging |
| Service Context Configuration | `strict` | Secure LLM/embedding model configuration |
| Citation and Source Tracking | `warning` | Provenance validation, source verification |
| Agent and Tool Security | `strict` | Tool sandboxing, permission validation |
| Multi-Index Query Security | `warning` | Cross-index access control |

---

## Rule: Secure Document Loader Configuration

**Level**: `strict`

**When**: Loading documents using LlamaIndex readers (SimpleDirectoryReader, PDFReader, etc.)

**Do**: Configure document loaders with allowlists, size limits, and path validation

```python
import os
import magic
from pathlib import Path
from typing import List, Optional, Set
from llama_index.core import SimpleDirectoryReader
from llama_index.core.schema import Document

class SecureDocumentLoader:
    """Secure wrapper for LlamaIndex document loading."""

    ALLOWED_EXTENSIONS: Set[str] = {".txt", ".pdf", ".md", ".docx", ".html"}
    ALLOWED_MIME_TYPES: Set[str] = {
        "text/plain",
        "application/pdf",
        "text/markdown",
        "text/html",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    }
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    MAX_FILES_PER_LOAD: int = 100

    def __init__(self, base_directory: str, allowed_subdirs: Optional[List[str]] = None):
        self.base_directory = Path(base_directory).resolve()
        self.allowed_subdirs = allowed_subdirs or []

        if not self.base_directory.exists():
            raise ValueError(f"Base directory does not exist: {base_directory}")

    def _validate_path(self, file_path: Path) -> bool:
        """Validate file path is within allowed boundaries."""
        resolved = file_path.resolve()

        # Prevent path traversal
        try:
            resolved.relative_to(self.base_directory)
        except ValueError:
            raise SecurityError(f"Path traversal attempt detected: {file_path}")

        # Check allowed subdirectories if specified
        if self.allowed_subdirs:
            in_allowed = any(
                str(resolved).startswith(str(self.base_directory / subdir))
                for subdir in self.allowed_subdirs
            )
            if not in_allowed:
                raise SecurityError(f"Path not in allowed subdirectories: {file_path}")

        return True

    def _validate_file(self, file_path: Path) -> bool:
        """Validate individual file before loading."""
        # Check extension
        if file_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise SecurityError(f"File extension not allowed: {file_path.suffix}")

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise SecurityError(f"File exceeds size limit: {file_size} bytes")

        # Verify MIME type using magic bytes
        mime_type = magic.from_file(str(file_path), mime=True)
        if mime_type not in self.ALLOWED_MIME_TYPES:
            raise SecurityError(f"MIME type not allowed: {mime_type}")

        return True

    def load_documents(
        self,
        input_dir: Optional[str] = None,
        input_files: Optional[List[str]] = None,
        recursive: bool = False,
        exclude_hidden: bool = True
    ) -> List[Document]:
        """Securely load documents with validation."""

        documents = []
        files_to_load = []

        if input_files:
            # Validate specific files
            for file_path in input_files:
                path = Path(file_path)
                self._validate_path(path)
                self._validate_file(path)
                files_to_load.append(str(path))

        elif input_dir:
            # Validate directory and collect files
            dir_path = Path(input_dir)
            self._validate_path(dir_path)

            pattern = "**/*" if recursive else "*"
            for file_path in dir_path.glob(pattern):
                if file_path.is_file():
                    if exclude_hidden and file_path.name.startswith("."):
                        continue
                    try:
                        self._validate_file(file_path)
                        files_to_load.append(str(file_path))
                    except SecurityError as e:
                        # Log and skip invalid files
                        logger.warning(f"Skipping file: {e}")

        # Enforce file count limit
        if len(files_to_load) > self.MAX_FILES_PER_LOAD:
            raise SecurityError(
                f"Too many files: {len(files_to_load)} exceeds limit of {self.MAX_FILES_PER_LOAD}"
            )

        # Load with LlamaIndex reader
        if files_to_load:
            reader = SimpleDirectoryReader(input_files=files_to_load)
            documents = reader.load_data()

            # Audit log
            logger.info(f"Loaded {len(documents)} documents from {len(files_to_load)} files")

        return documents


# Usage
loader = SecureDocumentLoader(
    base_directory="/app/documents",
    allowed_subdirs=["public", "internal"]
)

documents = loader.load_documents(
    input_dir="/app/documents/public",
    recursive=True
)
```

**Don't**: Load documents without path validation or file type restrictions

```python
# VULNERABLE: No path validation - allows traversal
from llama_index.core import SimpleDirectoryReader

def load_docs_unsafe(user_path: str):
    # User can pass "../../../etc/passwd"
    reader = SimpleDirectoryReader(input_dir=user_path)
    return reader.load_data()

# VULNERABLE: No file type restrictions
reader = SimpleDirectoryReader(
    input_dir="/uploads",
    recursive=True
)
documents = reader.load_data()  # May load malicious files
```

**Why**: Document loaders with unrestricted access enable path traversal attacks, loading of malicious file types, and denial of service through large files. Attackers can exfiltrate sensitive system files or inject malicious content into the RAG system.

**Refs**:
- OWASP LLM06 (Sensitive Information Disclosure)
- CWE-22 (Path Traversal)
- CWE-434 (Unrestricted Upload of File with Dangerous Type)
- MITRE ATLAS AML.T0020 (Poison Training Data)

---

## Rule: Index Persistence Security

**Level**: `strict`

**When**: Persisting or loading VectorStoreIndex to/from disk or external storage

**Do**: Encrypt persisted indexes and implement access controls

```python
import os
import json
import hashlib
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from llama_index.core import VectorStoreIndex, StorageContext, load_index_from_storage

class SecureIndexStorage:
    """Secure storage wrapper for LlamaIndex persistence."""

    def __init__(
        self,
        storage_dir: str,
        encryption_key: Optional[bytes] = None,
        tenant_id: Optional[str] = None
    ):
        self.storage_dir = Path(storage_dir)
        self.tenant_id = tenant_id

        # Initialize encryption
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = None

        # Create tenant-isolated directory
        if tenant_id:
            self.index_dir = self.storage_dir / self._hash_tenant(tenant_id)
        else:
            self.index_dir = self.storage_dir / "default"

        self.index_dir.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions
        os.chmod(self.index_dir, 0o700)

    def _hash_tenant(self, tenant_id: str) -> str:
        """Create non-reversible tenant directory name."""
        return hashlib.sha256(tenant_id.encode()).hexdigest()[:32]

    def _encrypt_file(self, file_path: Path) -> None:
        """Encrypt a persisted file in place."""
        if not self.cipher:
            return

        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted = self.cipher.encrypt(data)

        with open(file_path, 'wb') as f:
            f.write(encrypted)

    def _decrypt_file(self, file_path: Path) -> bytes:
        """Decrypt a persisted file."""
        with open(file_path, 'rb') as f:
            data = f.read()

        if self.cipher:
            return self.cipher.decrypt(data)
        return data

    def persist_index(
        self,
        index: VectorStoreIndex,
        index_name: str
    ) -> str:
        """Securely persist index with encryption."""
        # Validate index name
        if not index_name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Invalid index name - use alphanumeric characters only")

        persist_dir = self.index_dir / index_name
        persist_dir.mkdir(exist_ok=True)

        # Persist index
        index.storage_context.persist(persist_dir=str(persist_dir))

        # Encrypt all persisted files
        for file_path in persist_dir.glob("*.json"):
            self._encrypt_file(file_path)

        # Create integrity hash
        self._create_integrity_hash(persist_dir)

        # Audit log
        logger.info(f"Index persisted: {index_name} for tenant: {self.tenant_id}")

        return str(persist_dir)

    def load_index(
        self,
        index_name: str,
        service_context=None
    ) -> VectorStoreIndex:
        """Securely load index with decryption and integrity check."""
        persist_dir = self.index_dir / index_name

        if not persist_dir.exists():
            raise FileNotFoundError(f"Index not found: {index_name}")

        # Verify integrity
        if not self._verify_integrity(persist_dir):
            raise SecurityError(f"Index integrity check failed: {index_name}")

        # Decrypt files to temporary location
        temp_dir = self._decrypt_to_temp(persist_dir)

        try:
            # Load from decrypted files
            storage_context = StorageContext.from_defaults(persist_dir=str(temp_dir))
            index = load_index_from_storage(
                storage_context,
                service_context=service_context
            )

            logger.info(f"Index loaded: {index_name} for tenant: {self.tenant_id}")

            return index
        finally:
            # Clean up temporary decrypted files
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _create_integrity_hash(self, persist_dir: Path) -> None:
        """Create integrity hash for persisted files."""
        hashes = {}
        for file_path in sorted(persist_dir.glob("*.json")):
            with open(file_path, 'rb') as f:
                hashes[file_path.name] = hashlib.sha256(f.read()).hexdigest()

        integrity_file = persist_dir / ".integrity"
        with open(integrity_file, 'w') as f:
            json.dump(hashes, f)

    def _verify_integrity(self, persist_dir: Path) -> bool:
        """Verify index file integrity."""
        integrity_file = persist_dir / ".integrity"
        if not integrity_file.exists():
            return False

        with open(integrity_file) as f:
            expected_hashes = json.load(f)

        for filename, expected_hash in expected_hashes.items():
            file_path = persist_dir / filename
            if not file_path.exists():
                return False

            with open(file_path, 'rb') as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()

            if actual_hash != expected_hash:
                logger.warning(f"Integrity mismatch: {filename}")
                return False

        return True

    def _decrypt_to_temp(self, persist_dir: Path) -> Path:
        """Decrypt files to temporary directory."""
        import tempfile
        temp_dir = Path(tempfile.mkdtemp())

        for file_path in persist_dir.glob("*.json"):
            decrypted = self._decrypt_file(file_path)
            with open(temp_dir / file_path.name, 'wb') as f:
                f.write(decrypted)

        return temp_dir


# Usage
storage = SecureIndexStorage(
    storage_dir="/app/indexes",
    encryption_key=os.environ.get("INDEX_ENCRYPTION_KEY").encode(),
    tenant_id="tenant_123"
)

# Persist index
storage.persist_index(index, "my_index")

# Load index
index = storage.load_index("my_index")
```

**Don't**: Persist indexes without encryption or access controls

```python
# VULNERABLE: Unencrypted persistence
index.storage_context.persist(persist_dir="./storage")

# VULNERABLE: No tenant isolation
def load_any_index(index_name: str):
    return load_index_from_storage(
        StorageContext.from_defaults(persist_dir=f"./storage/{index_name}")
    )

# VULNERABLE: No integrity verification
storage_context = StorageContext.from_defaults(persist_dir=user_provided_path)
index = load_index_from_storage(storage_context)  # May load tampered index
```

**Why**: Persisted indexes contain embeddings that can leak information about the original content. Without encryption, attackers with storage access can extract sensitive data. Without integrity checks, indexes can be tampered to inject malicious content.

**Refs**:
- OWASP LLM06 (Sensitive Information Disclosure)
- CWE-311 (Missing Encryption of Sensitive Data)
- CWE-354 (Improper Validation of Integrity Check Value)
- NIST AI RMF GOVERN 4.2 (Privacy)

---

## Rule: Query Engine Input Validation

**Level**: `strict`

**When**: Processing user queries through LlamaIndex query engines

**Do**: Validate and sanitize all query inputs before processing

```python
import re
from typing import Optional, List
from llama_index.core import VectorStoreIndex
from llama_index.core.query_engine import BaseQueryEngine
from llama_index.core.schema import QueryBundle

class SecureQueryEngine:
    """Security wrapper for LlamaIndex query engines."""

    MAX_QUERY_LENGTH = 2000
    MAX_QUERIES_PER_MINUTE = 60

    INJECTION_PATTERNS = [
        r'ignore\s+(previous|above|all)\s+instructions?',
        r'disregard\s+(everything|all|previous)',
        r'forget\s+(everything|all|your)',
        r'you\s+are\s+now\s+[a-z]+',
        r'act\s+as\s+(if|a|an)',
        r'system\s*:\s*',
        r'assistant\s*:\s*',
        r'\[INST\]|\[/INST\]',
        r'<<SYS>>|<</SYS>>',
        r'<\|im_start\|>|<\|im_end\|>',
    ]

    def __init__(
        self,
        index: VectorStoreIndex,
        similarity_top_k: int = 5,
        response_mode: str = "compact"
    ):
        self.query_engine = index.as_query_engine(
            similarity_top_k=similarity_top_k,
            response_mode=response_mode
        )
        self._query_times: List[float] = []
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.INJECTION_PATTERNS
        ]

    def _validate_query(self, query: str) -> str:
        """Validate and sanitize query input."""
        if not query or not isinstance(query, str):
            raise ValueError("Query must be a non-empty string")

        # Length validation
        if len(query) > self.MAX_QUERY_LENGTH:
            raise ValueError(f"Query exceeds maximum length of {self.MAX_QUERY_LENGTH}")

        # Remove control characters
        query = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', query)

        # Check for injection patterns
        for pattern in self._compiled_patterns:
            if pattern.search(query):
                logger.warning(f"Injection pattern detected in query")
                query = pattern.sub('[FILTERED]', query)

        return query.strip()

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check per-user rate limits."""
        import time
        current_time = time.time()

        # Clean old entries
        self._query_times = [
            t for t in self._query_times
            if current_time - t < 60
        ]

        if len(self._query_times) >= self.MAX_QUERIES_PER_MINUTE:
            return False

        self._query_times.append(current_time)
        return True

    def query(
        self,
        query_str: str,
        user_id: Optional[str] = None,
        metadata_filters: Optional[dict] = None
    ):
        """Execute a secure query with validation."""
        # Rate limiting
        if user_id and not self._check_rate_limit(user_id):
            raise RateLimitError("Query rate limit exceeded")

        # Validate query
        validated_query = self._validate_query(query_str)

        # Sanitize metadata filters
        if metadata_filters:
            metadata_filters = self._sanitize_filters(metadata_filters)

        # Execute query
        try:
            response = self.query_engine.query(validated_query)

            # Validate response
            self._validate_response(response)

            return response

        except Exception as e:
            logger.error(f"Query execution error: {e}")
            raise

    def _sanitize_filters(self, filters: dict) -> dict:
        """Sanitize metadata filters to prevent injection."""
        sanitized = {}

        for key, value in filters.items():
            # Validate key format
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', key):
                continue

            # Prevent system field access
            if key.startswith("_"):
                continue

            sanitized[key] = value

        return sanitized

    def _validate_response(self, response) -> None:
        """Validate query response for security issues."""
        response_text = str(response)

        # Check for potential data leakage patterns
        leakage_patterns = [
            r'api[_-]?key\s*[=:]\s*\S+',
            r'password\s*[=:]\s*\S+',
            r'secret\s*[=:]\s*\S+',
        ]

        for pattern in leakage_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                logger.warning("Potential sensitive data in response")


# Usage
secure_engine = SecureQueryEngine(
    index=vector_index,
    similarity_top_k=5,
    response_mode="compact"
)

response = secure_engine.query(
    query_str="What are the project requirements?",
    user_id="user_123"
)
```

**Don't**: Pass user queries directly to query engines without validation

```python
# VULNERABLE: No input validation
query_engine = index.as_query_engine()
response = query_engine.query(user_input)  # Direct user input

# VULNERABLE: No rate limiting
def query_unlimited(query: str):
    return query_engine.query(query)  # DoS vulnerability

# VULNERABLE: No filter sanitization
response = query_engine.query(
    query,
    filters=user_provided_filters  # Can access system fields
)
```

**Why**: Unvalidated queries enable prompt injection attacks where malicious content in the query manipulates LLM behavior. Long queries or rapid-fire requests can cause denial of service. Unsanitized filters can bypass access controls.

**Refs**:
- OWASP LLM01 (Prompt Injection)
- CWE-20 (Improper Input Validation)
- CWE-400 (Uncontrolled Resource Consumption)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Response Synthesizer Security

**Level**: `warning`

**When**: Using response synthesizers to generate answers from retrieved context

**Do**: Validate synthesizer outputs and verify citations

```python
import re
from typing import List, Optional, Dict
from llama_index.core.response_synthesizers import (
    ResponseMode,
    get_response_synthesizer
)
from llama_index.core.schema import NodeWithScore

class SecureResponseSynthesizer:
    """Secure wrapper for LlamaIndex response synthesis."""

    MAX_RESPONSE_LENGTH = 10000

    HARMFUL_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'data:text/html',
    ]

    def __init__(
        self,
        response_mode: str = "compact",
        use_async: bool = False
    ):
        self.synthesizer = get_response_synthesizer(
            response_mode=ResponseMode(response_mode),
            use_async=use_async
        )
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.HARMFUL_PATTERNS
        ]

    def synthesize(
        self,
        query: str,
        nodes: List[NodeWithScore],
        verify_citations: bool = True
    ):
        """Synthesize response with security validation."""
        # Pre-validate nodes
        validated_nodes = self._validate_nodes(nodes)

        # Generate response
        response = self.synthesizer.synthesize(
            query=query,
            nodes=validated_nodes
        )

        # Post-process response
        response_text = str(response)

        # Check response length
        if len(response_text) > self.MAX_RESPONSE_LENGTH:
            logger.warning("Response truncated due to length")
            response_text = response_text[:self.MAX_RESPONSE_LENGTH]

        # Remove harmful patterns
        response_text = self._sanitize_output(response_text)

        # Verify citations if requested
        if verify_citations:
            citations = self._verify_citations(response, validated_nodes)
            response.metadata = response.metadata or {}
            response.metadata['verified_citations'] = citations

        return response

    def _validate_nodes(self, nodes: List[NodeWithScore]) -> List[NodeWithScore]:
        """Validate retrieved nodes before synthesis."""
        validated = []

        for node in nodes:
            # Check node content for injection
            content = node.node.get_content()
            if self._contains_injection(content):
                logger.warning(f"Skipping node with injection pattern: {node.node.node_id}")
                continue

            # Verify score is reasonable
            if not (0.0 <= node.score <= 1.0):
                logger.warning(f"Invalid score for node: {node.score}")
                continue

            validated.append(node)

        return validated

    def _contains_injection(self, content: str) -> bool:
        """Check if content contains injection patterns."""
        injection_patterns = [
            r'ignore\s+previous\s+instructions',
            r'system\s*:\s*',
            r'\[INST\]',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _sanitize_output(self, text: str) -> str:
        """Remove harmful patterns from output."""
        for pattern in self._compiled_patterns:
            text = pattern.sub('[REMOVED]', text)

        # HTML encode potentially dangerous characters
        text = text.replace('<', '&lt;').replace('>', '&gt;')

        return text

    def _verify_citations(
        self,
        response,
        nodes: List[NodeWithScore]
    ) -> Dict[str, bool]:
        """Verify that citations in response match source nodes."""
        citations = {}
        response_text = str(response).lower()

        for node in nodes:
            source = node.node.metadata.get('source', node.node.node_id)

            # Check if source content appears in response
            content_snippet = node.node.get_content()[:100].lower()
            citations[source] = content_snippet in response_text or source.lower() in response_text

        return citations


# Usage
secure_synthesizer = SecureResponseSynthesizer(
    response_mode="tree_summarize"
)

response = secure_synthesizer.synthesize(
    query="Summarize the main findings",
    nodes=retrieved_nodes,
    verify_citations=True
)

# Check citation verification
if response.metadata.get('verified_citations'):
    for source, verified in response.metadata['verified_citations'].items():
        if not verified:
            logger.warning(f"Unverified citation: {source}")
```

**Don't**: Use response synthesizers without output validation

```python
# VULNERABLE: No output validation
synthesizer = get_response_synthesizer()
response = synthesizer.synthesize(query, nodes)
return str(response)  # May contain XSS, injection patterns

# VULNERABLE: No node validation
def synthesize_unsafe(query: str, nodes: list):
    # Nodes may contain poisoned content
    return synthesizer.synthesize(query, nodes)

# VULNERABLE: No citation verification
response = synthesizer.synthesize(query, nodes)
# Response may fabricate citations or misattribute sources
```

**Why**: Response synthesizers can propagate malicious content from retrieved nodes into final outputs. Without validation, XSS payloads, prompt injection patterns, or fabricated citations can reach end users.

**Refs**:
- OWASP LLM01 (Prompt Injection)
- OWASP LLM02 (Insecure Output Handling)
- CWE-79 (Cross-site Scripting)
- CWE-20 (Improper Input Validation)

---

## Rule: Node Parser Security

**Level**: `warning`

**When**: Parsing documents into nodes/chunks for indexing

**Do**: Configure chunk size limits and preserve secure metadata

```python
from typing import List, Optional
from llama_index.core.node_parser import (
    SentenceSplitter,
    SimpleNodeParser
)
from llama_index.core.schema import Document, TextNode

class SecureNodeParser:
    """Secure node parser with size limits and metadata handling."""

    MAX_CHUNK_SIZE = 2048
    MIN_CHUNK_SIZE = 50
    MAX_CHUNK_OVERLAP = 200
    MAX_NODES_PER_DOCUMENT = 500

    METADATA_ALLOWLIST = {
        'source', 'file_name', 'page_number', 'creation_date',
        'author', 'title', 'section', 'category'
    }

    def __init__(
        self,
        chunk_size: int = 1024,
        chunk_overlap: int = 100,
        include_metadata: bool = True
    ):
        # Validate parameters
        if not (self.MIN_CHUNK_SIZE <= chunk_size <= self.MAX_CHUNK_SIZE):
            raise ValueError(f"chunk_size must be between {self.MIN_CHUNK_SIZE} and {self.MAX_CHUNK_SIZE}")

        if chunk_overlap > self.MAX_CHUNK_OVERLAP:
            raise ValueError(f"chunk_overlap must be <= {self.MAX_CHUNK_OVERLAP}")

        if chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be less than chunk_size")

        self.parser = SentenceSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            include_metadata=include_metadata
        )
        self.include_metadata = include_metadata

    def parse_documents(
        self,
        documents: List[Document],
        tenant_id: Optional[str] = None
    ) -> List[TextNode]:
        """Parse documents into secure nodes."""
        all_nodes = []

        for doc in documents:
            # Sanitize document metadata
            if doc.metadata:
                doc.metadata = self._sanitize_metadata(doc.metadata)

            # Add security metadata
            if tenant_id:
                doc.metadata = doc.metadata or {}
                doc.metadata['_tenant_id'] = tenant_id
                doc.metadata['_indexed_at'] = datetime.utcnow().isoformat()

            # Parse into nodes
            nodes = self.parser.get_nodes_from_documents([doc])

            # Enforce node count limit
            if len(nodes) > self.MAX_NODES_PER_DOCUMENT:
                logger.warning(
                    f"Document produced too many nodes: {len(nodes)}, truncating to {self.MAX_NODES_PER_DOCUMENT}"
                )
                nodes = nodes[:self.MAX_NODES_PER_DOCUMENT]

            # Validate and process each node
            for node in nodes:
                validated = self._validate_node(node)
                if validated:
                    all_nodes.append(validated)

        return all_nodes

    def _sanitize_metadata(self, metadata: dict) -> dict:
        """Sanitize metadata to allowed fields only."""
        sanitized = {}

        for key, value in metadata.items():
            # Keep system fields (prefixed with _)
            if key.startswith('_'):
                sanitized[key] = value
                continue

            # Check allowlist
            if key.lower() in self.METADATA_ALLOWLIST:
                # Sanitize string values
                if isinstance(value, str):
                    value = self._sanitize_string(value)
                sanitized[key] = value

        return sanitized

    def _sanitize_string(self, value: str) -> str:
        """Sanitize string metadata values."""
        import html

        # Limit length
        value = value[:1000]

        # Remove control characters
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

        # HTML encode
        value = html.escape(value)

        return value

    def _validate_node(self, node: TextNode) -> Optional[TextNode]:
        """Validate individual node."""
        content = node.get_content()

        # Check minimum content length
        if len(content.strip()) < 10:
            return None

        # Check for suspicious patterns
        if self._is_suspicious(content):
            logger.warning(f"Suspicious node content detected: {node.node_id}")
            # Option: filter or flag the node
            node.metadata['_flagged'] = True

        return node

    def _is_suspicious(self, content: str) -> bool:
        """Check for suspicious content patterns."""
        patterns = [
            r'base64,[A-Za-z0-9+/=]{100,}',  # Large base64 blobs
            r'(?:0x[0-9a-f]{2}){20,}',  # Hex-encoded data
        ]

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False


# Usage
parser = SecureNodeParser(
    chunk_size=1024,
    chunk_overlap=100,
    include_metadata=True
)

nodes = parser.parse_documents(
    documents=loaded_documents,
    tenant_id="tenant_123"
)
```

**Don't**: Use default parsers without security configuration

```python
# VULNERABLE: Unrestricted chunk sizes
parser = SentenceSplitter(
    chunk_size=100000,  # Enormous chunks
    chunk_overlap=50000  # Excessive overlap
)

# VULNERABLE: No metadata sanitization
nodes = parser.get_nodes_from_documents(documents)
# Preserves potentially malicious metadata

# VULNERABLE: No node count limits
for doc in huge_documents:
    nodes.extend(parser.get_nodes_from_documents([doc]))
    # Can produce millions of nodes
```

**Why**: Large chunk sizes can overwhelm embedding models and increase attack surface. Unsanitized metadata can contain XSS or injection payloads. Unlimited node generation enables denial of service attacks.

**Refs**:
- OWASP LLM06 (Sensitive Information Disclosure)
- CWE-400 (Uncontrolled Resource Consumption)
- CWE-79 (Cross-site Scripting)
- CWE-117 (Improper Output Neutralization for Logs)

---

## Rule: Callback Handler Security

**Level**: `warning`

**When**: Using LlamaIndex callback handlers for observability

**Do**: Sanitize callback data and use secure logging practices

```python
import re
import json
from typing import Any, Dict, List, Optional
from llama_index.core.callbacks import (
    CallbackManager,
    LlamaDebugHandler,
    CBEventType
)
from llama_index.core.callbacks.base import BaseCallbackHandler

class SecureCallbackHandler(BaseCallbackHandler):
    """Security-aware callback handler for LlamaIndex."""

    SENSITIVE_PATTERNS = [
        r'api[_-]?key\s*[=:]\s*[\'"]?[\w-]+',
        r'password\s*[=:]\s*[\'"]?[\w-]+',
        r'secret\s*[=:]\s*[\'"]?[\w-]+',
        r'token\s*[=:]\s*[\'"]?[\w-]+',
        r'bearer\s+[\w-]+',
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    ]

    def __init__(
        self,
        logger,
        log_sensitive: bool = False,
        max_content_length: int = 500
    ):
        super().__init__(
            event_starts_to_ignore=[],
            event_ends_to_ignore=[]
        )
        self.logger = logger
        self.log_sensitive = log_sensitive
        self.max_content_length = max_content_length
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.SENSITIVE_PATTERNS
        ]

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Handle event start with secure logging."""
        safe_payload = self._sanitize_payload(payload)

        self.logger.info(
            f"Event start: {event_type.value}",
            extra={
                'event_id': event_id,
                'parent_id': parent_id,
                'payload': safe_payload
            }
        )

        return event_id

    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Handle event end with secure logging."""
        safe_payload = self._sanitize_payload(payload)

        self.logger.info(
            f"Event end: {event_type.value}",
            extra={
                'event_id': event_id,
                'payload': safe_payload
            }
        )

    def _sanitize_payload(self, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Sanitize payload for safe logging."""
        if not payload:
            return {}

        sanitized = {}

        for key, value in payload.items():
            # Skip explicitly sensitive keys
            if any(s in key.lower() for s in ['password', 'secret', 'token', 'key', 'credential']):
                sanitized[key] = '[REDACTED]'
                continue

            # Process based on type
            if isinstance(value, str):
                sanitized[key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_payload(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_string(str(v))[:100] if isinstance(v, str) else '[OBJECT]'
                    for v in value[:10]  # Limit list size
                ]
            else:
                sanitized[key] = str(value)[:self.max_content_length]

        return sanitized

    def _sanitize_string(self, value: str) -> str:
        """Sanitize string value for logging."""
        # Truncate
        value = value[:self.max_content_length]

        # Redact sensitive patterns unless explicitly allowed
        if not self.log_sensitive:
            for pattern in self._compiled_patterns:
                value = pattern.sub('[REDACTED]', value)

        # Remove newlines for log safety
        value = value.replace('\n', ' ').replace('\r', '')

        return value

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        """Start a trace."""
        pass

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """End a trace."""
        pass


# Usage
import logging

# Configure secure logger
logger = logging.getLogger("llamaindex")
logger.setLevel(logging.INFO)

# Create secure callback handler
secure_handler = SecureCallbackHandler(
    logger=logger,
    log_sensitive=False,
    max_content_length=500
)

# Create callback manager
callback_manager = CallbackManager([secure_handler])

# Use with service context
from llama_index.core import Settings
Settings.callback_manager = callback_manager
```

**Don't**: Log sensitive data or use verbose callbacks in production

```python
# VULNERABLE: Logs all content including secrets
debug_handler = LlamaDebugHandler(print_trace_on_end=True)
# Prints full prompts, responses, potentially containing PII/secrets

# VULNERABLE: No redaction
def on_event_end(self, event_type, payload):
    logger.info(f"Payload: {json.dumps(payload)}")  # Logs everything

# VULNERABLE: Sensitive data in traces
callback_manager.on_event_start(
    event_type=CBEventType.LLM,
    payload={
        'prompt': f"API Key: {api_key}, Query: {query}"  # Exposes key
    }
)
```

**Why**: Callback handlers can inadvertently log sensitive information including API keys, PII, and proprietary data. These logs may be accessible to unauthorized parties or stored in insecure systems.

**Refs**:
- OWASP LLM06 (Sensitive Information Disclosure)
- CWE-532 (Insertion of Sensitive Information into Log File)
- CWE-200 (Exposure of Sensitive Information)
- NIST SSDF PW.1.1 (Secure logging)

---

## Rule: Service Context Configuration

**Level**: `strict`

**When**: Configuring LlamaIndex Settings or ServiceContext with LLM and embedding models

**Do**: Use secure model configuration with authentication and rate limiting

```python
import os
from typing import Optional
from llama_index.core import Settings
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding

class SecureServiceConfiguration:
    """Secure configuration for LlamaIndex services."""

    def __init__(
        self,
        llm_model: str = "gpt-4",
        embedding_model: str = "text-embedding-3-small",
        temperature: float = 0.1,
        max_tokens: int = 2048
    ):
        self.llm_model = llm_model
        self.embedding_model = embedding_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def configure(self) -> None:
        """Configure LlamaIndex settings securely."""
        # Load API key from secure source
        api_key = self._load_api_key()

        # Configure LLM with security settings
        llm = OpenAI(
            model=self.llm_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            api_key=api_key,
            timeout=30.0,  # Request timeout
            max_retries=3,
            additional_kwargs={
                "seed": 42,  # For reproducibility
            }
        )

        # Configure embedding model
        embed_model = OpenAIEmbedding(
            model=self.embedding_model,
            api_key=api_key,
            timeout=30.0,
            max_retries=3
        )

        # Set global settings
        Settings.llm = llm
        Settings.embed_model = embed_model
        Settings.chunk_size = 1024
        Settings.chunk_overlap = 100

        # Set conservative defaults
        Settings.num_output = 512  # Limit output length
        Settings.context_window = 4096  # Context limit

    def _load_api_key(self) -> str:
        """Load API key from secure source."""
        # Try secrets manager first
        api_key = self._load_from_secrets_manager()

        if not api_key:
            # Fall back to environment variable
            api_key = os.environ.get("OPENAI_API_KEY")

        if not api_key:
            raise ConfigurationError("OpenAI API key not configured")

        # Basic validation
        if not api_key.startswith("sk-") or len(api_key) < 20:
            raise ConfigurationError("Invalid API key format")

        return api_key

    def _load_from_secrets_manager(self) -> Optional[str]:
        """Load from cloud secrets manager."""
        try:
            import boto3
            client = boto3.client('secretsmanager')
            response = client.get_secret_value(SecretId='openai-api-key')
            return response['SecretString']
        except Exception:
            return None

    def configure_for_tenant(
        self,
        tenant_id: str,
        model_overrides: Optional[dict] = None
    ) -> None:
        """Configure with tenant-specific settings."""
        # Load tenant-specific API key if using separate keys per tenant
        tenant_key = self._load_tenant_key(tenant_id)

        # Apply model overrides if allowed
        llm_model = self.llm_model
        if model_overrides:
            allowed_models = {"gpt-3.5-turbo", "gpt-4", "gpt-4-turbo"}
            requested_model = model_overrides.get('llm_model')
            if requested_model in allowed_models:
                llm_model = requested_model

        # Configure with tenant settings
        llm = OpenAI(
            model=llm_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            api_key=tenant_key or self._load_api_key()
        )

        Settings.llm = llm

    def _load_tenant_key(self, tenant_id: str) -> Optional[str]:
        """Load tenant-specific API key."""
        # Implementation depends on your key management approach
        return None


# Usage
config = SecureServiceConfiguration(
    llm_model="gpt-4",
    embedding_model="text-embedding-3-small",
    temperature=0.1,
    max_tokens=2048
)

# Apply configuration
config.configure()

# Or configure for specific tenant
config.configure_for_tenant(
    tenant_id="tenant_123",
    model_overrides={'llm_model': 'gpt-4-turbo'}
)
```

**Don't**: Hardcode API keys or use insecure configurations

```python
# VULNERABLE: Hardcoded API key
from llama_index.llms.openai import OpenAI

llm = OpenAI(
    model="gpt-4",
    api_key="sk-proj-abc123..."  # Hardcoded key
)

# VULNERABLE: No timeout or retry limits
llm = OpenAI(model="gpt-4")  # Default may have no timeout

# VULNERABLE: High temperature in production
Settings.llm = OpenAI(
    model="gpt-4",
    temperature=1.0,  # High randomness
    max_tokens=32000  # No output limit
)

# VULNERABLE: User-controlled model selection
llm = OpenAI(model=user_provided_model)  # Can use expensive models
```

**Why**: Hardcoded API keys can be extracted from code repositories. Lack of timeouts enables DoS through slow responses. Unrestricted model selection allows cost attacks. High temperature reduces response predictability.

**Refs**:
- CWE-798 (Use of Hard-coded Credentials)
- CWE-400 (Uncontrolled Resource Consumption)
- OWASP LLM10 (Model Denial of Service)
- NIST AI RMF GOVERN 1.4 (Resource management)

---

## Rule: Citation and Source Tracking

**Level**: `warning`

**When**: Generating responses that include citations or source references

**Do**: Validate citation provenance and verify source authenticity

```python
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from llama_index.core.schema import NodeWithScore, TextNode

@dataclass
class Citation:
    source_id: str
    source_name: str
    content_snippet: str
    page_number: Optional[int]
    confidence: float
    verified: bool

class CitationValidator:
    """Validate and track citations in RAG responses."""

    def __init__(self, trusted_sources: Set[str]):
        self.trusted_sources = trusted_sources

    def extract_and_validate_citations(
        self,
        response_text: str,
        source_nodes: List[NodeWithScore]
    ) -> List[Citation]:
        """Extract citations and validate against source nodes."""
        citations = []

        # Build source map from nodes
        source_map = {}
        for node in source_nodes:
            source_id = node.node.node_id
            source_name = node.node.metadata.get('source', source_id)
            content = node.node.get_content()

            source_map[source_id] = {
                'name': source_name,
                'content': content,
                'score': node.score,
                'metadata': node.node.metadata
            }

        # Validate each source reference in response
        for source_id, source_info in source_map.items():
            citation = self._validate_citation(
                response_text=response_text,
                source_id=source_id,
                source_info=source_info
            )
            citations.append(citation)

        return citations

    def _validate_citation(
        self,
        response_text: str,
        source_id: str,
        source_info: dict
    ) -> Citation:
        """Validate individual citation."""
        source_name = source_info['name']
        content = source_info['content']

        # Check if source is trusted
        is_trusted = any(
            trusted in source_name
            for trusted in self.trusted_sources
        )

        # Check if content was actually used
        content_used = self._check_content_usage(response_text, content)

        # Calculate confidence
        confidence = source_info['score']
        if not is_trusted:
            confidence *= 0.5  # Reduce confidence for untrusted sources
        if not content_used:
            confidence *= 0.3  # Reduce if content not found in response

        return Citation(
            source_id=source_id,
            source_name=source_name,
            content_snippet=content[:200],
            page_number=source_info['metadata'].get('page_number'),
            confidence=confidence,
            verified=is_trusted and content_used
        )

    def _check_content_usage(self, response: str, content: str) -> bool:
        """Check if source content appears in response."""
        # Check for significant overlap
        response_lower = response.lower()
        content_words = set(content.lower().split())
        response_words = set(response_lower.split())

        overlap = len(content_words & response_words)
        if len(content_words) > 0:
            overlap_ratio = overlap / len(content_words)
            return overlap_ratio > 0.3

        return False

    def generate_citation_report(
        self,
        citations: List[Citation]
    ) -> Dict:
        """Generate citation verification report."""
        verified = [c for c in citations if c.verified]
        unverified = [c for c in citations if not c.verified]

        return {
            'total_citations': len(citations),
            'verified_count': len(verified),
            'unverified_count': len(unverified),
            'overall_confidence': sum(c.confidence for c in citations) / len(citations) if citations else 0,
            'verified_sources': [c.source_name for c in verified],
            'unverified_sources': [c.source_name for c in unverified],
            'warnings': self._generate_warnings(citations)
        }

    def _generate_warnings(self, citations: List[Citation]) -> List[str]:
        """Generate warnings for citation issues."""
        warnings = []

        unverified = [c for c in citations if not c.verified]
        if len(unverified) > len(citations) / 2:
            warnings.append("Majority of citations unverified")

        low_confidence = [c for c in citations if c.confidence < 0.5]
        if low_confidence:
            warnings.append(f"{len(low_confidence)} citations with low confidence")

        return warnings


# Usage
validator = CitationValidator(
    trusted_sources={'internal.company.com', 'docs.trusted.org'}
)

# After query
citations = validator.extract_and_validate_citations(
    response_text=str(response),
    source_nodes=response.source_nodes
)

# Generate report
report = validator.generate_citation_report(citations)

if report['unverified_count'] > 0:
    logger.warning(f"Unverified citations: {report['unverified_sources']}")
```

**Don't**: Accept citations without validation

```python
# VULNERABLE: No citation validation
def get_response_with_sources(query: str):
    response = query_engine.query(query)
    return {
        'answer': str(response),
        'sources': [n.node.metadata.get('source') for n in response.source_nodes]
    }
    # Sources may be fabricated or misattributed

# VULNERABLE: No provenance tracking
sources = [node.metadata['source'] for node in nodes]
# No verification that sources are trusted or content was actually used
```

**Why**: LLMs can fabricate or misattribute citations, leading users to trust incorrect information. Unvalidated sources may contain malicious content that gets cited authoritatively.

**Refs**:
- OWASP LLM09 (Overreliance)
- CWE-345 (Insufficient Verification of Data Authenticity)
- NIST AI RMF MAP 2.3 (Transparency)
- ISO/IEC 23894 (AI trustworthiness)

---

## Rule: Agent and Tool Security

**Level**: `strict`

**When**: Using LlamaIndex agents with tool access (QueryEngineTool, FunctionTool, etc.)

**Do**: Sandbox tool execution and validate permissions

```python
from typing import List, Dict, Any, Optional, Callable
from llama_index.core.tools import QueryEngineTool, FunctionTool, ToolMetadata
from llama_index.core.agent import ReActAgent

class SecureToolRegistry:
    """Secure registry for LlamaIndex agent tools."""

    def __init__(self, permission_checker: Callable[[str, str], bool]):
        self.tools: Dict[str, Dict] = {}
        self.permission_checker = permission_checker

    def register_query_tool(
        self,
        name: str,
        query_engine,
        description: str,
        required_permissions: List[str],
        rate_limit: int = 10
    ) -> QueryEngineTool:
        """Register a query engine tool with security controls."""

        # Wrap with security checks
        secure_engine = self._wrap_query_engine(
            query_engine,
            name,
            required_permissions,
            rate_limit
        )

        tool = QueryEngineTool.from_defaults(
            query_engine=secure_engine,
            name=name,
            description=description
        )

        self.tools[name] = {
            'tool': tool,
            'permissions': required_permissions,
            'rate_limit': rate_limit
        }

        return tool

    def register_function_tool(
        self,
        name: str,
        fn: Callable,
        description: str,
        required_permissions: List[str],
        sandboxed: bool = True
    ) -> FunctionTool:
        """Register a function tool with sandboxing."""

        # Wrap function with security
        if sandboxed:
            secure_fn = self._sandbox_function(fn, name, required_permissions)
        else:
            secure_fn = self._wrap_function(fn, name, required_permissions)

        tool = FunctionTool.from_defaults(
            fn=secure_fn,
            name=name,
            description=description
        )

        self.tools[name] = {
            'tool': tool,
            'permissions': required_permissions,
            'sandboxed': sandboxed
        }

        return tool

    def _wrap_query_engine(
        self,
        engine,
        tool_name: str,
        permissions: List[str],
        rate_limit: int
    ):
        """Wrap query engine with security checks."""

        class SecureQueryEngine:
            def __init__(self, base_engine, registry, tool_name, permissions, rate_limit):
                self._engine = base_engine
                self._registry = registry
                self._tool_name = tool_name
                self._permissions = permissions
                self._rate_limit = rate_limit
                self._call_count = 0

            def query(self, query_str: str, user_id: str = None):
                # Check permissions
                if user_id:
                    for perm in self._permissions:
                        if not self._registry.permission_checker(user_id, perm):
                            raise PermissionError(f"Missing permission: {perm}")

                # Check rate limit
                self._call_count += 1
                if self._call_count > self._rate_limit:
                    raise RateLimitError(f"Tool rate limit exceeded: {self._tool_name}")

                # Execute query
                return self._engine.query(query_str)

        return SecureQueryEngine(engine, self, tool_name, permissions, rate_limit)

    def _sandbox_function(
        self,
        fn: Callable,
        tool_name: str,
        permissions: List[str]
    ) -> Callable:
        """Sandbox function execution."""

        def sandboxed_fn(*args, user_id: str = None, **kwargs):
            # Check permissions
            if user_id:
                for perm in permissions:
                    if not self.permission_checker(user_id, perm):
                        raise PermissionError(f"Missing permission: {perm}")

            # Validate arguments
            self._validate_arguments(args, kwargs)

            # Execute in restricted environment
            import resource

            # Set resource limits
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # 5 seconds CPU
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))  # 256MB memory

            try:
                result = fn(*args, **kwargs)

                # Validate output
                self._validate_output(result)

                return result
            except resource.error:
                raise ResourceError(f"Tool exceeded resource limits: {tool_name}")

        return sandboxed_fn

    def _wrap_function(
        self,
        fn: Callable,
        tool_name: str,
        permissions: List[str]
    ) -> Callable:
        """Wrap function with permission checks only."""

        def wrapped_fn(*args, user_id: str = None, **kwargs):
            if user_id:
                for perm in permissions:
                    if not self.permission_checker(user_id, perm):
                        raise PermissionError(f"Missing permission: {perm}")

            return fn(*args, **kwargs)

        return wrapped_fn

    def _validate_arguments(self, args, kwargs) -> None:
        """Validate function arguments for security issues."""
        for arg in args:
            if isinstance(arg, str):
                # Check for command injection patterns
                if any(c in arg for c in [';', '|', '`', '$(']):
                    raise ValueError("Invalid characters in argument")

        for key, value in kwargs.items():
            if isinstance(value, str):
                if any(c in value for c in [';', '|', '`', '$(']):
                    raise ValueError(f"Invalid characters in {key}")

    def _validate_output(self, result) -> None:
        """Validate function output."""
        if isinstance(result, str) and len(result) > 100000:
            raise ValueError("Output exceeds size limit")

    def get_tools_for_user(self, user_id: str) -> List:
        """Get tools available to a specific user."""
        available = []

        for name, info in self.tools.items():
            # Check if user has all required permissions
            has_permissions = all(
                self.permission_checker(user_id, perm)
                for perm in info['permissions']
            )

            if has_permissions:
                available.append(info['tool'])

        return available


# Usage
def check_permission(user_id: str, permission: str) -> bool:
    """Check if user has permission."""
    # Implement your permission logic
    user_permissions = get_user_permissions(user_id)
    return permission in user_permissions

registry = SecureToolRegistry(permission_checker=check_permission)

# Register tools
registry.register_query_tool(
    name="search_docs",
    query_engine=doc_query_engine,
    description="Search internal documents",
    required_permissions=["docs:read"],
    rate_limit=20
)

registry.register_function_tool(
    name="calculate",
    fn=calculator_function,
    description="Perform calculations",
    required_permissions=["tools:calculate"],
    sandboxed=True
)

# Create agent with user-specific tools
user_tools = registry.get_tools_for_user("user_123")
agent = ReActAgent.from_tools(user_tools)
```

**Don't**: Give agents unrestricted tool access

```python
# VULNERABLE: No permission checks
tools = [
    QueryEngineTool.from_defaults(
        query_engine=admin_query_engine,  # Admin access for all
        name="admin_search"
    ),
    FunctionTool.from_defaults(
        fn=execute_shell_command,  # Shell access!
        name="run_command"
    )
]

agent = ReActAgent.from_tools(tools)

# VULNERABLE: No sandboxing
def dangerous_tool(code: str):
    return eval(code)  # Code execution!

tool = FunctionTool.from_defaults(fn=dangerous_tool)

# VULNERABLE: No rate limiting
agent.chat("Run expensive query repeatedly")  # DoS possible
```

**Why**: Agents with unrestricted tools can be manipulated through prompt injection to execute malicious actions, access unauthorized data, or cause resource exhaustion. Tool sandboxing limits blast radius.

**Refs**:
- OWASP LLM08 (Excessive Agency)
- CWE-78 (OS Command Injection)
- CWE-94 (Code Injection)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Multi-Index Query Security

**Level**: `warning`

**When**: Querying across multiple indexes or using ComposableGraph

**Do**: Enforce access controls across all indexes in multi-index queries

```python
from typing import List, Dict, Optional, Set
from llama_index.core import VectorStoreIndex
from llama_index.core.composability import ComposableGraph
from llama_index.core.query_engine import SubQuestionQueryEngine

class SecureMultiIndexManager:
    """Secure manager for multi-index queries."""

    def __init__(self):
        self.indexes: Dict[str, Dict] = {}

    def register_index(
        self,
        index_name: str,
        index: VectorStoreIndex,
        required_permissions: Set[str],
        tenant_id: Optional[str] = None
    ) -> None:
        """Register an index with access controls."""
        self.indexes[index_name] = {
            'index': index,
            'permissions': required_permissions,
            'tenant_id': tenant_id
        }

    def get_authorized_indexes(
        self,
        user_id: str,
        user_permissions: Set[str],
        user_tenant: Optional[str] = None
    ) -> List[str]:
        """Get indexes user is authorized to access."""
        authorized = []

        for index_name, info in self.indexes.items():
            # Check permissions
            if not info['permissions'].issubset(user_permissions):
                continue

            # Check tenant isolation
            if info['tenant_id'] and info['tenant_id'] != user_tenant:
                continue

            authorized.append(index_name)

        return authorized

    def create_secure_query_engine(
        self,
        user_id: str,
        user_permissions: Set[str],
        user_tenant: Optional[str] = None
    ):
        """Create query engine with only authorized indexes."""
        authorized = self.get_authorized_indexes(
            user_id,
            user_permissions,
            user_tenant
        )

        if not authorized:
            raise PermissionError("No authorized indexes available")

        # Create query tools for authorized indexes only
        tools = []
        for index_name in authorized:
            index = self.indexes[index_name]['index']
            query_engine = index.as_query_engine()

            from llama_index.core.tools import QueryEngineTool
            tool = QueryEngineTool.from_defaults(
                query_engine=query_engine,
                name=f"query_{index_name}",
                description=f"Query the {index_name} index"
            )
            tools.append(tool)

        # Create sub-question query engine
        return SubQuestionQueryEngine.from_defaults(
            query_engine_tools=tools,
            use_async=True
        )


class SecureComposableGraph:
    """Secure composable graph with access controls."""

    def __init__(
        self,
        all_indexes: Dict[str, VectorStoreIndex],
        index_permissions: Dict[str, Set[str]]
    ):
        self.all_indexes = all_indexes
        self.index_permissions = index_permissions

    def query(
        self,
        query_str: str,
        user_id: str,
        user_permissions: Set[str]
    ):
        """Query with cross-index access control."""
        # Filter to authorized indexes
        authorized_indexes = {}

        for name, index in self.all_indexes.items():
            required = self.index_permissions.get(name, set())
            if required.issubset(user_permissions):
                authorized_indexes[name] = index

        if not authorized_indexes:
            raise PermissionError("No indexes authorized for user")

        # Create graph with authorized indexes only
        index_summary_dict = {
            name: f"Index containing {name} documents"
            for name in authorized_indexes.keys()
        }

        graph = ComposableGraph.from_indices(
            list(authorized_indexes.values()),
            index_summary_dict
        )

        # Query the graph
        query_engine = graph.as_query_engine()

        response = query_engine.query(query_str)

        # Validate response doesn't leak unauthorized data
        self._validate_response(response, authorized_indexes.keys())

        return response

    def _validate_response(self, response, authorized_indexes) -> None:
        """Validate response only contains authorized sources."""
        if hasattr(response, 'source_nodes'):
            for node in response.source_nodes:
                source_index = node.node.metadata.get('index_name')
                if source_index and source_index not in authorized_indexes:
                    logger.warning(f"Unauthorized index in response: {source_index}")
                    # Remove unauthorized source
                    response.source_nodes.remove(node)


# Usage
manager = SecureMultiIndexManager()

# Register indexes with permissions
manager.register_index(
    "public_docs",
    public_index,
    required_permissions={"docs:read"},
    tenant_id=None
)

manager.register_index(
    "internal_docs",
    internal_index,
    required_permissions={"docs:read", "internal:access"},
    tenant_id=None
)

manager.register_index(
    "tenant_docs",
    tenant_index,
    required_permissions={"docs:read"},
    tenant_id="tenant_123"
)

# Create query engine for user
user_permissions = {"docs:read"}  # No internal:access
query_engine = manager.create_secure_query_engine(
    user_id="user_456",
    user_permissions=user_permissions,
    user_tenant="tenant_123"
)
# User can only query public_docs and their tenant_docs

response = query_engine.query("Find relevant information")
```

**Don't**: Allow cross-index queries without access control

```python
# VULNERABLE: No index-level access control
indexes = [public_index, internal_index, admin_index]
graph = ComposableGraph.from_indices(indexes)
query_engine = graph.as_query_engine()
response = query_engine.query(user_query)  # Access to all indexes

# VULNERABLE: No tenant isolation in multi-index
all_tenant_indexes = load_all_tenant_indexes()
combined = ComposableGraph.from_indices(all_tenant_indexes)
# Queries can retrieve data from any tenant

# VULNERABLE: No response validation
response = multi_index_engine.query(query)
return response  # May contain unauthorized sources
```

**Why**: Multi-index queries can inadvertently expose data from indexes the user shouldn't access. Without per-index authorization, sensitive data can leak through combined search results or cross-tenant contamination.

**Refs**:
- OWASP LLM06 (Sensitive Information Disclosure)
- CWE-284 (Improper Access Control)
- CWE-639 (Authorization Bypass Through User-Controlled Key)
- NIST AI RMF GOVERN 4.2 (Privacy)

---

## Implementation Checklist

### Document Loading
- [ ] Path traversal prevention configured
- [ ] File type allowlist defined
- [ ] File size limits enforced
- [ ] MIME type validation using magic bytes

### Index Persistence
- [ ] Encryption at rest enabled
- [ ] Tenant isolation implemented
- [ ] Integrity verification active
- [ ] Access permissions configured

### Query Processing
- [ ] Input validation and sanitization
- [ ] Prompt injection pattern detection
- [ ] Rate limiting per user
- [ ] Query length limits enforced

### Response Generation
- [ ] Output validation enabled
- [ ] Citation verification active
- [ ] XSS pattern filtering
- [ ] Response length limits

### Service Configuration
- [ ] API keys loaded from secure sources
- [ ] Request timeouts configured
- [ ] Model selection restricted
- [ ] Rate limits applied

### Agent Security
- [ ] Tool permissions validated
- [ ] Function sandboxing enabled
- [ ] Resource limits configured
- [ ] Tool rate limiting active

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01 | Initial LlamaIndex security rules |

---

## References

### Standards
- OWASP LLM Top 10 v1.1 (2023)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- NIST AI Risk Management Framework (AI RMF 1.0)
- NIST Secure Software Development Framework (SSDF)

### CWE References
- CWE-20: Improper Input Validation
- CWE-22: Path Traversal
- CWE-78: OS Command Injection
- CWE-79: Cross-site Scripting
- CWE-94: Code Injection
- CWE-200: Exposure of Sensitive Information
- CWE-284: Improper Access Control
- CWE-311: Missing Encryption of Sensitive Data
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-354: Improper Validation of Integrity Check Value
- CWE-400: Uncontrolled Resource Consumption
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-798: Use of Hard-coded Credentials
