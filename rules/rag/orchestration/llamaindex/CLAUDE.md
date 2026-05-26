# LlamaIndex Security Rules

Security rules for LlamaIndex RAG orchestration framework (llama-index-core 0.10+, split-package layout).
These rules extend the core RAG security patterns with LlamaIndex-specific implementations.

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
| Multi-Index Query Security | `warning` | Cross-index access control via router/sub-question patterns |
| QueryFusionRetriever Injection Surface | `strict` | Sanitize generated sub-queries before retrieval |
| PromptTemplate Variable Injection | `strict` | Validate template variables; never interpolate raw user input |
| HuggingFace Embedding trust_remote_code | `strict` | Deny trust_remote_code=True on untrusted models |
| Node Post-Processor Trust Boundary | `warning` | Validate post-processor inputs at tenant boundary |

---

## Rule: Secure Document Loader Configuration

**Level**: `strict`

**When**: Loading documents using LlamaIndex readers (SimpleDirectoryReader, PDFReader, etc.)

**Do**: Configure document loaders with allowlists, size limits, and path validation

```python
import os
import magic
import logging
from pathlib import Path
from typing import List, Optional, Set
from llama_index.core import SimpleDirectoryReader
from llama_index.core.schema import Document

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    pass


class SecureDocumentLoader:
    """Secure wrapper for LlamaIndex document loading."""

    ALLOWED_EXTENSIONS: Set[str] = {".txt", ".pdf", ".md", ".docx", ".html"}
    ALLOWED_MIME_TYPES: Set[str] = {
        "text/plain",
        "application/pdf",
        "text/markdown",
        "text/html",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50 MB
    MAX_FILES_PER_LOAD: int = 100

    def __init__(
        self,
        base_directory: str,
        allowed_subdirs: Optional[List[str]] = None,
    ):
        self.base_directory = Path(base_directory).resolve()
        self.allowed_subdirs = allowed_subdirs or []

        if not self.base_directory.exists():
            raise ValueError(f"Base directory does not exist: {base_directory}")

    def _validate_path(self, file_path: Path) -> None:
        """Validate file path is within allowed boundaries."""
        resolved = file_path.resolve()

        try:
            resolved.relative_to(self.base_directory)
        except ValueError:
            raise SecurityError(f"Path traversal attempt detected: {file_path}")

        if self.allowed_subdirs:
            in_allowed = any(
                str(resolved).startswith(str(self.base_directory / subdir))
                for subdir in self.allowed_subdirs
            )
            if not in_allowed:
                raise SecurityError(
                    f"Path not in allowed subdirectories: {file_path}"
                )

    def _validate_file(self, file_path: Path) -> None:
        """Validate individual file before loading."""
        if file_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise SecurityError(
                f"File extension not allowed: {file_path.suffix}"
            )

        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise SecurityError(f"File exceeds size limit: {file_size} bytes")

        mime_type = magic.from_file(str(file_path), mime=True)
        if mime_type not in self.ALLOWED_MIME_TYPES:
            raise SecurityError(f"MIME type not allowed: {mime_type}")

    def load_documents(
        self,
        input_dir: Optional[str] = None,
        input_files: Optional[List[str]] = None,
        recursive: bool = False,
        exclude_hidden: bool = True,
    ) -> List[Document]:
        """Securely load documents with validation."""
        files_to_load: List[str] = []

        if input_files:
            for file_path in input_files:
                path = Path(file_path)
                self._validate_path(path)
                self._validate_file(path)
                files_to_load.append(str(path))

        elif input_dir:
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
                        logger.warning("Skipping file: %s", e)

        if len(files_to_load) > self.MAX_FILES_PER_LOAD:
            raise SecurityError(
                f"Too many files: {len(files_to_load)} exceeds limit of "
                f"{self.MAX_FILES_PER_LOAD}"
            )

        documents: List[Document] = []
        if files_to_load:
            reader = SimpleDirectoryReader(input_files=files_to_load)
            documents = reader.load_data()
            logger.info(
                "Loaded %d documents from %d files",
                len(documents),
                len(files_to_load),
            )

        return documents


# Usage
loader = SecureDocumentLoader(
    base_directory="/app/documents",
    allowed_subdirs=["public", "internal"],
)

documents = loader.load_documents(
    input_dir="/app/documents/public",
    recursive=True,
)
```

**Don't**: Load documents without path validation or file type restrictions

```python
# VULNERABLE: No path validation — allows traversal
from llama_index.core import SimpleDirectoryReader

def load_docs_unsafe(user_path: str):
    reader = SimpleDirectoryReader(input_dir=user_path)  # ../../../etc/passwd
    return reader.load_data()

# VULNERABLE: No file type restrictions
reader = SimpleDirectoryReader(input_dir="/uploads", recursive=True)
documents = reader.load_data()  # May load malicious files
```

**Why**: Document loaders with unrestricted access enable path traversal attacks, loading of malicious file types, and denial of service through large files. Attackers can exfiltrate sensitive system files or inject malicious content into the RAG system.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-22 (Path Traversal)
- CWE-434 (Unrestricted Upload of File with Dangerous Type)
- MITRE ATLAS AML.T0020 (Poison Training Data)

---

## Rule: Index Persistence Security

**Level**: `strict`

**When**: Persisting or loading VectorStoreIndex to/from disk or external storage

**Do**: Encrypt persisted indexes, verify integrity, and pass settings via `Settings` global (not the removed `service_context` kwarg)

```python
import hashlib
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from llama_index.core import Settings, StorageContext, VectorStoreIndex, load_index_from_storage
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    pass


class SecureIndexStorage:
    """Secure storage wrapper for LlamaIndex persistence.

    Uses the Settings singleton (llama-index-core 0.10+) instead of the
    removed service_context kwarg on load_index_from_storage.
    """

    def __init__(
        self,
        storage_dir: str,
        encryption_key: Optional[bytes] = None,
        tenant_id: Optional[str] = None,
    ):
        self.storage_dir = Path(storage_dir)
        self.tenant_id = tenant_id
        self.cipher = Fernet(encryption_key) if encryption_key else None

        if tenant_id:
            self.index_dir = self.storage_dir / self._hash_tenant(tenant_id)
        else:
            self.index_dir = self.storage_dir / "default"

        self.index_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.index_dir, 0o700)

    def _hash_tenant(self, tenant_id: str) -> str:
        return hashlib.sha256(tenant_id.encode()).hexdigest()[:32]

    def _encrypt_file(self, file_path: Path) -> None:
        if not self.cipher:
            return
        data = file_path.read_bytes()
        file_path.write_bytes(self.cipher.encrypt(data))

    def _decrypt_file(self, file_path: Path) -> bytes:
        data = file_path.read_bytes()
        return self.cipher.decrypt(data) if self.cipher else data

    def persist_index(self, index: VectorStoreIndex, index_name: str) -> str:
        """Persist index with per-file encryption and an integrity manifest."""
        if not index_name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Invalid index name — use alphanumeric characters only")

        persist_dir = self.index_dir / index_name
        persist_dir.mkdir(exist_ok=True)

        index.storage_context.persist(persist_dir=str(persist_dir))

        for file_path in persist_dir.glob("*.json"):
            self._encrypt_file(file_path)

        self._create_integrity_hash(persist_dir)

        logger.info("Index persisted: %s tenant: %s", index_name, self.tenant_id)
        return str(persist_dir)

    def load_index(self, index_name: str) -> VectorStoreIndex:
        """Load and decrypt an index, checking integrity first.

        Model settings come from the Settings singleton configured at startup,
        not from the removed service_context kwarg.
        """
        persist_dir = self.index_dir / index_name
        if not persist_dir.exists():
            raise FileNotFoundError(f"Index not found: {index_name}")

        if not self._verify_integrity(persist_dir):
            raise SecurityError(f"Index integrity check failed: {index_name}")

        temp_dir = self._decrypt_to_temp(persist_dir)
        try:
            storage_context = StorageContext.from_defaults(persist_dir=str(temp_dir))
            # Settings.llm / Settings.embed_model are used automatically;
            # do NOT pass service_context= (removed in 0.10+).
            index = load_index_from_storage(storage_context)
            logger.info("Index loaded: %s tenant: %s", index_name, self.tenant_id)
            return index
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _create_integrity_hash(self, persist_dir: Path) -> None:
        hashes = {
            fp.name: hashlib.sha256(fp.read_bytes()).hexdigest()
            for fp in sorted(persist_dir.glob("*.json"))
        }
        (persist_dir / ".integrity").write_text(json.dumps(hashes))

    def _verify_integrity(self, persist_dir: Path) -> bool:
        integrity_file = persist_dir / ".integrity"
        if not integrity_file.exists():
            return False
        expected = json.loads(integrity_file.read_text())
        for filename, expected_hash in expected.items():
            fp = persist_dir / filename
            if not fp.exists():
                return False
            if hashlib.sha256(fp.read_bytes()).hexdigest() != expected_hash:
                logger.warning("Integrity mismatch: %s", filename)
                return False
        return True

    def _decrypt_to_temp(self, persist_dir: Path) -> Path:
        temp_dir = Path(tempfile.mkdtemp())
        for fp in persist_dir.glob("*.json"):
            (temp_dir / fp.name).write_bytes(self._decrypt_file(fp))
        return temp_dir


# Startup: configure Settings once; all load_index_from_storage calls pick it up.
Settings.llm = OpenAI(model="gpt-4o", api_key=os.environ["OPENAI_API_KEY"])
Settings.embed_model = OpenAIEmbedding(
    model="text-embedding-3-small",
    api_key=os.environ["OPENAI_API_KEY"],
)

storage = SecureIndexStorage(
    storage_dir="/app/indexes",
    encryption_key=os.environ["INDEX_ENCRYPTION_KEY"].encode(),
    tenant_id="tenant_123",
)

storage.persist_index(index, "my_index")
loaded = storage.load_index("my_index")
```

**Don't**: Pass `service_context=` to `load_index_from_storage`, skip encryption, or skip integrity checks

```python
# BROKEN: service_context kwarg removed in 0.10+
index = load_index_from_storage(storage_context, service_context=svc_ctx)

# VULNERABLE: Unencrypted persistence
index.storage_context.persist(persist_dir="./storage")

# VULNERABLE: No integrity verification
storage_context = StorageContext.from_defaults(persist_dir=user_provided_path)
index = load_index_from_storage(storage_context)  # May load tampered index
```

**Why**: Persisted indexes contain embeddings that can leak information about the original content. Without encryption, attackers with storage access can extract sensitive data. Without integrity checks, indexes can be tampered to inject malicious content. The removed `service_context` kwarg causes a runtime `TypeError` in 0.10+ deployments.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-311 (Missing Encryption of Sensitive Data)
- CWE-354 (Improper Validation of Integrity Check Value)
- NIST AI RMF GOVERN 4.2 (Privacy)

---

## Rule: Query Engine Input Validation

**Level**: `strict`

**When**: Processing user queries through LlamaIndex query engines

**Do**: Validate and sanitize all query inputs; enforce per-user (not global) rate limits

```python
import logging
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional

from llama_index.core import VectorStoreIndex

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    pass


class SecureQueryEngine:
    """Security wrapper for LlamaIndex query engines."""

    MAX_QUERY_LENGTH = 2000
    MAX_QUERIES_PER_MINUTE = 60

    INJECTION_PATTERNS = [
        r"ignore\s+(previous|above|all)\s+instructions?",
        r"disregard\s+(everything|all|previous)",
        r"forget\s+(everything|all|your)",
        r"you\s+are\s+now\s+[a-z]+",
        r"act\s+as\s+(if|a|an)",
        r"system\s*:\s*",
        r"assistant\s*:\s*",
        r"\[INST\]|\[/INST\]",
        r"<<SYS>>|<</SYS>>",
        r"<\|im_start\|>|<\|im_end\|>",
    ]

    def __init__(
        self,
        index: VectorStoreIndex,
        similarity_top_k: int = 5,
        response_mode: str = "compact",
    ):
        self.query_engine = index.as_query_engine(
            similarity_top_k=similarity_top_k,
            response_mode=response_mode,
        )
        # Per-user timestamp store — a flat list would conflate all users.
        self._user_query_times: Dict[str, List[float]] = defaultdict(list)
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]

    def _validate_query(self, query: str) -> str:
        if not query or not isinstance(query, str):
            raise ValueError("Query must be a non-empty string")

        if len(query) > self.MAX_QUERY_LENGTH:
            raise ValueError(
                f"Query exceeds maximum length of {self.MAX_QUERY_LENGTH}"
            )

        query = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", query)

        for pattern in self._compiled_patterns:
            if pattern.search(query):
                logger.warning("Injection pattern detected in query")
                query = pattern.sub("[FILTERED]", query)

        return query.strip()

    def _check_rate_limit(self, user_id: str) -> bool:
        """Enforce per-user rate limit — each user has an independent window."""
        current_time = time.time()
        window = self._user_query_times[user_id]

        # Evict timestamps outside the 60-second window.
        self._user_query_times[user_id] = [
            t for t in window if current_time - t < 60
        ]

        if len(self._user_query_times[user_id]) >= self.MAX_QUERIES_PER_MINUTE:
            return False

        self._user_query_times[user_id].append(current_time)
        return True

    def _sanitize_filters(self, filters: dict) -> dict:
        sanitized = {}
        for key, value in filters.items():
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", key):
                continue
            if key.startswith("_"):
                continue
            sanitized[key] = value
        return sanitized

    def _validate_response(self, response) -> None:
        response_text = str(response)
        leakage_patterns = [
            r"api[_-]?key\s*[=:]\s*\S+",
            r"password\s*[=:]\s*\S+",
            r"secret\s*[=:]\s*\S+",
        ]
        for pattern in leakage_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                logger.warning("Potential sensitive data in response")

    def query(
        self,
        query_str: str,
        user_id: Optional[str] = None,
        metadata_filters: Optional[dict] = None,
    ):
        if user_id and not self._check_rate_limit(user_id):
            raise RateLimitError("Query rate limit exceeded")

        validated_query = self._validate_query(query_str)

        if metadata_filters:
            metadata_filters = self._sanitize_filters(metadata_filters)

        try:
            response = self.query_engine.query(validated_query)
            self._validate_response(response)
            return response
        except Exception as e:
            logger.error("Query execution error: %s", e)
            raise


# Usage
secure_engine = SecureQueryEngine(
    index=vector_index,
    similarity_top_k=5,
    response_mode="compact",
)

response = secure_engine.query(
    query_str="What are the project requirements?",
    user_id="user_123",
)
```

**Don't**: Pass user queries directly to query engines or share rate-limit state across users

```python
# VULNERABLE: No input validation
query_engine = index.as_query_engine()
response = query_engine.query(user_input)

# VULNERABLE: Flat list shared across all users — one heavy user blocks everyone
class BadEngine:
    _query_times: List[float] = []  # Wrong: not keyed by user

    def _check_rate_limit(self, user_id: str) -> bool:
        self._query_times = [t for t in self._query_times if time.time() - t < 60]
        if len(self._query_times) >= 60:
            return False
        self._query_times.append(time.time())
        return True

# VULNERABLE: No filter sanitization
response = query_engine.query(query, filters=user_provided_filters)
```

**Why**: Unvalidated queries enable prompt injection. A flat rate-limit list lets one user exhaust the budget for all others (IDOR on rate state). Unsanitized filters can bypass access controls.

**Refs**:
- OWASP LLM Top 10:2025 LLM01 (Prompt Injection)
- CWE-20 (Improper Input Validation)
- CWE-400 (Uncontrolled Resource Consumption)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Response Synthesizer Security

**Level**: `warning`

**When**: Using response synthesizers to generate answers from retrieved context

**Do**: Validate synthesizer outputs and verify citations

```python
import logging
import re
from typing import Dict, List, Optional

from llama_index.core.response_synthesizers import ResponseMode, get_response_synthesizer
from llama_index.core.schema import NodeWithScore

logger = logging.getLogger(__name__)


class SecureResponseSynthesizer:
    """Secure wrapper for LlamaIndex response synthesis."""

    MAX_RESPONSE_LENGTH = 10000

    HARMFUL_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"data:text/html",
    ]

    def __init__(
        self,
        response_mode: str = "compact",
        use_async: bool = False,
    ):
        self.synthesizer = get_response_synthesizer(
            response_mode=ResponseMode(response_mode),
            use_async=use_async,
        )
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.HARMFUL_PATTERNS
        ]

    def synthesize(
        self,
        query: str,
        nodes: List[NodeWithScore],
        verify_citations: bool = True,
    ):
        validated_nodes = self._validate_nodes(nodes)

        response = self.synthesizer.synthesize(query=query, nodes=validated_nodes)

        response_text = str(response)
        if len(response_text) > self.MAX_RESPONSE_LENGTH:
            logger.warning("Response truncated due to length")
            response_text = response_text[: self.MAX_RESPONSE_LENGTH]

        response_text = self._sanitize_output(response_text)

        if verify_citations:
            citations = self._verify_citations(response, validated_nodes)
            response.metadata = response.metadata or {}
            response.metadata["verified_citations"] = citations

        return response

    def _validate_nodes(self, nodes: List[NodeWithScore]) -> List[NodeWithScore]:
        validated = []
        for node in nodes:
            content = node.node.get_content()
            if self._contains_injection(content):
                logger.warning(
                    "Skipping node with injection pattern: %s", node.node.node_id
                )
                continue
            if not (0.0 <= node.score <= 1.0):
                logger.warning("Invalid score for node: %s", node.score)
                continue
            validated.append(node)
        return validated

    def _contains_injection(self, content: str) -> bool:
        patterns = [
            r"ignore\s+previous\s+instructions",
            r"system\s*:\s*",
            r"\[INST\]",
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in patterns)

    def _sanitize_output(self, text: str) -> str:
        for pattern in self._compiled_patterns:
            text = pattern.sub("[REMOVED]", text)
        text = text.replace("<", "&lt;").replace(">", "&gt;")
        return text

    def _verify_citations(
        self, response, nodes: List[NodeWithScore]
    ) -> Dict[str, bool]:
        citations = {}
        response_lower = str(response).lower()
        for node in nodes:
            source = node.node.metadata.get("source", node.node.node_id)
            snippet = node.node.get_content()[:100].lower()
            citations[source] = snippet in response_lower or source.lower() in response_lower
        return citations


# Usage
secure_synthesizer = SecureResponseSynthesizer(response_mode="tree_summarize")

response = secure_synthesizer.synthesize(
    query="Summarize the main findings",
    nodes=retrieved_nodes,
    verify_citations=True,
)

if response.metadata.get("verified_citations"):
    for source, verified in response.metadata["verified_citations"].items():
        if not verified:
            logger.warning("Unverified citation: %s", source)
```

**Don't**: Use response synthesizers without output validation

```python
# VULNERABLE: No output validation
synthesizer = get_response_synthesizer()
response = synthesizer.synthesize(query, nodes)
return str(response)  # May contain XSS, injection patterns

# VULNERABLE: No node validation before synthesis
def synthesize_unsafe(query: str, nodes: list):
    return synthesizer.synthesize(query, nodes)  # Nodes may carry poisoned content
```

**Why**: Response synthesizers propagate malicious content from retrieved nodes into final outputs. Without validation, XSS payloads, prompt injection patterns, or fabricated citations can reach end users.

**Refs**:
- OWASP LLM Top 10:2025 LLM01 (Prompt Injection)
- OWASP LLM Top 10:2025 LLM05 (Improper Output Handling)
- CWE-79 (Cross-site Scripting)
- CWE-20 (Improper Input Validation)

---

## Rule: Node Parser Security

**Level**: `warning`

**When**: Parsing documents into nodes/chunks for indexing

**Do**: Use `SentenceSplitter` (0.10+ replacement for the removed `SimpleNodeParser`); enforce chunk limits and sanitize metadata

```python
import html
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from llama_index.core.node_parser import SentenceSplitter  # SimpleNodeParser removed in 0.10+
from llama_index.core.schema import Document, TextNode

logger = logging.getLogger(__name__)


class SecureNodeParser:
    """Secure node parser.

    SimpleNodeParser was removed in llama-index-core 0.10+.
    SentenceSplitter is the direct replacement from llama_index.core.node_parser.
    """

    MAX_CHUNK_SIZE = 2048
    MIN_CHUNK_SIZE = 50
    MAX_CHUNK_OVERLAP = 200
    MAX_NODES_PER_DOCUMENT = 500

    METADATA_ALLOWLIST = {
        "source",
        "file_name",
        "page_number",
        "creation_date",
        "author",
        "title",
        "section",
        "category",
    }

    def __init__(
        self,
        chunk_size: int = 1024,
        chunk_overlap: int = 100,
        include_metadata: bool = True,
    ):
        if not (self.MIN_CHUNK_SIZE <= chunk_size <= self.MAX_CHUNK_SIZE):
            raise ValueError(
                f"chunk_size must be between {self.MIN_CHUNK_SIZE} and "
                f"{self.MAX_CHUNK_SIZE}"
            )
        if chunk_overlap > self.MAX_CHUNK_OVERLAP:
            raise ValueError(f"chunk_overlap must be <= {self.MAX_CHUNK_OVERLAP}")
        if chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be less than chunk_size")

        # SentenceSplitter is the 0.10+ replacement for SimpleNodeParser.
        self.parser = SentenceSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            include_metadata=include_metadata,
        )
        self.include_metadata = include_metadata

    def parse_documents(
        self,
        documents: List[Document],
        tenant_id: Optional[str] = None,
    ) -> List[TextNode]:
        all_nodes: List[TextNode] = []

        for doc in documents:
            if doc.metadata:
                doc.metadata = self._sanitize_metadata(doc.metadata)

            if tenant_id:
                doc.metadata = doc.metadata or {}
                doc.metadata["_tenant_id"] = tenant_id
                doc.metadata["_indexed_at"] = datetime.now(timezone.utc).isoformat()

            nodes = self.parser.get_nodes_from_documents([doc])

            if len(nodes) > self.MAX_NODES_PER_DOCUMENT:
                logger.warning(
                    "Document produced too many nodes: %d, truncating to %d",
                    len(nodes),
                    self.MAX_NODES_PER_DOCUMENT,
                )
                nodes = nodes[: self.MAX_NODES_PER_DOCUMENT]

            for node in nodes:
                validated = self._validate_node(node)
                if validated:
                    all_nodes.append(validated)

        return all_nodes

    def _sanitize_metadata(self, metadata: dict) -> dict:
        sanitized = {}
        for key, value in metadata.items():
            if key.startswith("_"):
                sanitized[key] = value
                continue
            if key.lower() in self.METADATA_ALLOWLIST:
                if isinstance(value, str):
                    value = self._sanitize_string(value)
                sanitized[key] = value
        return sanitized

    def _sanitize_string(self, value: str) -> str:
        value = value[:1000]
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
        return html.escape(value)

    def _validate_node(self, node: TextNode) -> Optional[TextNode]:
        content = node.get_content()
        if len(content.strip()) < 10:
            return None
        if self._is_suspicious(content):
            logger.warning("Suspicious node content detected: %s", node.node_id)
            node.metadata["_flagged"] = True
        return node

    def _is_suspicious(self, content: str) -> bool:
        patterns = [
            r"base64,[A-Za-z0-9+/=]{100,}",
            r"(?:0x[0-9a-f]{2}){20,}",
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in patterns)


# Usage
parser = SecureNodeParser(chunk_size=1024, chunk_overlap=100, include_metadata=True)

nodes = parser.parse_documents(
    documents=loaded_documents,
    tenant_id="tenant_123",
)
```

**Don't**: Import or use `SimpleNodeParser` (removed) or apply no limits

```python
# BROKEN: SimpleNodeParser removed in 0.10+
from llama_index.core.node_parser import SimpleNodeParser  # ImportError
parser = SimpleNodeParser.from_defaults(chunk_size=512)

# VULNERABLE: Unrestricted chunk sizes
parser = SentenceSplitter(chunk_size=100000, chunk_overlap=50000)

# VULNERABLE: No metadata sanitization or node count limits
nodes = parser.get_nodes_from_documents(documents)
```

**Why**: `SimpleNodeParser` raises `ImportError` in current llama-index-core. Large chunk sizes overwhelm embedding models and increase attack surface. Unsanitized metadata can carry XSS or injection payloads. Unlimited node generation enables denial of service.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-400 (Uncontrolled Resource Consumption)
- CWE-79 (Cross-site Scripting)
- CWE-117 (Improper Output Neutralization for Logs)

---

## Rule: Callback Handler Security

**Level**: `warning`

**When**: Using LlamaIndex callback handlers for observability

**Do**: Sanitize callback data and use secure logging practices

```python
import json
import logging
import re
from typing import Any, Dict, List, Optional

from llama_index.core import Settings
from llama_index.core.callbacks import CallbackManager, CBEventType, LlamaDebugHandler
from llama_index.core.callbacks.base import BaseCallbackHandler

logger = logging.getLogger(__name__)


class SecureCallbackHandler(BaseCallbackHandler):
    """Security-aware callback handler for LlamaIndex."""

    SENSITIVE_PATTERNS = [
        r"api[_-]?key\s*[=:]\s*['\"]?[\w-]+",
        r"password\s*[=:]\s*['\"]?[\w-]+",
        r"secret\s*[=:]\s*['\"]?[\w-]+",
        r"token\s*[=:]\s*['\"]?[\w-]+",
        r"bearer\s+[\w-]+",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    ]

    def __init__(
        self,
        log_sensitive: bool = False,
        max_content_length: int = 500,
    ):
        super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
        self.log_sensitive = log_sensitive
        self.max_content_length = max_content_length
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_PATTERNS
        ]

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        safe_payload = self._sanitize_payload(payload)
        logger.info(
            "Event start: %s",
            event_type.value,
            extra={"event_id": event_id, "parent_id": parent_id, "payload": safe_payload},
        )
        return event_id

    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        safe_payload = self._sanitize_payload(payload)
        logger.info(
            "Event end: %s",
            event_type.value,
            extra={"event_id": event_id, "payload": safe_payload},
        )

    def _sanitize_payload(self, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not payload:
            return {}
        sanitized = {}
        for key, value in payload.items():
            if any(
                s in key.lower()
                for s in ["password", "secret", "token", "key", "credential"]
            ):
                sanitized[key] = "[REDACTED]"
                continue
            if isinstance(value, str):
                sanitized[key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_payload(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_string(str(v))[:100] if isinstance(v, str) else "[OBJECT]"
                    for v in value[:10]
                ]
            else:
                sanitized[key] = str(value)[: self.max_content_length]
        return sanitized

    def _sanitize_string(self, value: str) -> str:
        value = value[: self.max_content_length]
        if not self.log_sensitive:
            for pattern in self._compiled_patterns:
                value = pattern.sub("[REDACTED]", value)
        return value.replace("\n", " ").replace("\r", "")

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        pass

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        pass


# Usage
secure_handler = SecureCallbackHandler(log_sensitive=False, max_content_length=500)
callback_manager = CallbackManager([secure_handler])
Settings.callback_manager = callback_manager
```

**Don't**: Log all content or expose sensitive data through debug handlers in production

```python
# VULNERABLE: Logs full prompts and responses including PII/secrets
debug_handler = LlamaDebugHandler(print_trace_on_end=True)

# VULNERABLE: No redaction
def on_event_end(self, event_type, payload):
    logger.info("Payload: %s", json.dumps(payload))  # Logs everything

# VULNERABLE: Key exposed in payload
callback_manager.on_event_start(
    event_type=CBEventType.LLM,
    payload={"prompt": f"API Key: {api_key}, Query: {query}"},
)
```

**Why**: Callback handlers can inadvertently log API keys, PII, and proprietary data. These logs may be accessible to unauthorized parties or stored in insecure systems.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-532 (Insertion of Sensitive Information into Log File)
- CWE-200 (Exposure of Sensitive Information)
- NIST SSDF PW.1.1 (Secure logging)

---

## Rule: Service Context Configuration

**Level**: `strict`

**When**: Configuring LlamaIndex `Settings` with LLM and embedding models

**Do**: Use secure model configuration with authentication and rate limiting via the `Settings` singleton (the `ServiceContext` class is removed in 0.10+)

```python
import os
from typing import Optional

from llama_index.core import Settings
from llama_index.embeddings.openai import OpenAIEmbedding  # split-package layout
from llama_index.llms.openai import OpenAI               # split-package layout


class ConfigurationError(Exception):
    pass


class SecureServiceConfiguration:
    """Secure configuration for LlamaIndex services.

    ServiceContext is removed in 0.10+; use the Settings global instead.
    Import embeddings from llama_index.embeddings.<provider> and LLMs from
    llama_index.llms.<provider> (split-package layout introduced in 0.10).
    """

    ALLOWED_MODELS = {"gpt-3.5-turbo", "gpt-4", "gpt-4o", "gpt-4-turbo"}

    def __init__(
        self,
        llm_model: str = "gpt-4o",
        embedding_model: str = "text-embedding-3-small",
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        if llm_model not in self.ALLOWED_MODELS:
            raise ConfigurationError(f"Model not in allowlist: {llm_model}")
        self.llm_model = llm_model
        self.embedding_model = embedding_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def configure(self) -> None:
        api_key = self._load_api_key()

        Settings.llm = OpenAI(
            model=self.llm_model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            api_key=api_key,
            timeout=30.0,
            max_retries=3,
            additional_kwargs={"seed": 42},
        )

        Settings.embed_model = OpenAIEmbedding(
            model=self.embedding_model,
            api_key=api_key,
            timeout=30.0,
            max_retries=3,
        )

        Settings.chunk_size = 1024
        Settings.chunk_overlap = 100
        Settings.num_output = 512
        Settings.context_window = 4096

    def _load_api_key(self) -> str:
        api_key = self._load_from_secrets_manager() or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ConfigurationError("OpenAI API key not configured")
        if not api_key.startswith("sk-") or len(api_key) < 20:
            raise ConfigurationError("Invalid API key format")
        return api_key

    def _load_from_secrets_manager(self) -> Optional[str]:
        try:
            import boto3
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId="openai-api-key")
            return response["SecretString"]
        except Exception:
            return None


# Usage
config = SecureServiceConfiguration(
    llm_model="gpt-4o",
    embedding_model="text-embedding-3-small",
    temperature=0.1,
    max_tokens=2048,
)
config.configure()
```

**Don't**: Hardcode API keys, skip timeouts, or allow user-controlled model selection

```python
# BROKEN: ServiceContext removed in 0.10+
from llama_index.core import ServiceContext
svc_ctx = ServiceContext.from_defaults(llm=llm)  # TypeError at import time

# BROKEN: Old monolithic import (pre-0.10)
from llama_index.embeddings import OpenAIEmbedding  # ImportError in 0.10+

# VULNERABLE: Hardcoded key
llm = OpenAI(model="gpt-4", api_key="sk-proj-abc123...")

# VULNERABLE: User-controlled model selection
llm = OpenAI(model=user_provided_model)
```

**Why**: `ServiceContext` is fully removed in 0.10+; code referencing it raises `TypeError` at startup. The old monolithic `llama_index.embeddings` path raises `ImportError`. Hardcoded keys can be extracted from source. Unrestricted model selection allows cost attacks.

**Refs**:
- CWE-798 (Use of Hard-coded Credentials)
- CWE-400 (Uncontrolled Resource Consumption)
- OWASP LLM Top 10:2025 LLM04 (Model Denial of Service)
- NIST AI RMF GOVERN 1.4 (Resource management)

---

## Rule: Citation and Source Tracking

**Level**: `warning`

**When**: Generating responses that include citations or source references

**Do**: Validate citation provenance and verify source authenticity

```python
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from llama_index.core.schema import NodeWithScore, TextNode

logger = logging.getLogger(__name__)


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
        source_nodes: List[NodeWithScore],
    ) -> List[Citation]:
        source_map = {
            node.node.node_id: {
                "name": node.node.metadata.get("source", node.node.node_id),
                "content": node.node.get_content(),
                "score": node.score,
                "metadata": node.node.metadata,
            }
            for node in source_nodes
        }

        return [
            self._validate_citation(response_text, sid, info)
            for sid, info in source_map.items()
        ]

    def _validate_citation(
        self,
        response_text: str,
        source_id: str,
        source_info: dict,
    ) -> Citation:
        source_name = source_info["name"]
        content = source_info["content"]

        is_trusted = any(t in source_name for t in self.trusted_sources)
        content_used = self._check_content_usage(response_text, content)

        confidence = source_info["score"]
        if not is_trusted:
            confidence *= 0.5
        if not content_used:
            confidence *= 0.3

        return Citation(
            source_id=source_id,
            source_name=source_name,
            content_snippet=content[:200],
            page_number=source_info["metadata"].get("page_number"),
            confidence=confidence,
            verified=is_trusted and content_used,
        )

    def _check_content_usage(self, response: str, content: str) -> bool:
        response_words = set(response.lower().split())
        content_words = set(content.lower().split())
        if not content_words:
            return False
        return len(content_words & response_words) / len(content_words) > 0.3

    def generate_citation_report(self, citations: List[Citation]) -> Dict:
        verified = [c for c in citations if c.verified]
        unverified = [c for c in citations if not c.verified]
        return {
            "total_citations": len(citations),
            "verified_count": len(verified),
            "unverified_count": len(unverified),
            "overall_confidence": (
                sum(c.confidence for c in citations) / len(citations) if citations else 0
            ),
            "verified_sources": [c.source_name for c in verified],
            "unverified_sources": [c.source_name for c in unverified],
            "warnings": self._generate_warnings(citations),
        }

    def _generate_warnings(self, citations: List[Citation]) -> List[str]:
        warnings = []
        unverified = [c for c in citations if not c.verified]
        if len(unverified) > len(citations) / 2:
            warnings.append("Majority of citations unverified")
        low = [c for c in citations if c.confidence < 0.5]
        if low:
            warnings.append(f"{len(low)} citations with low confidence")
        return warnings


# Usage
validator = CitationValidator(trusted_sources={"internal.company.com", "docs.trusted.org"})
citations = validator.extract_and_validate_citations(
    response_text=str(response),
    source_nodes=response.source_nodes,
)
report = validator.generate_citation_report(citations)
if report["unverified_count"] > 0:
    logger.warning("Unverified citations: %s", report["unverified_sources"])
```

**Don't**: Accept citations without validation

```python
# VULNERABLE: No citation validation — sources may be fabricated
def get_response_with_sources(query: str):
    response = query_engine.query(query)
    return {
        "answer": str(response),
        "sources": [n.node.metadata.get("source") for n in response.source_nodes],
    }

# VULNERABLE: No provenance tracking
sources = [node.metadata["source"] for node in nodes]
```

**Why**: LLMs can fabricate or misattribute citations, leading users to trust incorrect information. Unvalidated sources may contain malicious content cited authoritatively.

**Refs**:
- OWASP LLM Top 10:2025 LLM09 (Misinformation)
- CWE-345 (Insufficient Verification of Data Authenticity)
- NIST AI RMF MAP 2.3 (Transparency)
- ISO/IEC 23894 (AI trustworthiness)

---

## Rule: Agent and Tool Security

**Level**: `strict`

**When**: Using LlamaIndex agents with tool access (QueryEngineTool, FunctionTool, etc.)

**Do**: Sandbox tool execution and validate permissions

```python
import logging
import resource
from typing import Any, Callable, Dict, List, Optional

from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool, QueryEngineTool

logger = logging.getLogger(__name__)


class PermissionError(Exception):
    pass


class RateLimitError(Exception):
    pass


class ResourceError(Exception):
    pass


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
        rate_limit: int = 10,
    ) -> QueryEngineTool:
        secure_engine = self._wrap_query_engine(
            query_engine, name, required_permissions, rate_limit
        )
        tool = QueryEngineTool.from_defaults(
            query_engine=secure_engine,
            name=name,
            description=description,
        )
        self.tools[name] = {
            "tool": tool,
            "permissions": required_permissions,
            "rate_limit": rate_limit,
        }
        return tool

    def register_function_tool(
        self,
        name: str,
        fn: Callable,
        description: str,
        required_permissions: List[str],
        sandboxed: bool = True,
    ) -> FunctionTool:
        secure_fn = (
            self._sandbox_function(fn, name, required_permissions)
            if sandboxed
            else self._wrap_function(fn, name, required_permissions)
        )
        tool = FunctionTool.from_defaults(fn=secure_fn, name=name, description=description)
        self.tools[name] = {
            "tool": tool,
            "permissions": required_permissions,
            "sandboxed": sandboxed,
        }
        return tool

    def _wrap_query_engine(self, engine, tool_name, permissions, rate_limit):
        registry = self

        class _SecureEngine:
            def __init__(self):
                self._engine = engine
                self._call_count = 0

            def query(self, query_str: str, user_id: str = None):
                if user_id:
                    for perm in permissions:
                        if not registry.permission_checker(user_id, perm):
                            raise PermissionError(f"Missing permission: {perm}")
                self._call_count += 1
                if self._call_count > rate_limit:
                    raise RateLimitError(f"Tool rate limit exceeded: {tool_name}")
                return self._engine.query(query_str)

        return _SecureEngine()

    def _sandbox_function(self, fn, tool_name, permissions):
        registry = self

        def sandboxed_fn(*args, user_id: str = None, **kwargs):
            if user_id:
                for perm in permissions:
                    if not registry.permission_checker(user_id, perm):
                        raise PermissionError(f"Missing permission: {perm}")
            registry._validate_arguments(args, kwargs)
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
            try:
                result = fn(*args, **kwargs)
                registry._validate_output(result)
                return result
            except resource.error:
                raise ResourceError(f"Tool exceeded resource limits: {tool_name}")

        return sandboxed_fn

    def _wrap_function(self, fn, tool_name, permissions):
        registry = self

        def wrapped_fn(*args, user_id: str = None, **kwargs):
            if user_id:
                for perm in permissions:
                    if not registry.permission_checker(user_id, perm):
                        raise PermissionError(f"Missing permission: {perm}")
            return fn(*args, **kwargs)

        return wrapped_fn

    def _validate_arguments(self, args, kwargs) -> None:
        for arg in args:
            if isinstance(arg, str) and any(c in arg for c in [";", "|", "`", "$("]):
                raise ValueError("Invalid characters in argument")
        for key, value in kwargs.items():
            if isinstance(value, str) and any(c in value for c in [";", "|", "`", "$("]):
                raise ValueError(f"Invalid characters in {key}")

    def _validate_output(self, result) -> None:
        if isinstance(result, str) and len(result) > 100_000:
            raise ValueError("Output exceeds size limit")

    def get_tools_for_user(self, user_id: str) -> List:
        return [
            info["tool"]
            for info in self.tools.values()
            if all(self.permission_checker(user_id, p) for p in info["permissions"])
        ]


# Usage
def check_permission(user_id: str, permission: str) -> bool:
    user_permissions = get_user_permissions(user_id)
    return permission in user_permissions


registry = SecureToolRegistry(permission_checker=check_permission)

registry.register_query_tool(
    name="search_docs",
    query_engine=doc_query_engine,
    description="Search internal documents",
    required_permissions=["docs:read"],
    rate_limit=20,
)

user_tools = registry.get_tools_for_user("user_123")
agent = ReActAgent.from_tools(user_tools)
```

**Don't**: Give agents unrestricted tool access

```python
# VULNERABLE: No permission checks, shell access via FunctionTool
tools = [
    QueryEngineTool.from_defaults(query_engine=admin_query_engine, name="admin_search"),
    FunctionTool.from_defaults(fn=execute_shell_command, name="run_command"),
]
agent = ReActAgent.from_tools(tools)

# VULNERABLE: No sandboxing
def dangerous_tool(code: str):
    return eval(code)

tool = FunctionTool.from_defaults(fn=dangerous_tool)
```

**Why**: Agents with unrestricted tools can be manipulated through prompt injection to execute malicious actions, access unauthorized data, or cause resource exhaustion. Tool sandboxing limits blast radius.

**Refs**:
- OWASP LLM Top 10:2025 LLM06 (Excessive Agency)
- CWE-78 (OS Command Injection)
- CWE-94 (Code Injection)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: Multi-Index Query Security

**Level**: `warning`

**When**: Querying across multiple indexes

**Do**: Use `SubQuestionQueryEngine` or `RouterQueryEngine` (current API) with per-index access control. `ComposableGraph` was removed in 0.10+ and raises `ImportError`.

```python
import logging
from typing import Dict, List, Optional, Set

from llama_index.core import VectorStoreIndex
from llama_index.core.query_engine import SubQuestionQueryEngine
from llama_index.core.tools import QueryEngineTool

logger = logging.getLogger(__name__)


class PermissionError(Exception):
    pass


class SecureMultiIndexManager:
    """Secure manager for multi-index queries.

    ComposableGraph is removed in 0.10+. Use SubQuestionQueryEngine or
    RouterQueryEngine, both of which operate on per-index QueryEngineTool
    instances that can carry their own access-control wrappers.
    """

    def __init__(self):
        self.indexes: Dict[str, Dict] = {}

    def register_index(
        self,
        index_name: str,
        index: VectorStoreIndex,
        required_permissions: Set[str],
        tenant_id: Optional[str] = None,
    ) -> None:
        self.indexes[index_name] = {
            "index": index,
            "permissions": required_permissions,
            "tenant_id": tenant_id,
        }

    def get_authorized_indexes(
        self,
        user_permissions: Set[str],
        user_tenant: Optional[str] = None,
    ) -> List[str]:
        return [
            name
            for name, info in self.indexes.items()
            if info["permissions"].issubset(user_permissions)
            and (not info["tenant_id"] or info["tenant_id"] == user_tenant)
        ]

    def create_secure_query_engine(
        self,
        user_id: str,
        user_permissions: Set[str],
        user_tenant: Optional[str] = None,
    ) -> SubQuestionQueryEngine:
        """Build a SubQuestionQueryEngine scoped to authorized indexes only."""
        authorized = self.get_authorized_indexes(user_permissions, user_tenant)
        if not authorized:
            raise PermissionError("No authorized indexes available")

        tools = [
            QueryEngineTool.from_defaults(
                query_engine=self.indexes[name]["index"].as_query_engine(),
                name=f"query_{name}",
                description=f"Query the {name} index",
            )
            for name in authorized
        ]

        return SubQuestionQueryEngine.from_defaults(
            query_engine_tools=tools,
            use_async=True,
        )


# Usage
manager = SecureMultiIndexManager()

manager.register_index(
    "public_docs",
    public_index,
    required_permissions={"docs:read"},
)

manager.register_index(
    "internal_docs",
    internal_index,
    required_permissions={"docs:read", "internal:access"},
)

manager.register_index(
    "tenant_docs",
    tenant_index,
    required_permissions={"docs:read"},
    tenant_id="tenant_123",
)

user_permissions = {"docs:read"}
query_engine = manager.create_secure_query_engine(
    user_id="user_456",
    user_permissions=user_permissions,
    user_tenant="tenant_123",
)
# User can only query public_docs and their tenant_docs

response = query_engine.query("Find relevant information")
```

**Don't**: Use `ComposableGraph` (removed) or query all indexes without access control

```python
# BROKEN: ComposableGraph removed in 0.10+
from llama_index.core.composability import ComposableGraph  # ImportError

# VULNERABLE: No index-level access control
query_engine = SubQuestionQueryEngine.from_defaults(
    query_engine_tools=[tool_public, tool_internal, tool_admin]
)
response = query_engine.query(user_query)  # Access to all indexes

# VULNERABLE: No tenant isolation
all_tenant_indexes = load_all_tenant_indexes()
# Queries can retrieve data from any tenant
```

**Why**: `ComposableGraph` raises `ImportError` in current releases. Multi-index queries without authorization can expose data from indexes the user should not access.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-284 (Improper Access Control)
- CWE-639 (Authorization Bypass Through User-Controlled Key)
- NIST AI RMF GOVERN 4.2 (Privacy)

---

## Rule: QueryFusionRetriever Injection Surface

**Level**: `strict`

**When**: Using `QueryFusionRetriever` (or any retriever that generates multiple sub-queries internally)

**Do**: Validate generated sub-queries before they reach the retrieval layer; treat them as untrusted output even though the LLM produced them

```python
import logging
import re
from typing import List, Optional

from llama_index.core.retrievers import QueryFusionRetriever
from llama_index.core.schema import NodeWithScore, QueryBundle

logger = logging.getLogger(__name__)


class SafeQueryFusionRetriever:
    """Wraps QueryFusionRetriever to validate LLM-generated sub-queries.

    The retriever generates N sub-queries via an LLM call. If the original
    query contains an injection payload, the LLM may propagate it into one or
    more sub-queries. Each generated sub-query must be screened before it
    reaches the underlying vector store.
    """

    MAX_SUBQUERY_LENGTH = 500
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|above|all)\s+instructions?",
        r"system\s*:\s*",
        r"\[INST\]|\[/INST\]",
        r"<<SYS>>|<</SYS>>",
        r"<\|im_start\|>",
    ]

    def __init__(self, retrievers: list, num_queries: int = 4, **kwargs):
        self._retriever = QueryFusionRetriever(
            retrievers=retrievers,
            num_queries=num_queries,
            **kwargs,
        )
        self._compiled = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]

    def _validate_subquery(self, query: str) -> Optional[str]:
        """Return sanitized query or None if it must be dropped."""
        if len(query) > self.MAX_SUBQUERY_LENGTH:
            logger.warning("Sub-query truncated: length %d", len(query))
            query = query[: self.MAX_SUBQUERY_LENGTH]
        for pattern in self._compiled:
            if pattern.search(query):
                logger.warning("Injection pattern in LLM-generated sub-query — dropped")
                return None
        return query

    def retrieve(self, query_str: str) -> List[NodeWithScore]:
        # Let the retriever generate and fuse sub-queries internally,
        # then validate nodes at the trust boundary.
        nodes = self._retriever.retrieve(query_str)
        return self._screen_nodes(nodes)

    def _screen_nodes(self, nodes: List[NodeWithScore]) -> List[NodeWithScore]:
        clean = []
        for node in nodes:
            content = node.node.get_content()
            if any(p.search(content) for p in self._compiled):
                logger.warning(
                    "Node %s dropped: injection pattern in content", node.node.node_id
                )
                continue
            clean.append(node)
        return clean


# Usage
safe_retriever = SafeQueryFusionRetriever(
    retrievers=[vector_retriever_1, vector_retriever_2],
    num_queries=4,
)

nodes = safe_retriever.retrieve("What are the Q3 revenue figures?")
```

**Don't**: Feed QueryFusionRetriever output into the response synthesizer without screening

```python
# VULNERABLE: LLM-generated sub-queries reach vector store unscreened
retriever = QueryFusionRetriever(retrievers=[r1, r2], num_queries=4)
nodes = retriever.retrieve(user_query)  # Injection in user_query → poisoned sub-queries
response = synthesizer.synthesize(query, nodes)
```

**Why**: `QueryFusionRetriever` uses the LLM to rewrite the original query into multiple sub-queries. A prompt injection payload in the user query can propagate into those sub-queries, causing the retriever to fetch attacker-controlled nodes that then appear in the synthesized response.

**Refs**:
- OWASP LLM Top 10:2025 LLM01 (Prompt Injection)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)
- CWE-20 (Improper Input Validation)

---

## Rule: PromptTemplate Variable Injection

**Level**: `strict`

**When**: Constructing `PromptTemplate` objects with user-supplied variables

**Do**: Validate template variables against an allowlist; never interpolate raw user input directly into the template string

```python
import logging
import re
from typing import Any, Dict, Set

from llama_index.core import PromptTemplate

logger = logging.getLogger(__name__)


ALLOWED_VARIABLE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")


def build_safe_prompt(
    template_str: str,
    variables: Dict[str, Any],
    allowed_variables: Set[str],
) -> str:
    """Render a PromptTemplate after validating every variable.

    Args:
        template_str: Template string with {variable} placeholders.
        variables: Caller-supplied key/value pairs.
        allowed_variables: The exact set of variable names the template accepts.

    Returns:
        Rendered prompt string.

    Raises:
        ValueError: If unknown or malformed variable names are supplied.
    """
    # Reject variable names not in the allowlist.
    for key in variables:
        if key not in allowed_variables:
            raise ValueError(f"Template variable not in allowlist: {key!r}")
        if not ALLOWED_VARIABLE_PATTERN.match(key):
            raise ValueError(f"Variable name fails format check: {key!r}")

    # Sanitize string values — strip control characters and limit length.
    sanitized: Dict[str, Any] = {}
    for key, value in variables.items():
        if isinstance(value, str):
            value = re.sub(r"[\x00-\x1f\x7f]", "", value)[:4096]
        sanitized[key] = value

    tmpl = PromptTemplate(template_str)
    return tmpl.format(**sanitized)


# Usage — template variables are declared explicitly; user input is one value,
# never the template itself.
QUERY_TEMPLATE = (
    "You are a helpful assistant. Answer the following question using only "
    "the provided context.\n\nContext: {context_str}\n\nQuestion: {query_str}"
)

rendered = build_safe_prompt(
    template_str=QUERY_TEMPLATE,
    variables={"context_str": retrieved_context, "query_str": user_question},
    allowed_variables={"context_str", "query_str"},
)
```

**Don't**: Let users supply the template string or inject arbitrary variable names

```python
# VULNERABLE: User controls the template — full prompt injection
user_template = request.json["template"]
tmpl = PromptTemplate(user_template)
rendered = tmpl.format(context_str=ctx, query_str=q)

# VULNERABLE: Variable names taken from user input without validation
user_vars = request.json["variables"]  # {"__class__": "...", ...}
rendered = PromptTemplate(TEMPLATE).format(**user_vars)
```

**Why**: Allowing user-controlled template strings or variable names gives attackers a direct prompt injection surface. Malicious variables can override system instructions, exfiltrate context, or manipulate the LLM's role.

**Refs**:
- OWASP LLM Top 10:2025 LLM01 (Prompt Injection)
- CWE-94 (Code Injection)
- CWE-20 (Improper Input Validation)
- MITRE ATLAS AML.T0051 (LLM Prompt Injection)

---

## Rule: HuggingFace Embedding trust_remote_code

**Level**: `strict`

**When**: Loading HuggingFace embedding models via `HuggingFaceEmbedding` or `langchain_huggingface`

**Do**: Block `trust_remote_code=True` on any model that is not reviewed and pinned by digest

```python
import logging
from typing import Optional

from llama_index.embeddings.huggingface import HuggingFaceEmbedding

logger = logging.getLogger(__name__)

# Models that have been security-reviewed and are allowed to use remote code.
# Each entry is "org/name@sha256:<digest>" to pin to an immutable revision.
REVIEWED_REMOTE_CODE_MODELS: set = set()  # empty by default — add after review


def load_embedding_model(
    model_name: str,
    trust_remote_code: bool = False,
    revision: Optional[str] = None,
) -> HuggingFaceEmbedding:
    """Load a HuggingFace embedding model with remote-code guard.

    trust_remote_code=True executes arbitrary Python shipped with the model.
    Only allow it for models explicitly reviewed and pinned by digest.
    """
    if trust_remote_code:
        pinned = f"{model_name}@{revision}" if revision else model_name
        if pinned not in REVIEWED_REMOTE_CODE_MODELS:
            raise ValueError(
                f"trust_remote_code=True denied for unreviewed model: {model_name!r}. "
                "Add the model + digest to REVIEWED_REMOTE_CODE_MODELS after security review."
            )
        logger.warning(
            "Loading model with trust_remote_code=True (reviewed): %s@%s",
            model_name,
            revision,
        )

    return HuggingFaceEmbedding(
        model_name=model_name,
        trust_remote_code=trust_remote_code,
    )


# Usage — standard open models do not need remote code.
embed_model = load_embedding_model(
    model_name="BAAI/bge-small-en-v1.5",
    trust_remote_code=False,
)
```

**Don't**: Set `trust_remote_code=True` without an explicit review and digest pin

```python
# VULNERABLE: Executes arbitrary Python from the model repository
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

embed_model = HuggingFaceEmbedding(
    model_name=user_provided_model,  # Attacker controls the model
    trust_remote_code=True,           # Executes attacker code
)
```

**Why**: `trust_remote_code=True` instructs the HuggingFace `transformers` library to download and execute Python files bundled with the model. A malicious or compromised model repository can use this to achieve arbitrary code execution on the inference host. This is a supply-chain attack vector, not just a model-quality concern.

**Refs**:
- OWASP LLM Top 10:2025 LLM03 (Supply Chain)
- CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- MITRE ATLAS AML.T0010 (ML Supply Chain Compromise)
- NIST SSDF PO.1.3 (Verify third-party software)

---

## Rule: Node Post-Processor Trust Boundary

**Level**: `warning`

**When**: Using node post-processors (rerankers, metadata replacers, key-word filters, etc.) in a multi-tenant or user-facing pipeline

**Do**: Validate post-processor inputs at the tenant boundary and cap the node list before it enters the post-processor

```python
import logging
from typing import Callable, List, Optional

from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import NodeWithScore, QueryBundle

logger = logging.getLogger(__name__)


class TenantBoundaryPostprocessor(BaseNodePostprocessor):
    """Wraps any post-processor to enforce tenant isolation and input limits.

    Post-processors receive a node list that may have been retrieved from
    multiple indexes. Without a trust boundary, a node from a different
    tenant's index can slip through and be re-ranked or returned.
    """

    MAX_INPUT_NODES = 200

    def __init__(
        self,
        inner: BaseNodePostprocessor,
        tenant_id: str,
        tenant_id_field: str = "_tenant_id",
    ):
        super().__init__()
        self.inner = inner
        self.tenant_id = tenant_id
        self.tenant_id_field = tenant_id_field

    def _postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        # Cap input size to prevent CPU/memory exhaustion in expensive rerankers.
        if len(nodes) > self.MAX_INPUT_NODES:
            logger.warning(
                "Node list capped from %d to %d before post-processing",
                len(nodes),
                self.MAX_INPUT_NODES,
            )
            nodes = nodes[: self.MAX_INPUT_NODES]

        # Drop nodes that belong to a different tenant.
        tenant_filtered = []
        for node in nodes:
            node_tenant = node.node.metadata.get(self.tenant_id_field)
            if node_tenant is not None and node_tenant != self.tenant_id:
                logger.warning(
                    "Dropping cross-tenant node %s (tenant=%s, expected=%s)",
                    node.node.node_id,
                    node_tenant,
                    self.tenant_id,
                )
                continue
            tenant_filtered.append(node)

        return self.inner._postprocess_nodes(tenant_filtered, query_bundle)


# Usage — wrap any existing reranker with the boundary guard.
from llama_index.core.postprocessor import SentenceTransformerRerank

reranker = SentenceTransformerRerank(model="cross-encoder/ms-marco-MiniLM-L-6-v2", top_n=5)

safe_reranker = TenantBoundaryPostprocessor(
    inner=reranker,
    tenant_id="tenant_123",
    tenant_id_field="_tenant_id",
)

query_engine = index.as_query_engine(node_postprocessors=[safe_reranker])
```

**Don't**: Pass raw retriever output directly into a post-processor without tenant validation

```python
# VULNERABLE: Cross-tenant nodes pass through the reranker
from llama_index.core.postprocessor import SentenceTransformerRerank

reranker = SentenceTransformerRerank(top_n=5)
query_engine = index.as_query_engine(node_postprocessors=[reranker])
# Nodes from any tenant can be re-ranked and returned to the caller

# VULNERABLE: No node count cap — expensive reranker called on 10 000 nodes
reranker = SentenceTransformerRerank(top_n=5)
nodes = retriever.retrieve(query)  # may return thousands of nodes
reranked = reranker.postprocess_nodes(nodes, query_bundle)
```

**Why**: Post-processors such as rerankers, metadata replacers, and keyword filters operate on the raw retriever output. Without a tenant filter, a node from another tenant's index that leaked through the retrieval stage can be re-ranked to the top and returned to the wrong user. Without a node-count cap, sending thousands of nodes to a cross-encoder reranker is a denial-of-service vector.

**Refs**:
- OWASP LLM Top 10:2025 LLM02 (Sensitive Information Disclosure)
- CWE-284 (Improper Access Control)
- CWE-400 (Uncontrolled Resource Consumption)
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
- [ ] `Settings` global used instead of removed `service_context` kwarg

### Query Processing
- [ ] Input validation and sanitization
- [ ] Prompt injection pattern detection
- [ ] Per-user rate limiting (keyed by user_id, not a shared list)
- [ ] Query length limits enforced

### Response Generation
- [ ] Output validation enabled
- [ ] Citation verification active
- [ ] XSS pattern filtering
- [ ] Response length limits

### Service Configuration
- [ ] Split-package imports used (`llama_index.llms.<provider>`, `llama_index.embeddings.<provider>`)
- [ ] `Settings` singleton used (not removed `ServiceContext`)
- [ ] API keys loaded from secure sources
- [ ] Request timeouts configured
- [ ] Model selection restricted to allowlist
- [ ] Rate limits applied

### Agent Security
- [ ] Tool permissions validated
- [ ] Function sandboxing enabled
- [ ] Resource limits configured
- [ ] Tool rate limiting active

### RAG Pipeline Hygiene
- [ ] `QueryFusionRetriever` sub-query output screened before retrieval
- [ ] `PromptTemplate` variables validated against allowlist
- [ ] `trust_remote_code=True` blocked except for digest-pinned reviewed models
- [ ] Node post-processors wrapped with tenant boundary guard
- [ ] Node count capped before expensive post-processors

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-05 | Rewrite for llama-index-core 0.10+: replace SimpleNodeParser→SentenceSplitter, remove ComposableGraph→SubQuestionQueryEngine, fix service_context kwarg, per-user rate limiting, OWASP 2025 refs, add 4 new rules |
| 1.0.0 | 2025-01 | Initial LlamaIndex security rules |

---

## References

### Standards
- OWASP LLM Top 10:2025
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
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
