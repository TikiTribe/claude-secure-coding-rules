# LangChain Document Loaders Security Rules

Security patterns for LangChain document loaders in RAG pipelines. These rules address SSRF, path traversal, injection, and resource exhaustion risks specific to LangChain's loader ecosystem.

---

## Quick Reference

| Rule | Level | Risk | Primary Defense |
|------|-------|------|-----------------|
| Web Loader Security | `strict` | SSRF, data exfiltration | URL allowlisting, timeout limits |
| File Loader Security | `strict` | Path traversal, arbitrary file read | Path validation, type checking |
| Database Loader Security | `strict` | SQL injection, credential exposure | Parameterized queries, least privilege |
| API Loader Security | `strict` | Auth bypass, rate limit abuse | Token management, response validation |
| Recursive Chunking Security | `warning` | Resource exhaustion, memory overflow | Size limits, overlap validation |
| Metadata Extraction Security | `warning` | PII leakage, injection | Field sanitization, PII filtering |
| Async Loader Security | `warning` | Resource exhaustion, timeout abuse | Concurrency limits, timeout handling |
| Custom Loader Security | `strict` | Input validation bypass, injection | Comprehensive validation, error handling |

---

## Rule: Web Loader Security

**Level**: `strict`

**When**: Using `WebBaseLoader`, `UnstructuredURLLoader`, or any loader that fetches content from URLs

**Do**:
```python
from langchain_community.document_loaders import WebBaseLoader
from urllib.parse import urlparse
import ipaddress
import socket
from typing import Optional
import httpx

class SecureWebLoader:
    """Secure wrapper for LangChain web loaders with SSRF protection."""

    ALLOWED_DOMAINS = {
        "docs.company.com",
        "wiki.internal.com",
        "confluence.company.com",
    }

    BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}

    def __init__(
        self,
        timeout: int = 30,
        max_content_size: int = 10 * 1024 * 1024,  # 10MB
        verify_ssl: bool = True,
    ):
        self.timeout = timeout
        self.max_content_size = max_content_size
        self.verify_ssl = verify_ssl

    def validate_url(self, url: str) -> bool:
        """Validate URL against security policy."""
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid scheme: {parsed.scheme}. Only HTTP/HTTPS allowed.")

        if parsed.scheme in self.BLOCKED_SCHEMES:
            raise ValueError(f"Blocked scheme: {parsed.scheme}")

        # Check domain allowlist
        if parsed.netloc not in self.ALLOWED_DOMAINS:
            raise ValueError(f"Domain not in allowlist: {parsed.netloc}")

        # Prevent SSRF to internal networks
        try:
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                raise ValueError(f"URL resolves to private/internal IP: {ip}")
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {parsed.hostname}")

        return True

    def load(self, urls: list[str]) -> list:
        """Load documents from validated URLs."""
        # Validate all URLs first
        for url in urls:
            self.validate_url(url)

        # Configure loader with security settings
        loader = WebBaseLoader(
            web_paths=urls,
            requests_kwargs={
                "timeout": self.timeout,
                "verify": self.verify_ssl,
                "headers": {
                    "User-Agent": "SecureRAGLoader/1.0",
                },
            },
        )

        # Load with size check
        documents = loader.load()

        for doc in documents:
            if len(doc.page_content) > self.max_content_size:
                raise ValueError(
                    f"Content from {doc.metadata.get('source')} "
                    f"exceeds size limit: {len(doc.page_content)} bytes"
                )

        return documents


# Usage
secure_loader = SecureWebLoader()
docs = secure_loader.load(["https://docs.company.com/api-guide"])
```

**Don't**:
```python
from langchain_community.document_loaders import WebBaseLoader

# VULNERABLE: No URL validation - SSRF possible
def load_web_content(url: str):
    # Attacker can pass:
    # - file:///etc/passwd
    # - http://169.254.169.254/latest/meta-data (AWS metadata)
    # - http://localhost:8080/admin

    loader = WebBaseLoader(url)  # No validation
    return loader.load()  # No timeout, no size limit
```

**Why**: WebBaseLoader without URL validation enables Server-Side Request Forgery (SSRF). Attackers can fetch internal resources, cloud metadata endpoints (AWS/GCP/Azure), or internal services. URL allowlisting and IP validation prevent these attacks.

**Refs**: CWE-918 (SSRF), OWASP A10:2021 (SSRF), CWE-441 (Unintended Proxy)

---

## Rule: File Loader Security

**Level**: `strict`

**When**: Using `DirectoryLoader`, `TextLoader`, `PyPDFLoader`, or any file-based loader

**Do**:
```python
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from pathlib import Path
import os
import magic
from typing import Optional

class SecureFileLoader:
    """Secure wrapper for LangChain file loaders with path traversal protection."""

    ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf", ".docx", ".csv", ".json"}

    ALLOWED_MIME_TYPES = {
        "text/plain",
        "text/markdown",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/csv",
        "application/json",
    }

    def __init__(
        self,
        base_directory: str,
        max_file_size: int = 50 * 1024 * 1024,  # 50MB
        max_files: int = 1000,
    ):
        # Resolve and validate base directory
        self.base_directory = Path(base_directory).resolve()
        if not self.base_directory.exists():
            raise ValueError(f"Base directory does not exist: {base_directory}")

        self.max_file_size = max_file_size
        self.max_files = max_files
        self._mime_detector = magic.Magic(mime=True)

    def validate_path(self, file_path: str) -> Path:
        """Validate file path against security policy."""
        # Resolve to absolute path
        resolved = Path(file_path).resolve()

        # Prevent path traversal
        try:
            resolved.relative_to(self.base_directory)
        except ValueError:
            raise ValueError(
                f"Path traversal attempt detected: {file_path} "
                f"is outside base directory {self.base_directory}"
            )

        # Check extension
        if resolved.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension not allowed: {resolved.suffix}")

        # Check file size
        if resolved.exists():
            size = resolved.stat().st_size
            if size > self.max_file_size:
                raise ValueError(f"File exceeds size limit: {size} bytes")

            # Validate MIME type from content
            with open(resolved, "rb") as f:
                mime_type = self._mime_detector.from_buffer(f.read(8192))

            if mime_type not in self.ALLOWED_MIME_TYPES:
                raise ValueError(f"Invalid MIME type: {mime_type}")

        return resolved

    def load_file(self, file_path: str) -> list:
        """Load single file with security validation."""
        validated_path = self.validate_path(file_path)

        loader = TextLoader(str(validated_path))
        return loader.load()

    def load_directory(
        self,
        glob_pattern: str = "**/*.txt",
        recursive: bool = True,
    ) -> list:
        """Load directory with security controls."""

        # Validate glob pattern doesn't escape base directory
        if ".." in glob_pattern:
            raise ValueError("Path traversal in glob pattern not allowed")

        # Count files first
        files = list(self.base_directory.glob(glob_pattern))
        if len(files) > self.max_files:
            raise ValueError(
                f"Too many files ({len(files)}), limit is {self.max_files}"
            )

        # Validate each file
        for file_path in files:
            self.validate_path(str(file_path))

        # Load with DirectoryLoader
        loader = DirectoryLoader(
            str(self.base_directory),
            glob=glob_pattern,
            recursive=recursive,
            loader_cls=TextLoader,
            show_progress=True,
        )

        return loader.load()


# Usage
secure_loader = SecureFileLoader("/var/data/documents")
docs = secure_loader.load_directory("**/*.md")
```

**Don't**:
```python
from langchain_community.document_loaders import DirectoryLoader

# VULNERABLE: No path validation
def load_documents(user_path: str):
    # Attacker can pass:
    # - "../../../etc/passwd"
    # - "/etc/shadow"
    # - "/var/log/application.log"

    loader = DirectoryLoader(
        user_path,  # User-controlled path - path traversal!
        glob="**/*",  # Loads everything
    )
    return loader.load()  # No size limits, no type validation
```

**Why**: File loaders without path validation allow path traversal attacks. Attackers can read sensitive system files, configuration files with credentials, or application logs. Base directory confinement and MIME validation prevent unauthorized file access.

**Refs**: CWE-22 (Path Traversal), CWE-434 (Unrestricted Upload), OWASP A03:2021 (Injection)

---

## Rule: Database Loader Security

**Level**: `strict`

**When**: Using `SQLDatabaseLoader`, `SQLLoader`, or any database-connected loader

**Do**:
```python
from langchain_community.document_loaders import SQLDatabaseLoader
from langchain_community.utilities import SQLDatabase
from sqlalchemy import create_engine, text
from typing import Optional
import os

class SecureDatabaseLoader:
    """Secure wrapper for LangChain SQL loaders with injection protection."""

    # Allowed tables (whitelist approach)
    ALLOWED_TABLES = {"documents", "articles", "knowledge_base"}

    # Columns that should never be loaded
    BLOCKED_COLUMNS = {"password", "api_key", "secret", "token", "ssn", "credit_card"}

    def __init__(
        self,
        connection_string: Optional[str] = None,
        max_rows: int = 10000,
        query_timeout: int = 30,
    ):
        # Load connection string from environment (never hardcode)
        self.connection_string = connection_string or os.environ.get("DATABASE_URL")
        if not self.connection_string:
            raise ValueError("Database connection string not configured")

        self.max_rows = max_rows
        self.query_timeout = query_timeout

        # Create engine with security settings
        self.engine = create_engine(
            self.connection_string,
            pool_pre_ping=True,
            pool_recycle=3600,
            connect_args={"connect_timeout": 10},
        )

        self.db = SQLDatabase(
            engine=self.engine,
            include_tables=list(self.ALLOWED_TABLES),  # Only expose allowed tables
        )

    def validate_query(self, table: str, columns: list[str]) -> None:
        """Validate query parameters against security policy."""
        # Check table allowlist
        if table not in self.ALLOWED_TABLES:
            raise ValueError(f"Table not in allowlist: {table}")

        # Check for blocked columns
        for col in columns:
            if col.lower() in self.BLOCKED_COLUMNS:
                raise ValueError(f"Blocked column: {col}")

    def load_table(
        self,
        table: str,
        columns: list[str],
        where_clause: Optional[dict] = None,
    ) -> list:
        """Load from database with parameterized queries."""

        # Validate inputs
        self.validate_query(table, columns)

        # Build parameterized query (NEVER string concatenation)
        safe_columns = ", ".join(
            f'"{col}"' for col in columns  # Quote column names
        )

        query = f'SELECT {safe_columns} FROM "{table}"'
        params = {}

        if where_clause:
            # Use parameterized WHERE clause
            conditions = []
            for i, (key, value) in enumerate(where_clause.items()):
                # Validate column name
                if key.lower() in self.BLOCKED_COLUMNS:
                    raise ValueError(f"Cannot filter on blocked column: {key}")

                param_name = f"param_{i}"
                conditions.append(f'"{key}" = :{param_name}')
                params[param_name] = value

            query += " WHERE " + " AND ".join(conditions)

        # Add row limit
        query += f" LIMIT {self.max_rows}"

        # Execute with timeout
        loader = SQLDatabaseLoader(
            query=query,
            db=self.db,
            parameters=params,
        )

        return loader.load()

    def load_with_custom_query(self, query: str, params: dict) -> list:
        """Load with user-provided parameterized query."""

        # Validate query doesn't contain dangerous operations
        query_upper = query.upper()
        dangerous_keywords = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "TRUNCATE"]

        for keyword in dangerous_keywords:
            if keyword in query_upper:
                raise ValueError(f"Query contains dangerous keyword: {keyword}")

        # Ensure query has LIMIT
        if "LIMIT" not in query_upper:
            query += f" LIMIT {self.max_rows}"

        loader = SQLDatabaseLoader(
            query=query,
            db=self.db,
            parameters=params,  # Always use parameters, never string interpolation
        )

        return loader.load()


# Usage
secure_loader = SecureDatabaseLoader()
docs = secure_loader.load_table(
    table="documents",
    columns=["title", "content", "author"],
    where_clause={"category": "technical"}
)
```

**Don't**:
```python
from langchain_community.document_loaders import SQLDatabaseLoader
from langchain_community.utilities import SQLDatabase

# VULNERABLE: SQL injection possible
def load_from_database(table: str, filter_value: str):
    db = SQLDatabase.from_uri(
        "postgresql://user:password@localhost/db"  # Hardcoded credentials!
    )

    # String concatenation = SQL injection
    query = f"SELECT * FROM {table} WHERE category = '{filter_value}'"

    loader = SQLDatabaseLoader(query=query, db=db)
    return loader.load()

# Attacker passes: filter_value = "'; DROP TABLE users; --"
```

**Why**: SQL loaders with string concatenation enable SQL injection. Attackers can extract sensitive data, modify records, or drop tables. Parameterized queries and table allowlisting prevent injection and limit data exposure.

**Refs**: CWE-89 (SQL Injection), OWASP A03:2021 (Injection), CWE-798 (Hardcoded Credentials)

---

## Rule: API Loader Security

**Level**: `strict`

**When**: Using `NotionDBLoader`, `GitHubLoader`, `SlackLoader`, or any API-based loader

**Do**:
```python
from langchain_community.document_loaders import NotionDBLoader
import os
import time
from typing import Optional
import httpx
from functools import wraps

class SecureAPILoader:
    """Secure wrapper for LangChain API loaders with auth and rate limiting."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        rate_limit: int = 60,  # requests per minute
        timeout: int = 30,
        max_retries: int = 3,
    ):
        # Load API key from secure source
        self.api_key = api_key or os.environ.get("NOTION_API_KEY")
        if not self.api_key:
            raise ValueError("API key not configured")

        # Validate API key format (basic check)
        if len(self.api_key) < 20:
            raise ValueError("Invalid API key format")

        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries

        # Rate limiting state
        self._request_times: list[float] = []

    def _check_rate_limit(self) -> None:
        """Enforce rate limiting."""
        now = time.time()
        minute_ago = now - 60

        # Remove old requests
        self._request_times = [t for t in self._request_times if t > minute_ago]

        if len(self._request_times) >= self.rate_limit:
            wait_time = self._request_times[0] - minute_ago
            raise RuntimeError(f"Rate limit exceeded. Wait {wait_time:.1f}s")

        self._request_times.append(now)

    def validate_response(self, documents: list) -> list:
        """Validate API response for security issues."""
        validated = []

        for doc in documents:
            content = doc.page_content

            # Check for excessive size
            if len(content) > 1_000_000:  # 1MB per document
                raise ValueError(f"Document exceeds size limit: {len(content)} bytes")

            # Check for potential injection patterns in API response
            suspicious_patterns = [
                "ignore previous instructions",
                "system:",
                "assistant:",
            ]

            content_lower = content.lower()
            for pattern in suspicious_patterns:
                if pattern in content_lower:
                    # Log but don't block - API data might legitimately contain these
                    import logging
                    logging.warning(f"Suspicious pattern in API response: {pattern}")

            validated.append(doc)

        return validated

    def load_notion_database(
        self,
        database_id: str,
        filter_params: Optional[dict] = None,
    ) -> list:
        """Load from Notion with security controls."""

        # Validate database ID format
        if not database_id or len(database_id) != 32:
            raise ValueError("Invalid Notion database ID format")

        # Rate limit check
        self._check_rate_limit()

        # Configure loader with security settings
        loader = NotionDBLoader(
            integration_token=self.api_key,
            database_id=database_id,
            request_timeout_sec=self.timeout,
        )

        # Load and validate
        documents = loader.load()
        return self.validate_response(documents)

    def load_with_retry(self, load_func, *args, **kwargs) -> list:
        """Load with retry logic for resilience."""
        last_error = None

        for attempt in range(self.max_retries):
            try:
                self._check_rate_limit()
                return load_func(*args, **kwargs)
            except httpx.TimeoutException as e:
                last_error = e
                time.sleep(2 ** attempt)  # Exponential backoff
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    time.sleep(60)  # Wait a minute
                    last_error = e
                elif e.response.status_code == 401:
                    raise ValueError("Invalid API credentials")
                else:
                    raise

        raise RuntimeError(f"Failed after {self.max_retries} retries: {last_error}")


# Usage
secure_loader = SecureAPILoader()
docs = secure_loader.load_notion_database(
    database_id="abcd1234abcd1234abcd1234abcd1234"
)
```

**Don't**:
```python
from langchain_community.document_loaders import NotionDBLoader

# VULNERABLE: Insecure API usage
def load_notion(database_id: str):
    loader = NotionDBLoader(
        integration_token="secret_abc123xyz",  # Hardcoded token!
        database_id=database_id,
        # No timeout - can hang forever
        # No rate limiting - can exhaust API quota
        # No response validation
    )
    return loader.load()
```

**Why**: API loaders without proper authentication management expose credentials. Missing rate limiting can exhaust quotas or trigger bans. Response validation catches malformed or malicious data from compromised APIs.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-400 (Resource Exhaustion), CWE-20 (Input Validation)

---

## Rule: Recursive Chunking Security

**Level**: `warning`

**When**: Using `RecursiveCharacterTextSplitter` or any text splitting with documents

**Do**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter
from typing import Optional

class SecureTextSplitter:
    """Secure wrapper for LangChain text splitters with resource limits."""

    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        max_chunks: int = 10000,
        max_input_size: int = 100 * 1024 * 1024,  # 100MB
    ):
        # Validate configuration
        if chunk_overlap >= chunk_size:
            raise ValueError(
                f"Overlap ({chunk_overlap}) must be less than chunk size ({chunk_size})"
            )

        if chunk_overlap < 0:
            raise ValueError("Overlap cannot be negative")

        # Prevent excessive overlap that could cause memory issues
        max_overlap_ratio = 0.5
        if chunk_overlap > chunk_size * max_overlap_ratio:
            raise ValueError(
                f"Overlap ratio ({chunk_overlap/chunk_size:.2f}) "
                f"exceeds maximum ({max_overlap_ratio})"
            )

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.max_chunks = max_chunks
        self.max_input_size = max_input_size

        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            length_function=len,
            is_separator_regex=False,
        )

    def split_text(self, text: str) -> list[str]:
        """Split text with security controls."""

        # Check input size
        if len(text) > self.max_input_size:
            raise ValueError(
                f"Input text ({len(text)} bytes) exceeds limit ({self.max_input_size})"
            )

        # Estimate chunk count to prevent memory exhaustion
        estimated_chunks = len(text) / (self.chunk_size - self.chunk_overlap)
        if estimated_chunks > self.max_chunks:
            raise ValueError(
                f"Estimated chunks ({estimated_chunks:.0f}) exceeds limit ({self.max_chunks})"
            )

        # Perform splitting
        chunks = self.splitter.split_text(text)

        # Verify actual chunk count
        if len(chunks) > self.max_chunks:
            raise ValueError(
                f"Actual chunks ({len(chunks)}) exceeds limit ({self.max_chunks})"
            )

        return chunks

    def split_documents(self, documents: list) -> list:
        """Split documents with security controls."""

        total_size = sum(len(doc.page_content) for doc in documents)
        if total_size > self.max_input_size:
            raise ValueError(
                f"Total document size ({total_size} bytes) exceeds limit"
            )

        # Split with chunk limit enforcement
        all_chunks = self.splitter.split_documents(documents)

        if len(all_chunks) > self.max_chunks:
            raise ValueError(
                f"Total chunks ({len(all_chunks)}) exceeds limit ({self.max_chunks})"
            )

        return all_chunks


# Usage
secure_splitter = SecureTextSplitter(
    chunk_size=1000,
    chunk_overlap=200,
    max_chunks=5000,
)
chunks = secure_splitter.split_text(document_text)
```

**Don't**:
```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

# VULNERABLE: No resource limits
def split_document(text: str, user_chunk_size: int, user_overlap: int):
    # User-controlled parameters - resource exhaustion possible
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=user_chunk_size,  # Could be 1
        chunk_overlap=user_overlap,   # Could be larger than chunk_size!
    )

    # No size limits - memory exhaustion possible
    return splitter.split_text(text)

# Attacker passes: chunk_size=1, overlap=0 -> millions of chunks
```

**Why**: Text splitters with user-controlled parameters can cause resource exhaustion. Small chunk sizes create excessive chunks consuming memory. Invalid overlap configurations can cause infinite loops or memory issues.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits)

---

## Rule: Metadata Extraction Security

**Level**: `warning`

**When**: Processing document metadata from loaders before storage

**Do**:
```python
from typing import Any, Optional
import re
import html
from dataclasses import dataclass

@dataclass
class MetadataConfig:
    """Configuration for metadata security."""
    allowed_fields: tuple = (
        "source", "title", "author", "page", "chunk_index",
        "file_type", "creation_date", "modification_date",
    )
    max_field_length: int = 1000
    pii_patterns: tuple = (
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',  # SSN
    )

class SecureMetadataProcessor:
    """Secure metadata processing for LangChain documents."""

    def __init__(self, config: Optional[MetadataConfig] = None):
        self.config = config or MetadataConfig()

    def sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Sanitize metadata from LangChain documents."""
        sanitized = {}

        for key, value in metadata.items():
            # Normalize key
            normalized_key = key.lower().replace(" ", "_").replace("-", "_")

            # Filter to allowed fields only
            if normalized_key not in self.config.allowed_fields:
                continue

            # Sanitize value
            sanitized_value = self._sanitize_value(value)
            sanitized[normalized_key] = sanitized_value

        return sanitized

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize individual metadata value."""
        if value is None:
            return None

        if isinstance(value, (int, float, bool)):
            return value

        # Convert to string for text processing
        str_value = str(value)

        # Truncate long values
        if len(str_value) > self.config.max_field_length:
            str_value = str_value[:self.config.max_field_length] + "..."

        # Remove control characters
        str_value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str_value)

        # HTML encode to prevent XSS
        str_value = html.escape(str_value)

        # Redact PII
        for pattern in self.config.pii_patterns:
            str_value = re.sub(pattern, '[REDACTED]', str_value)

        return str_value.strip()

    def process_documents(self, documents: list) -> list:
        """Process list of LangChain documents with metadata sanitization."""
        processed = []

        for doc in documents:
            # Create copy with sanitized metadata
            sanitized_metadata = self.sanitize_metadata(doc.metadata)

            # Update document metadata
            doc.metadata = sanitized_metadata
            processed.append(doc)

        return processed


# Usage
processor = SecureMetadataProcessor()
docs = loader.load()
secure_docs = processor.process_documents(docs)
```

**Don't**:
```python
# VULNERABLE: No metadata sanitization
def load_and_store(file_path: str):
    loader = TextLoader(file_path)
    docs = loader.load()

    # Metadata may contain:
    # - Full file paths with usernames
    # - Author email addresses
    # - System information

    for doc in docs:
        vector_store.add_documents([doc])  # Unsanitized metadata stored
```

**Why**: Document metadata often contains sensitive information like email addresses, file paths revealing usernames, or system details. Metadata is often exposed in search results and UIs. Field allowlisting and PII redaction prevent data leakage.

**Refs**: CWE-200 (Information Exposure), CWE-359 (Privacy Violation), GDPR Article 5

---

## Rule: Async Loader Security

**Level**: `warning`

**When**: Using `AsyncChromiumLoader`, `AsyncHtmlLoader`, or any async loader

**Do**:
```python
from langchain_community.document_loaders import AsyncHtmlLoader
import asyncio
from typing import Optional
import time

class SecureAsyncLoader:
    """Secure wrapper for LangChain async loaders with concurrency control."""

    def __init__(
        self,
        max_concurrency: int = 5,
        timeout: int = 30,
        max_urls: int = 100,
        rate_limit: float = 1.0,  # seconds between requests
    ):
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.max_urls = max_urls
        self.rate_limit = rate_limit

        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def load_urls(self, urls: list[str]) -> list:
        """Load URLs with concurrency and timeout controls."""

        # Validate URL count
        if len(urls) > self.max_urls:
            raise ValueError(f"Too many URLs ({len(urls)}), limit is {self.max_urls}")

        # Validate each URL (using SecureWebLoader validation)
        from secure_web_loader import SecureWebLoader
        validator = SecureWebLoader()
        for url in urls:
            validator.validate_url(url)

        # Load with concurrency control
        loader = AsyncHtmlLoader(
            urls,
            timeout=self.timeout,
            requests_per_second=1 / self.rate_limit,
        )

        # Apply timeout to entire operation
        try:
            documents = await asyncio.wait_for(
                loader.aload(),
                timeout=self.timeout * len(urls) / self.max_concurrency + 60
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Async loading timed out after {self.timeout}s per URL"
            )

        return documents

    async def load_with_semaphore(self, url: str) -> Optional[str]:
        """Load single URL with semaphore control."""
        async with self._semaphore:
            loader = AsyncHtmlLoader([url], timeout=self.timeout)
            try:
                docs = await asyncio.wait_for(
                    loader.aload(),
                    timeout=self.timeout
                )
                await asyncio.sleep(self.rate_limit)  # Rate limiting
                return docs[0] if docs else None
            except asyncio.TimeoutError:
                return None

    def load_sync(self, urls: list[str]) -> list:
        """Synchronous wrapper for async loading."""
        return asyncio.run(self.load_urls(urls))


# Usage
async def main():
    loader = SecureAsyncLoader(
        max_concurrency=5,
        timeout=30,
        max_urls=50,
    )
    docs = await loader.load_urls(validated_urls)
    return docs

docs = asyncio.run(main())
```

**Don't**:
```python
from langchain_community.document_loaders import AsyncHtmlLoader

# VULNERABLE: No concurrency limits
async def load_urls_unsafe(urls: list[str]):
    # No limit on concurrent requests - can overwhelm target or system
    # No timeout - can hang forever
    # No URL validation

    loader = AsyncHtmlLoader(urls)  # All URLs fetched concurrently
    return await loader.aload()

# Attacker passes 1000 URLs -> system resource exhaustion
```

**Why**: Async loaders without concurrency limits can exhaust system resources (file descriptors, memory) or overwhelm target servers. Missing timeouts can cause operations to hang indefinitely. Semaphores and rate limiting ensure controlled resource usage.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), CWE-834 (Excessive Iteration)

---

## Rule: Custom Loader Security

**Level**: `strict`

**When**: Creating custom LangChain document loaders by extending `BaseLoader`

**Do**:
```python
from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document
from typing import Iterator, Optional, Any
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CustomLoaderConfig:
    """Configuration for custom loader security."""
    max_documents: int = 1000
    max_content_size: int = 10 * 1024 * 1024  # 10MB per document
    timeout: int = 60
    allowed_sources: tuple = ()

class SecureCustomLoader(BaseLoader):
    """Template for secure custom LangChain loader implementation."""

    def __init__(
        self,
        source: str,
        config: Optional[CustomLoaderConfig] = None,
        **kwargs: Any,
    ):
        self.config = config or CustomLoaderConfig()

        # Validate source
        self.source = self._validate_source(source)

        # Store validated kwargs only
        self.kwargs = self._validate_kwargs(kwargs)

    def _validate_source(self, source: str) -> str:
        """Validate data source."""
        if not source:
            raise ValueError("Source cannot be empty")

        # Check against allowlist if configured
        if self.config.allowed_sources:
            if source not in self.config.allowed_sources:
                raise ValueError(f"Source not in allowlist: {source}")

        return source

    def _validate_kwargs(self, kwargs: dict) -> dict:
        """Validate and sanitize additional arguments."""
        validated = {}

        for key, value in kwargs.items():
            # Type validation
            if not isinstance(key, str):
                raise ValueError(f"Invalid kwarg key type: {type(key)}")

            # Sanitize key
            if not key.isalnum() and "_" not in key:
                raise ValueError(f"Invalid kwarg key: {key}")

            validated[key] = value

        return validated

    def lazy_load(self) -> Iterator[Document]:
        """Lazily load documents with security controls."""
        document_count = 0

        try:
            for item in self._fetch_items():
                # Enforce document limit
                if document_count >= self.config.max_documents:
                    logger.warning(
                        f"Document limit reached ({self.config.max_documents})"
                    )
                    break

                # Process item into document
                doc = self._process_item(item)

                if doc:
                    document_count += 1
                    yield doc

        except Exception as e:
            # Log error without exposing sensitive details
            logger.error(f"Error in custom loader: {type(e).__name__}")
            raise RuntimeError("Document loading failed") from e

    def _fetch_items(self) -> Iterator[Any]:
        """Fetch raw items from source. Override in subclass."""
        raise NotImplementedError("Subclass must implement _fetch_items")

    def _process_item(self, item: Any) -> Optional[Document]:
        """Process raw item into Document with validation."""
        try:
            # Extract content (implement in subclass)
            content = self._extract_content(item)

            # Validate content size
            if len(content) > self.config.max_content_size:
                logger.warning(f"Content exceeds size limit, truncating")
                content = content[:self.config.max_content_size]

            # Extract and sanitize metadata
            metadata = self._extract_metadata(item)
            sanitized_metadata = self._sanitize_metadata(metadata)

            return Document(
                page_content=content,
                metadata=sanitized_metadata,
            )

        except Exception as e:
            logger.warning(f"Failed to process item: {type(e).__name__}")
            return None

    def _extract_content(self, item: Any) -> str:
        """Extract text content from item. Override in subclass."""
        raise NotImplementedError("Subclass must implement _extract_content")

    def _extract_metadata(self, item: Any) -> dict:
        """Extract metadata from item. Override in subclass."""
        return {"source": self.source}

    def _sanitize_metadata(self, metadata: dict) -> dict:
        """Sanitize metadata for security."""
        sanitized = {}

        for key, value in metadata.items():
            # Skip None values
            if value is None:
                continue

            # Sanitize key
            safe_key = str(key).lower().replace(" ", "_")[:50]

            # Sanitize value
            if isinstance(value, str):
                safe_value = value[:1000]  # Truncate
            else:
                safe_value = value

            sanitized[safe_key] = safe_value

        return sanitized


# Example implementation
class SecureAPILoader(SecureCustomLoader):
    """Example secure API loader implementation."""

    def __init__(self, api_url: str, api_key: str, **kwargs):
        # Validate API key is from environment
        import os
        if api_key and not api_key.startswith("env:"):
            # Check if it looks like it's from environment
            if api_key == os.environ.get("API_KEY"):
                pass  # OK, came from environment
            else:
                raise ValueError("API key should come from environment variable")

        super().__init__(source=api_url, **kwargs)
        self.api_key = os.environ.get("API_KEY") or api_key.replace("env:", "")

    def _fetch_items(self) -> Iterator[dict]:
        """Fetch items from API."""
        import httpx

        with httpx.Client(timeout=self.config.timeout) as client:
            response = client.get(
                self.source,
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()

            for item in response.json().get("items", []):
                yield item

    def _extract_content(self, item: dict) -> str:
        """Extract content from API response item."""
        return str(item.get("content", ""))
```

**Don't**:
```python
from langchain_core.document_loaders import BaseLoader

# VULNERABLE: Insecure custom loader
class UnsafeLoader(BaseLoader):
    def __init__(self, source, **kwargs):
        self.source = source  # No validation
        self.kwargs = kwargs  # Unvalidated kwargs

    def lazy_load(self):
        import subprocess

        # Command injection vulnerability!
        result = subprocess.run(
            f"cat {self.source}",  # User input in shell command
            shell=True,
            capture_output=True
        )

        yield Document(
            page_content=result.stdout.decode(),
            metadata=self.kwargs  # Unsanitized metadata
        )

# Attacker passes: source = "; rm -rf /"
```

**Why**: Custom loaders without input validation enable injection attacks. Missing error handling exposes sensitive information. Unsanitized metadata propagates through the entire RAG pipeline. Proper validation at the loader level prevents vulnerabilities from entering the system.

**Refs**: CWE-78 (OS Command Injection), CWE-20 (Input Validation), CWE-209 (Error Information Exposure)

---

## Implementation Checklist

### Web Loaders
- [ ] URL allowlist configured
- [ ] SSRF protection (private IP blocking)
- [ ] Timeout limits set
- [ ] Content size limits enforced
- [ ] SSL verification enabled

### File Loaders
- [ ] Base directory confinement
- [ ] Path traversal prevention
- [ ] MIME type validation
- [ ] File size limits
- [ ] Extension allowlisting

### Database Loaders
- [ ] Parameterized queries only
- [ ] Table/column allowlisting
- [ ] Credentials from environment
- [ ] Row limits enforced
- [ ] Query timeout configured

### API Loaders
- [ ] API keys from secure storage
- [ ] Rate limiting implemented
- [ ] Response validation
- [ ] Retry logic with backoff
- [ ] Timeout handling

### Text Splitters
- [ ] Chunk size limits
- [ ] Overlap validation
- [ ] Maximum chunks enforced
- [ ] Input size limits
- [ ] Memory monitoring

### Metadata Processing
- [ ] Field allowlisting
- [ ] PII detection/redaction
- [ ] Value sanitization
- [ ] Length limits
- [ ] XSS prevention

---

## References

### CWE References
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-400: Uncontrolled Resource Consumption
- CWE-798: Use of Hard-coded Credentials
- CWE-20: Improper Input Validation
- CWE-200: Exposure of Sensitive Information

### OWASP References
- OWASP A03:2021 - Injection
- OWASP A10:2021 - Server-Side Request Forgery
- OWASP A05:2021 - Security Misconfiguration
- OWASP A01:2021 - Broken Access Control

### Additional Resources
- LangChain Security Best Practices
- NIST AI RMF - Data Governance
- GDPR Article 5 - Data Minimization

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01 | Initial release with 8 core loader security rules |
