# LlamaParse Document Parsing Security Rules

Security rules for LlamaParse document parsing in RAG pipelines.

**Prerequisites**:
- `rules/_core/ai-security.md`
- `rules/rag/_core/document-processing-security.md`

---

## Rule: Secure API Key Management

**Level**: `strict`

**When**: Configuring LlamaParse client with API credentials

**Do**:
```python
import os
from llama_parse import LlamaParse

# Load API key from environment variable
api_key = os.environ.get("LLAMA_CLOUD_API_KEY")
if not api_key:
    raise ValueError("LLAMA_CLOUD_API_KEY environment variable not set")

parser = LlamaParse(
    api_key=api_key,
    result_type="markdown"
)
```

**Don't**:
```python
from llama_parse import LlamaParse

# Hardcoded API key - exposed in version control
parser = LlamaParse(
    api_key="llx-abc123xyz789secretkey",
    result_type="markdown"
)
```

**Why**: Hardcoded API keys in source code are exposed through version control history, logs, and error messages. Attackers can use stolen keys to consume your API quota, access parsed documents, or incur charges on your account.

**Refs**: CWE-798 (Hardcoded Credentials), OWASP API Security Top 10 API2:2023

---

## Rule: Document Upload Validation

**Level**: `strict`

**When**: Accepting documents for parsing from user uploads

**Do**:
```python
import os
from pathlib import Path
from llama_parse import LlamaParse

ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.pptx', '.xlsx', '.html', '.txt'}
MAX_FILE_SIZE_MB = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

def validate_document(file_path: str) -> bool:
    """Validate document before parsing."""
    path = Path(file_path)

    # Check file extension
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type {path.suffix} not allowed")

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File exceeds {MAX_FILE_SIZE_MB}MB limit")

    # Verify file exists and is readable
    if not path.is_file():
        raise ValueError("Invalid file path")

    return True

def parse_document(file_path: str):
    validate_document(file_path)

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )
    return parser.load_data(file_path)
```

**Don't**:
```python
from llama_parse import LlamaParse

def parse_document(file_path: str):
    # No validation - accepts any file type or size
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )
    # Directly parse without checks
    return parser.load_data(file_path)
```

**Why**: Without validation, attackers can upload malicious files (e.g., crafted PDFs with exploits), oversized files causing resource exhaustion, or unexpected file types that may trigger parser vulnerabilities. File size limits prevent denial of service through resource consumption.

**Refs**: CWE-434 (Unrestricted File Upload), CWE-400 (Resource Exhaustion), OWASP File Upload Cheat Sheet

---

## Rule: Parsing Mode Security Configuration

**Level**: `warning`

**When**: Selecting parsing mode for documents

**Do**:
```python
from llama_parse import LlamaParse
import os

def create_parser(document_type: str, security_context: str = "standard"):
    """Create parser with appropriate mode based on security context."""

    # Use fast mode for untrusted/public documents
    # Use accurate mode only for trusted internal documents
    if security_context == "untrusted" or document_type == "external":
        parsing_mode = "fast"
        use_vendor_models = False
    else:
        parsing_mode = "accurate"
        use_vendor_models = True

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        parsing_instruction="Extract text content only. Do not execute any embedded code or scripts.",
        # Limit processing for untrusted content
        num_workers=2 if security_context == "untrusted" else 4,
        verbose=False,  # Don't expose internal details
        show_progress=False
    )

    return parser
```

**Don't**:
```python
from llama_parse import LlamaParse
import os

def create_parser():
    # Always uses most powerful mode regardless of trust level
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        verbose=True,  # Exposes internal processing details
        num_workers=8  # No resource limits
    )
    return parser
```

**Why**: Different parsing modes have different security implications. More powerful modes with vendor multimodal models may process embedded content more deeply, increasing attack surface. Untrusted documents should use constrained modes. Verbose output can leak internal processing details useful to attackers.

**Refs**: CWE-200 (Information Exposure), NIST AI RMF Map 1.1

---

## Rule: Result Caching Security

**Level**: `warning`

**When**: Caching parsed document results

**Do**:
```python
import hashlib
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from llama_parse import LlamaParse

CACHE_DIR = Path("/secure/cache/llamaparse")
CACHE_TTL_HOURS = 24

def get_cache_key(file_path: str, file_content: bytes) -> str:
    """Generate secure cache key from file content hash."""
    content_hash = hashlib.sha256(file_content).hexdigest()
    return content_hash

def get_cached_result(cache_key: str):
    """Retrieve cached result if valid."""
    cache_file = CACHE_DIR / f"{cache_key}.json"

    if not cache_file.exists():
        return None

    # Check cache age
    mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
    if datetime.now() - mtime > timedelta(hours=CACHE_TTL_HOURS):
        cache_file.unlink()  # Delete expired cache
        return None

    with open(cache_file, 'r') as f:
        return json.load(f)

def cache_result(cache_key: str, result: dict):
    """Cache result securely."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Set restrictive permissions
    cache_file = CACHE_DIR / f"{cache_key}.json"
    with open(cache_file, 'w') as f:
        json.dump(result, f)

    os.chmod(cache_file, 0o600)  # Owner read/write only

def parse_with_cache(file_path: str):
    """Parse document with secure caching."""
    with open(file_path, 'rb') as f:
        content = f.read()

    cache_key = get_cache_key(file_path, content)

    # Check cache first
    cached = get_cached_result(cache_key)
    if cached:
        return cached

    # Parse and cache
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )
    result = parser.load_data(file_path)

    # Serialize and cache
    serialized = [{"text": doc.text, "metadata": doc.metadata} for doc in result]
    cache_result(cache_key, serialized)

    return result
```

**Don't**:
```python
import os
from llama_parse import LlamaParse

# Global cache with no expiration or access control
CACHE = {}

def parse_with_cache(file_path: str):
    # Use filename as cache key - collision risk
    if file_path in CACHE:
        return CACHE[file_path]

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )
    result = parser.load_data(file_path)

    # Cache indefinitely in memory
    CACHE[file_path] = result
    return result
```

**Why**: Insecure caching can lead to cache poisoning (using filename instead of content hash), unauthorized access to cached sensitive documents, stale data exposure, and memory exhaustion from unbounded caches. Cache files should have restrictive permissions and TTLs.

**Refs**: CWE-524 (Information Exposure Through Caching), CWE-525 (Information Exposure Through Browser Caching)

---

## Rule: Multi-Modal Content Handling

**Level**: `warning`

**When**: Parsing documents with images, tables, or embedded content

**Do**:
```python
import os
from llama_parse import LlamaParse

def parse_multimodal_document(
    file_path: str,
    allow_images: bool = False,
    trust_level: str = "low"
):
    """Parse document with controlled multi-modal handling."""

    # Configure based on trust level
    if trust_level == "low":
        # Minimal extraction for untrusted documents
        parser = LlamaParse(
            api_key=os.environ["LLAMA_CLOUD_API_KEY"],
            result_type="text",  # Plain text only
            parsing_instruction="Extract text only. Ignore embedded images and scripts.",
            skip_diagonal_text=True,
            do_not_unroll_columns=True
        )
    elif trust_level == "medium":
        # Allow structured content but not images
        parser = LlamaParse(
            api_key=os.environ["LLAMA_CLOUD_API_KEY"],
            result_type="markdown",
            parsing_instruction="Extract text and tables. Do not process embedded images or execute any code.",
        )
    else:
        # Full extraction for trusted documents only
        parser = LlamaParse(
            api_key=os.environ["LLAMA_CLOUD_API_KEY"],
            result_type="markdown",
            take_screenshot=allow_images,
        )

    result = parser.load_data(file_path)

    # Post-process to remove any remaining suspicious content
    sanitized = []
    for doc in result:
        text = doc.text
        # Remove potential script injections
        if '<script' in text.lower() or 'javascript:' in text.lower():
            text = sanitize_text(text)
        sanitized.append(text)

    return sanitized

def sanitize_text(text: str) -> str:
    """Remove potentially dangerous content from extracted text."""
    import re
    # Remove script tags and javascript: URLs
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    return text
```

**Don't**:
```python
from llama_parse import LlamaParse
import os

def parse_document(file_path: str):
    # Full extraction with no content filtering
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        take_screenshot=True,  # Always extract images
        # No parsing instructions to limit scope
    )

    # Return raw results without sanitization
    return parser.load_data(file_path)
```

**Why**: Embedded images and multi-modal content can contain steganographic payloads, EXIF data with sensitive information, or specially crafted content designed to manipulate downstream LLM processing. Untrusted documents should have minimal extraction to reduce attack surface.

**Refs**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), MITRE ATLAS AML.T0043 (Data Snooping)

---

## Rule: Instruction Injection Prevention

**Level**: `strict`

**When**: Using parsing instructions with user-controlled content

**Do**:
```python
import os
from llama_parse import LlamaParse

# Predefined safe instructions - not user-controllable
SAFE_INSTRUCTIONS = {
    "general": "Extract all text content in markdown format. Preserve document structure.",
    "tables": "Focus on extracting tables with proper formatting. Preserve headers and cell alignment.",
    "technical": "Extract text, code blocks, and technical diagrams. Preserve formatting.",
    "minimal": "Extract plain text only. Ignore formatting, images, and tables."
}

def parse_with_instruction(file_path: str, instruction_type: str = "general"):
    """Parse with predefined safe instruction."""

    # Only allow predefined instructions
    if instruction_type not in SAFE_INSTRUCTIONS:
        raise ValueError(f"Invalid instruction type: {instruction_type}")

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        parsing_instruction=SAFE_INSTRUCTIONS[instruction_type]
    )

    return parser.load_data(file_path)

def parse_with_language(file_path: str, language: str = "en"):
    """Parse with language setting - validated."""

    # Whitelist of allowed languages
    ALLOWED_LANGUAGES = {"en", "es", "fr", "de", "it", "pt", "zh", "ja", "ko"}

    if language not in ALLOWED_LANGUAGES:
        language = "en"  # Default to English

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        language=language
    )

    return parser.load_data(file_path)
```

**Don't**:
```python
from llama_parse import LlamaParse
import os

def parse_with_user_instruction(file_path: str, user_instruction: str):
    # User-controlled instruction - injection risk
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        parsing_instruction=user_instruction  # Direct injection point
    )

    return parser.load_data(file_path)

def parse_with_language(file_path: str, language: str):
    # Unvalidated language parameter
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        language=language  # Could be injection vector
    )

    return parser.load_data(file_path)
```

**Why**: Parsing instructions are sent to LLM models for processing. User-controlled instructions can inject prompts that alter extraction behavior, exfiltrate data, or manipulate output. Always use predefined, validated instructions and whitelist language parameters.

**Refs**: CWE-94 (Code Injection), OWASP LLM01 (Prompt Injection), CWE-20 (Improper Input Validation)

---

## Rule: Output Sanitization

**Level**: `strict`

**When**: Using parsed content in downstream applications

**Do**:
```python
import os
import re
import html
from llama_parse import LlamaParse

def parse_and_sanitize(file_path: str, output_context: str = "llm"):
    """Parse document and sanitize output for intended context."""

    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )

    result = parser.load_data(file_path)

    sanitized_results = []
    for doc in result:
        text = doc.text

        if output_context == "llm":
            # Sanitize for LLM consumption - prevent prompt injection
            text = sanitize_for_llm(text)
        elif output_context == "web":
            # Sanitize for web display - prevent XSS
            text = sanitize_for_web(text)
        elif output_context == "database":
            # Sanitize for database storage
            text = sanitize_for_storage(text)

        sanitized_results.append(text)

    return sanitized_results

def sanitize_for_llm(text: str) -> str:
    """Sanitize text for LLM context to prevent prompt injection."""
    # Remove common prompt injection patterns
    injection_patterns = [
        r'ignore previous instructions',
        r'disregard all prior',
        r'system:\s*',
        r'assistant:\s*',
        r'<\|.*?\|>',  # Special tokens
        r'\[INST\].*?\[/INST\]',
    ]

    for pattern in injection_patterns:
        text = re.sub(pattern, '[FILTERED]', text, flags=re.IGNORECASE)

    # Escape delimiter characters
    text = text.replace('```', '\\`\\`\\`')

    return text

def sanitize_for_web(text: str) -> str:
    """Sanitize text for web display."""
    # HTML escape
    text = html.escape(text)
    # Remove any remaining script-like content
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    return text

def sanitize_for_storage(text: str) -> str:
    """Sanitize text for database storage."""
    # Remove null bytes
    text = text.replace('\x00', '')
    # Normalize unicode
    import unicodedata
    text = unicodedata.normalize('NFKC', text)
    return text
```

**Don't**:
```python
from llama_parse import LlamaParse
import os

def parse_document(file_path: str):
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown"
    )

    # Return raw unsanitized output
    return parser.load_data(file_path)

def use_in_prompt(parsed_text: str, user_query: str):
    # Direct concatenation without sanitization
    prompt = f"""
    Document content:
    {parsed_text}

    User query: {user_query}
    """
    return prompt
```

**Why**: Parsed documents may contain crafted content designed for prompt injection attacks when fed to LLMs, XSS attacks when displayed in web interfaces, or SQL injection when stored in databases. Output must be sanitized for its specific usage context.

**Refs**: CWE-79 (XSS), CWE-89 (SQL Injection), OWASP LLM01 (Prompt Injection), CWE-116 (Improper Encoding)

---

## Rule: Cost and Rate Limiting

**Level**: `warning`

**When**: Processing documents at scale or from untrusted sources

**Do**:
```python
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict
from llama_parse import LlamaParse

class RateLimitedParser:
    def __init__(
        self,
        max_pages_per_hour: int = 1000,
        max_requests_per_minute: int = 10,
        max_file_size_mb: int = 50
    ):
        self.max_pages_per_hour = max_pages_per_hour
        self.max_requests_per_minute = max_requests_per_minute
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

        self.page_count = 0
        self.page_count_reset = datetime.now() + timedelta(hours=1)
        self.request_timestamps = []

        # Per-user tracking
        self.user_usage = defaultdict(lambda: {"pages": 0, "reset": datetime.now() + timedelta(hours=1)})

    def check_rate_limit(self, user_id: str = None):
        """Check if request is within rate limits."""
        now = datetime.now()

        # Clean old request timestamps
        self.request_timestamps = [
            ts for ts in self.request_timestamps
            if now - ts < timedelta(minutes=1)
        ]

        if len(self.request_timestamps) >= self.max_requests_per_minute:
            wait_time = 60 - (now - self.request_timestamps[0]).seconds
            raise Exception(f"Rate limit exceeded. Wait {wait_time} seconds.")

        # Reset hourly counters
        if now > self.page_count_reset:
            self.page_count = 0
            self.page_count_reset = now + timedelta(hours=1)

        # Check per-user limits if user_id provided
        if user_id:
            user = self.user_usage[user_id]
            if now > user["reset"]:
                user["pages"] = 0
                user["reset"] = now + timedelta(hours=1)

    def parse_document(
        self,
        file_path: str,
        user_id: str = None,
        estimated_pages: int = None
    ):
        """Parse document with rate limiting and cost controls."""

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size_bytes:
            raise ValueError(f"File exceeds size limit")

        # Check rate limits
        self.check_rate_limit(user_id)

        # Estimate pages if not provided (rough estimate: 50KB per page)
        if estimated_pages is None:
            estimated_pages = max(1, file_size // (50 * 1024))

        # Check page budget
        if self.page_count + estimated_pages > self.max_pages_per_hour:
            raise Exception(f"Page limit exceeded. {self.max_pages_per_hour - self.page_count} pages remaining this hour.")

        # Per-user check
        if user_id:
            user_limit = self.max_pages_per_hour // 10  # 10% of total per user
            if self.user_usage[user_id]["pages"] + estimated_pages > user_limit:
                raise Exception(f"User page limit exceeded")

        # Record request
        self.request_timestamps.append(datetime.now())

        # Parse document
        parser = LlamaParse(
            api_key=os.environ["LLAMA_CLOUD_API_KEY"],
            result_type="markdown",
            num_workers=2  # Limit concurrent processing
        )

        result = parser.load_data(file_path)

        # Update usage counters
        actual_pages = len(result)
        self.page_count += actual_pages
        if user_id:
            self.user_usage[user_id]["pages"] += actual_pages

        return result

# Usage
rate_limited_parser = RateLimitedParser(
    max_pages_per_hour=1000,
    max_requests_per_minute=10
)

result = rate_limited_parser.parse_document(
    "document.pdf",
    user_id="user123",
    estimated_pages=50
)
```

**Don't**:
```python
from llama_parse import LlamaParse
import os

def parse_document(file_path: str):
    # No rate limiting or cost controls
    parser = LlamaParse(
        api_key=os.environ["LLAMA_CLOUD_API_KEY"],
        result_type="markdown",
        num_workers=8  # Maximum parallel processing
    )

    # Parse without any limits
    return parser.load_data(file_path)

def batch_parse(file_paths: list):
    # Process unlimited files with no throttling
    results = []
    for path in file_paths:
        results.append(parse_document(path))
    return results
```

**Why**: LlamaParse charges per page processed. Without rate limiting, attackers can cause significant financial damage through API abuse, or perform denial of service by exhausting quotas. Per-user limits prevent any single user from monopolizing resources. Page estimation helps budget costs before committing to processing.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), OWASP API4:2023 (Unrestricted Resource Consumption)
