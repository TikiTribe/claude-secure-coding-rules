# CLAUDE.md - Docling Document Parser Security Rules

Security rules for IBM Docling document parsing library in RAG pipelines.

**Prerequisites**: `rules/_core/rag-security.md`, `rules/rag/_core/document-processing-security.md`

---

## Rule: Secure Model Loading

**Level**: `strict`

**When**: Loading Docling models or custom document processing models

**Do**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.datamodel.pipeline_options import TesseractCliOcrOptions
from pathlib import Path

# Pin model weights to a pre-downloaded local directory.
# artifacts_path prevents docling from fetching weights at runtime.
ARTIFACTS_PATH = Path("/app/models/docling")

# Use a typed OcrOptions subclass — plain dicts are silently ignored at runtime.
ocr_options = TesseractCliOcrOptions()

pipeline_options = PdfPipelineOptions(
    do_ocr=True,
    ocr_options=ocr_options,
    # Both default False; set explicitly so intent is auditable.
    allow_external_plugins=False,
    enable_remote_services=False,
    artifacts_path=ARTIFACTS_PATH,
)

converter = DocumentConverter(pipeline_options=pipeline_options)

# Verify model checksums when using locally managed weights.
def load_verified_model(model_path: str, expected_hash: str) -> str:
    import hashlib
    with open(model_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError("Model integrity check failed")
    return model_path
```

**Don't**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions

# VULNERABLE: ocr_options is typed as OcrOptions — assigning a dict causes
# AttributeError at runtime because docling reads it as an OcrOptions object.
pipeline_options = PdfPipelineOptions()
pipeline_options.ocr_options = {
    "trust_remote_code": True,  # Not a docling API field; has no effect.
}

# VULNERABLE: Loading unverified custom models without integrity check.
converter = DocumentConverter(
    custom_model_path="/tmp/untrusted_model.bin"
)
```

**Why**: `ocr_options` is a Pydantic model field; a plain dict assignment is silently accepted by Python but triggers `AttributeError` when docling reads the field. `trust_remote_code` is a HuggingFace transformers parameter not present in docling's API. The genuine docling trust controls are `allow_external_plugins` and `enable_remote_services` (both `False` by default); `artifacts_path` pins offline model weights and prevents runtime downloads. Unverified models may be backdoored, enabling remote code execution.

**Refs**: CWE-502 (Deserialization), OWASP LLM05:2025 (Supply Chain), MITRE ATLAS ML Supply Chain Compromise

---

## Rule: Document Upload Validation

**Level**: `strict`

**When**: Accepting documents for processing via API or user upload

**Do**:
```python
import os
import magic
from pathlib import Path
from docling.document_converter import DocumentConverter

# Configuration
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "image/png",
    "image/jpeg",
    "text/html",
    "text/plain"
}
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".pptx", ".png", ".jpg", ".jpeg", ".html", ".txt"}

def validate_document(file_path: str, file_content: bytes) -> bool:
    """Validate document before processing with Docling."""
    # Check file size
    if len(file_content) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds maximum size of {MAX_FILE_SIZE} bytes")

    # Check extension
    ext = Path(file_path).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension {ext} not allowed")

    # Verify MIME type using magic bytes (not extension)
    detected_mime = magic.from_buffer(file_content, mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"MIME type {detected_mime} not allowed")

    # Check for path traversal
    safe_path = os.path.realpath(file_path)
    if not safe_path.startswith(os.path.realpath("/app/uploads/")):
        raise ValueError("Invalid file path")

    return True

# Use validated document
def process_document(file_path: str, file_content: bytes):
    validate_document(file_path, file_content)
    converter = DocumentConverter()
    result = converter.convert(file_path)
    return result
```

**Don't**:
```python
from docling.document_converter import DocumentConverter

def process_document(file_path: str):
    # VULNERABLE: No file size check - DoS via large files
    # VULNERABLE: No MIME type validation - can process malicious files
    # VULNERABLE: No path validation - path traversal attacks

    converter = DocumentConverter()
    result = converter.convert(file_path)  # Direct processing
    return result

# VULNERABLE: Trusting client-provided extension
def process_upload(filename: str, content: bytes):
    if filename.endswith(".pdf"):  # Only checks extension, not content
        with open(f"/uploads/{filename}", "wb") as f:
            f.write(content)
```

**Why**: Without validation, attackers can upload oversized files for DoS, malicious files disguised with fake extensions, or use path traversal to access sensitive files. Magic byte validation prevents extension spoofing attacks.

**Refs**: CWE-434 (Unrestricted File Upload), CWE-22 (Path Traversal), OWASP File Upload Cheat Sheet

---

## Rule: Scientific Document Resource Limits

**Level**: `strict`

**When**: Processing scientific documents with complex layouts, equations, or large tables

**Do**:
```python
import resource
import signal
from contextlib import contextmanager
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions

# Resource limits
MAX_PAGES = 500
MAX_PROCESSING_TIME = 300  # 5 minutes
MAX_MEMORY_MB = 2048

@contextmanager
def resource_limits(timeout_sec: int, max_memory_mb: int):
    """Apply resource limits during document processing."""
    # Set timeout
    def timeout_handler(signum, frame):
        raise TimeoutError("Document processing exceeded time limit")

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_sec)

    # Set memory limit
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(
        resource.RLIMIT_AS,
        (max_memory_mb * 1024 * 1024, hard)
    )

    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

def process_scientific_document(file_path: str):
    """Process scientific documents with resource controls."""
    pipeline_options = PdfPipelineOptions()
    pipeline_options.do_table_structure = True
    pipeline_options.do_ocr = True

    converter = DocumentConverter(pipeline_options=pipeline_options)

    # max_num_pages is a parameter on convert(), not on PdfPipelineOptions.
    # pipeline_options.page_range does not exist and would be silently ignored.
    with resource_limits(MAX_PROCESSING_TIME, MAX_MEMORY_MB):
        result = converter.convert(file_path, max_num_pages=MAX_PAGES)

    return result
```

**Don't**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions

def process_scientific_document(file_path: str):
    # VULNERABLE: No page limits - can process 10,000+ page documents
    # VULNERABLE: No timeout - infinite processing on complex documents
    # VULNERABLE: No memory limits - can exhaust system memory

    pipeline_options = PdfPipelineOptions()
    # BROKEN: page_range is not a PdfPipelineOptions field; this is a no-op.
    pipeline_options.page_range = (1, 500)

    converter = DocumentConverter(pipeline_options=pipeline_options)
    result = converter.convert(file_path)  # Unbounded processing
    return result
```

**Why**: Scientific documents can contain thousands of pages, complex tables, and intricate equations that consume excessive CPU and memory. Without limits, attackers can cause denial of service by submitting specially crafted documents that exhaust system resources. `pipeline_options.page_range` does not exist in the docling API and silently has no effect; page limits must be passed via `converter.convert(max_num_pages=...)`.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), NIST AI RMF

---

## Rule: Table and Figure Extraction Security

**Level**: `warning`

**When**: Extracting tables, figures, and images from documents

**Do**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
import os
import tempfile

# Secure configuration for table/figure extraction
MAX_TABLES_PER_DOC = 100
MAX_FIGURES_PER_DOC = 200
MAX_IMAGE_SIZE_MB = 10

def secure_table_extraction(file_path: str):
    """Extract tables with security controls."""
    pipeline_options = PdfPipelineOptions()
    pipeline_options.do_table_structure = True

    converter = DocumentConverter(pipeline_options=pipeline_options)
    result = converter.convert(file_path)

    # Limit number of extracted tables
    tables = []
    for item in result.document.tables[:MAX_TABLES_PER_DOC]:
        # Sanitize table content
        sanitized_table = sanitize_table_content(item)
        tables.append(sanitized_table)

    if len(result.document.tables) > MAX_TABLES_PER_DOC:
        result.metadata["tables_truncated"] = True

    return tables

def secure_figure_extraction(file_path: str, output_dir: str):
    """Extract figures with size and count limits."""
    # Ensure output directory is within allowed path
    safe_output = os.path.realpath(output_dir)
    if not safe_output.startswith("/app/output/"):
        raise ValueError("Invalid output directory")

    pipeline_options = PdfPipelineOptions()
    # generate_page_images is the current field; generate_picture_images is
    # retained for backwards compatibility but triggers a deprecation warning
    # in recent docling versions.
    pipeline_options.generate_page_images = True

    converter = DocumentConverter(pipeline_options=pipeline_options)
    result = converter.convert(file_path)

    figures = []
    for idx, figure in enumerate(result.document.pictures[:MAX_FIGURES_PER_DOC]):
        # Check image size before saving
        if hasattr(figure, 'image') and figure.image:
            img_size = len(figure.image.tobytes()) / (1024 * 1024)
            if img_size > MAX_IMAGE_SIZE_MB:
                continue  # Skip oversized images

        # Save with safe filename
        safe_name = f"figure_{idx:04d}.png"
        figure_path = os.path.join(safe_output, safe_name)
        figures.append(figure_path)

    return figures

def sanitize_table_content(table):
    """Remove potentially dangerous content from table cells."""
    import html
    for row in table.data:
        for i, cell in enumerate(row):
            # HTML encode to prevent XSS
            row[i] = html.escape(str(cell))
    return table
```

**Don't**:
```python
from docling.document_converter import DocumentConverter

def extract_tables(file_path: str):
    # VULNERABLE: No limit on extracted tables
    converter = DocumentConverter()
    result = converter.convert(file_path)
    return result.document.tables  # Could be thousands of tables

def extract_figures(file_path: str, output_dir: str):
    # VULNERABLE: No output path validation
    # VULNERABLE: No image size limits
    converter = DocumentConverter()
    result = converter.convert(file_path)

    for idx, figure in enumerate(result.document.pictures):
        # VULNERABLE: Using unsanitized filename
        figure.image.save(f"{output_dir}/{figure.name}")  # Path injection risk
```

**Why**: Unrestricted extraction can exhaust memory and disk space. Unsanitized filenames allow path traversal attacks. Table content may contain XSS payloads if rendered in web interfaces. Image extraction without size limits enables resource exhaustion.

**Refs**: CWE-400 (Resource Exhaustion), CWE-79 (XSS), CWE-22 (Path Traversal)

---

## Rule: Equation and Formula Handling

**Level**: `warning`

**When**: Processing documents with LaTeX equations or mathematical formulas

**Do**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.datamodel.document import DocItemLabel
import re

# Equation processing limits
MAX_EQUATIONS = 500
MAX_EQUATION_LENGTH = 5000
FORBIDDEN_LATEX_COMMANDS = [
    r"\\input",
    r"\\include",
    r"\\write",
    r"\\read",
    r"\\openin",
    r"\\openout",
    r"\\immediate",
    r"\\newcommand",
    r"\\def",
    r"\\csname",
    r"\\catcode"
]

def sanitize_latex(latex_content: str) -> str:
    """Remove potentially dangerous LaTeX commands."""
    if len(latex_content) > MAX_EQUATION_LENGTH:
        raise ValueError("Equation exceeds maximum length")

    # Check for forbidden commands
    for pattern in FORBIDDEN_LATEX_COMMANDS:
        if re.search(pattern, latex_content, re.IGNORECASE):
            raise ValueError("Forbidden LaTeX command detected")

    return latex_content

def process_equations(file_path: str):
    """Extract and sanitize equations from documents."""
    pipeline_options = PdfPipelineOptions(do_formula_enrichment=True)

    converter = DocumentConverter(pipeline_options=pipeline_options)
    result = converter.convert(file_path)

    equations = []
    # In docling v2, iterate result.document.texts and filter by item type.
    # result.document.main_text was removed in v2 and raises AttributeError.
    for idx, item in enumerate(result.document.texts):
        if idx >= MAX_EQUATIONS:
            break

        # Formula items carry their LaTeX in item.text
        if hasattr(item, 'label') and item.label == DocItemLabel.FORMULA:
            try:
                sanitized = sanitize_latex(item.text)
                equations.append(sanitized)
            except ValueError:
                # Log and skip malicious equations
                continue

    return equations

def render_equation_safely(latex: str) -> str:
    """Render LaTeX to image with sandboxing."""
    import subprocess
    import tempfile

    sanitized = sanitize_latex(latex)

    # Use restricted LaTeX profile
    with tempfile.TemporaryDirectory() as tmpdir:
        tex_file = f"{tmpdir}/eq.tex"
        with open(tex_file, "w") as f:
            f.write(
                f"\\documentclass{{standalone}}\n"
                f"\\begin{{document}}\n{sanitized}\n\\end{{document}}"
            )

        # Run with restrictions
        proc = subprocess.run(
            ["pdflatex", "-no-shell-escape", "-interaction=nonstopmode", tex_file],
            cwd=tmpdir,
            timeout=30,
            capture_output=True
        )

        if proc.returncode != 0:
            raise ValueError("LaTeX rendering failed")

        return f"{tmpdir}/eq.pdf"
```

**Don't**:
```python
from docling.document_converter import DocumentConverter

def process_equations(file_path: str):
    # VULNERABLE: No equation count limits
    converter = DocumentConverter()
    result = converter.convert(file_path)

    # BROKEN: result.document.main_text does not exist in docling v2; raises AttributeError.
    return [item.equation for item in result.document.main_text
            if hasattr(item, 'equation')]

def render_equation(latex: str):
    import subprocess
    # VULNERABLE: Shell escape enabled - allows command execution
    # VULNERABLE: No timeout - can hang indefinitely
    subprocess.run(
        ["pdflatex", "-shell-escape", latex],
        shell=True  # Command injection risk
    )
```

**Why**: LaTeX has powerful I/O commands that can read/write arbitrary files when shell escape is enabled. Malicious equations can execute system commands, exfiltrate data, or cause infinite loops. Without limits, equation-heavy documents cause resource exhaustion. `result.document.main_text` was removed in docling v2; using it raises `AttributeError` immediately on any current installation.

**Refs**: CWE-78 (OS Command Injection), CWE-400 (Resource Exhaustion), LaTeX Security Guidelines

---

## Rule: Output Sanitization

**Level**: `strict`

**When**: Using Docling output in downstream applications (web display, databases, LLM prompts)

**Do**:
```python
from docling.document_converter import DocumentConverter
import html
import re

def get_safe_text_output(file_path: str) -> str:
    """Extract and sanitize text for safe use in applications."""
    converter = DocumentConverter()
    result = converter.convert(file_path)

    # Get text content
    text = result.document.export_to_text()

    # Sanitize for different contexts
    return sanitize_for_context(text, context="web")

def sanitize_for_context(text: str, context: str) -> str:
    """Sanitize text based on output context."""
    if context == "web":
        # HTML encode to prevent XSS
        text = html.escape(text)
        # Remove potential script injection patterns
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)

    elif context == "sql":
        # Use parameterized queries instead, but as defense in depth:
        text = text.replace("'", "''")
        text = text.replace("\\", "\\\\")

    elif context == "llm":
        # Prevent prompt injection
        text = sanitize_for_llm(text)

    return text

def sanitize_for_llm(text: str) -> str:
    """Sanitize document text before including in LLM prompts."""
    # Remove common prompt injection patterns
    injection_patterns = [
        r"ignore previous instructions",
        r"disregard above",
        r"system prompt:",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"```system",
    ]

    for pattern in injection_patterns:
        text = re.sub(pattern, "[FILTERED]", text, flags=re.IGNORECASE)

    # Truncate to reasonable length
    max_length = 50000
    if len(text) > max_length:
        text = text[:max_length] + "\n[TRUNCATED]"

    return text

def safe_json_export(file_path: str) -> dict:
    """Export document as sanitized JSON."""
    converter = DocumentConverter()
    result = converter.convert(file_path)

    # Get JSON export
    doc_json = result.document.export_to_dict()

    # Recursively sanitize all string values
    return sanitize_dict(doc_json)

def sanitize_dict(obj):
    """Recursively sanitize dictionary values."""
    if isinstance(obj, dict):
        return {k: sanitize_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_dict(item) for item in obj]
    elif isinstance(obj, str):
        return html.escape(obj)
    return obj
```

**Don't**:
```python
from docling.document_converter import DocumentConverter

def get_document_text(file_path: str):
    converter = DocumentConverter()
    result = converter.convert(file_path)

    # VULNERABLE: Unsanitized output used directly
    return result.document.export_to_text()

def display_in_web(file_path: str):
    text = get_document_text(file_path)
    # VULNERABLE: Direct HTML injection
    return f"<div>{text}</div>"

def query_database(file_path: str):
    text = get_document_text(file_path)
    # VULNERABLE: SQL injection
    cursor.execute(f"INSERT INTO docs (content) VALUES ('{text}')")

def send_to_llm(file_path: str):
    text = get_document_text(file_path)
    # VULNERABLE: Prompt injection
    prompt = f"Summarize this document:\n{text}"
```

**Why**: Document content can contain malicious payloads including XSS scripts, SQL injection, and prompt injection attacks. Without context-aware sanitization, these payloads execute in downstream systems, leading to data theft, unauthorized actions, or system compromise.

**Refs**: CWE-79 (XSS), CWE-89 (SQL Injection), OWASP LLM01:2025 (Prompt Injection), CWE-116 (Output Encoding)

---

## Rule: Pipeline Configuration Security

**Level**: `warning`

**When**: Configuring Docling pipelines and processing options

**Do**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
from docling.datamodel.base_models import ConversionStatus
import yaml
import os

# Secure default configuration
SECURE_PIPELINE_CONFIG = {
    "do_ocr": True,
    "do_table_structure": True,
    "generate_page_images": False,  # Disable unless needed
    "max_pages": 500,
    "timeout_seconds": 300,
}

def load_secure_config(config_path: str) -> dict:
    """Load and validate pipeline configuration."""
    # Validate config path
    safe_path = os.path.realpath(config_path)
    if not safe_path.startswith("/app/config/"):
        raise ValueError("Invalid configuration path")

    with open(safe_path, 'r') as f:
        config = yaml.safe_load(f)

    # Validate configuration values
    validated = validate_config(config)
    return validated

def validate_config(config: dict) -> dict:
    """Validate pipeline configuration values."""
    validated = SECURE_PIPELINE_CONFIG.copy()

    # Only allow specific keys to be overridden
    allowed_overrides = {"do_ocr", "do_table_structure", "max_pages"}

    for key in allowed_overrides:
        if key in config:
            value = config[key]
            # Validate value types and ranges
            if key == "max_pages" and (not isinstance(value, int) or value > 1000):
                raise ValueError(f"Invalid max_pages: {value}")
            validated[key] = value

    return validated

def create_secure_pipeline(config: dict = None):
    """Create pipeline with secure defaults."""
    if config is None:
        config = SECURE_PIPELINE_CONFIG
    else:
        config = validate_config(config)

    pipeline_options = PdfPipelineOptions()
    pipeline_options.do_ocr = config.get("do_ocr", True)
    pipeline_options.do_table_structure = config.get("do_table_structure", True)

    converter = DocumentConverter(pipeline_options=pipeline_options)

    # max_num_pages is a convert() parameter, not a PdfPipelineOptions field.
    # pipeline_options.page_range does not exist and would be silently ignored.
    max_pages = config.get("max_pages", 500)
    return converter, max_pages

def convert_with_limits(converter: DocumentConverter, file_path: str, max_pages: int):
    """Run conversion with page limit enforced via the correct API."""
    return converter.convert(file_path, max_num_pages=max_pages)

def handle_conversion_errors(result) -> dict:
    """Safely handle conversion results and errors."""
    if result.status == ConversionStatus.FAILURE:
        # Don't expose internal error details
        return {
            "success": False,
            "error": "Document conversion failed"
            # Don't include: result.error_message (may leak paths/internals)
        }

    # page_count is on InputDocument (result.input), not on DoclingDocument (result.document).
    return {
        "success": True,
        "page_count": result.input.page_count
    }
```

**Don't**:
```python
from docling.document_converter import DocumentConverter
from docling.datamodel.pipeline_options import PdfPipelineOptions
import yaml

def load_config(config_path: str):
    # VULNERABLE: No path validation
    # VULNERABLE: Using yaml.load without safe_load
    with open(config_path, 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)  # Allows code execution
    return config

def create_pipeline(config: dict):
    # VULNERABLE: No validation of config values
    pipeline_options = PdfPipelineOptions()

    # Directly applying untrusted config
    for key, value in config.items():
        setattr(pipeline_options, key, value)  # Arbitrary attribute setting

    # BROKEN: page_range is not a PdfPipelineOptions field; silently a no-op.
    pipeline_options.page_range = (1, 500)

    return DocumentConverter(pipeline_options=pipeline_options)

def process_with_errors(file_path: str):
    converter = DocumentConverter()
    result = converter.convert(file_path)

    if result.status == "FAILURE":
        # VULNERABLE: Exposes internal error details
        raise Exception(f"Failed: {result.error_message} at {result.error_trace}")

def broken_page_count(result):
    # BROKEN: page_count is on result.input, not result.document; raises AttributeError.
    return result.document.page_count
```

**Why**: Untrusted configuration can override security controls or set dangerous options. YAML deserialization with unsafe loaders enables code execution. Exposing internal error messages leaks sensitive information about system internals and file paths. `pipeline_options.page_range` is not a docling API field and silently does nothing; page limits must use `converter.convert(max_num_pages=...)`. `result.document.page_count` does not exist in docling v2; the correct attribute is `result.input.page_count`.

**Refs**: CWE-502 (Deserialization), CWE-209 (Error Information Exposure), OWASP Configuration Security

---

## Rule: Caching and Temporary File Security

**Level**: `warning`

**When**: Caching parsed documents or creating temporary files during processing

**Do**:
```python
import tempfile
import os
import hashlib
import shutil
from pathlib import Path
from docling.document_converter import DocumentConverter

# Secure cache configuration
CACHE_DIR = "/app/cache/docling"
MAX_CACHE_SIZE_GB = 10
CACHE_TTL_HOURS = 24

def get_secure_cache_path(file_content: bytes, user_id: str) -> str:
    """Generate secure cache path based on content hash."""
    # Create deterministic but unique cache key
    content_hash = hashlib.sha256(file_content).hexdigest()
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8]

    # Prevent cache poisoning between users
    cache_key = f"{user_hash}_{content_hash}"

    # Ensure path is within cache directory
    cache_path = os.path.join(CACHE_DIR, cache_key[:2], cache_key)
    safe_path = os.path.realpath(cache_path)

    if not safe_path.startswith(os.path.realpath(CACHE_DIR)):
        raise ValueError("Invalid cache path")

    return safe_path

def process_with_secure_temp(file_content: bytes):
    """Process document using secure temporary files."""
    # Create temp directory with restricted permissions
    with tempfile.TemporaryDirectory(
        prefix="docling_",
        dir="/app/tmp"  # Controlled location
    ) as tmpdir:
        # Set restrictive permissions
        os.chmod(tmpdir, 0o700)

        # Write file with safe name
        temp_file = os.path.join(tmpdir, "document.pdf")
        with open(temp_file, "wb") as f:
            f.write(file_content)

        # Process document
        converter = DocumentConverter()
        result = converter.convert(temp_file)

        # Temp directory auto-cleaned on exit
        return result.document.export_to_markdown()

def cleanup_cache():
    """Securely clean up old cache entries."""
    import time

    cutoff_time = time.time() - (CACHE_TTL_HOURS * 3600)
    total_size = 0

    for root, dirs, files in os.walk(CACHE_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            stat = os.stat(file_path)

            # Remove old files
            if stat.st_mtime < cutoff_time:
                os.unlink(file_path)
            else:
                total_size += stat.st_size

    # Check total cache size
    if total_size > MAX_CACHE_SIZE_GB * 1024 * 1024 * 1024:
        # Implement LRU cleanup
        pass

def secure_file_permissions(file_path: str):
    """Ensure file has secure permissions."""
    os.chmod(file_path, 0o600)  # Owner read/write only
```

**Don't**:
```python
import tempfile
from docling.document_converter import DocumentConverter

def process_document(file_content: bytes):
    # VULNERABLE: Predictable temp file name
    temp_path = "/tmp/docling_upload.pdf"
    with open(temp_path, "wb") as f:
        f.write(file_content)

    # VULNERABLE: No cleanup
    converter = DocumentConverter()
    result = converter.convert(temp_path)

    # File remains on disk after processing
    return result

def cache_result(file_path: str, result):
    # VULNERABLE: Using filename directly in cache path
    cache_path = f"/cache/{os.path.basename(file_path)}"  # Path traversal risk

    # VULNERABLE: World-readable cache
    with open(cache_path, "w") as f:
        f.write(result)
    # Default permissions may be too permissive

def get_cached(filename: str):
    # VULNERABLE: Cache poisoning - no user isolation
    cache_path = f"/cache/{filename}"
    if os.path.exists(cache_path):
        return open(cache_path).read()
```

**Why**: Predictable temporary file names allow race condition attacks and symlink attacks. Without proper cleanup, sensitive document content persists on disk. Shared cache without user isolation enables cache poisoning attacks where one user's malicious content is served to another user.

**Refs**: CWE-377 (Insecure Temp File), CWE-732 (Incorrect Permission), CWE-345 (Insufficient Verification of Data Authenticity)
