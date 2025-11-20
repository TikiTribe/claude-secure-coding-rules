# CLAUDE.md - Document Parser and OCR Security Rules

Security rules for document parsing and OCR tools including PyMuPDF, Marker, Tesseract, and Azure Document Intelligence.

## Prerequisites

- `rules/_core/ai-security.md` - Core AI/ML security principles
- `rules/rag/_core/document-processing-security.md` - Document processing foundations

## Overview

Document parsers and OCR tools process untrusted files that may contain malicious payloads. These rules ensure secure handling of PDFs, images, and other document formats while preventing resource exhaustion, injection attacks, and unsafe code execution.

---

## Rule: PyMuPDF File Validation and Resource Limits

**Level**: `strict`

**When**: Processing PDF files with PyMuPDF (fitz)

**Do**:
```python
import fitz
import os
from pathlib import Path

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_PAGES = 1000
ALLOWED_EXTENSIONS = {'.pdf'}

def validate_and_open_pdf(file_path: str) -> fitz.Document:
    """Securely open PDF with validation and resource limits."""
    path = Path(file_path)

    # Validate extension
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file type: {path.suffix}")

    # Check file size before opening
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})")

    # Open with error handling
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        raise ValueError(f"Failed to open PDF: {e}")

    # Validate page count
    if doc.page_count > MAX_PAGES:
        doc.close()
        raise ValueError(f"Too many pages: {doc.page_count} (max: {MAX_PAGES})")

    # Check for encryption (may indicate evasion)
    if doc.is_encrypted:
        doc.close()
        raise ValueError("Encrypted PDFs not supported")

    return doc

def extract_text_safely(doc: fitz.Document, timeout_per_page: float = 5.0) -> str:
    """Extract text with per-page timeout protection."""
    import signal

    def timeout_handler(signum, frame):
        raise TimeoutError("Page extraction timeout")

    text_parts = []
    for page_num in range(doc.page_count):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout_per_page)
        try:
            page = doc[page_num]
            text_parts.append(page.get_text())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    return "\n".join(text_parts)
```

**Don't**:
```python
import fitz

def process_pdf(file_path):
    # No validation - vulnerable to malicious PDFs
    doc = fitz.open(file_path)  # Opens any file type

    # No size/page limits - resource exhaustion
    text = ""
    for page in doc:  # Could be millions of pages
        text += page.get_text()  # No timeout

    return text
```

**Why**: Malicious PDFs can contain crafted content designed to exploit parser vulnerabilities, cause excessive memory usage through deeply nested objects, or trigger CPU exhaustion through complex rendering operations. Without validation, attackers can process arbitrary file types or overwhelm systems with large documents.

**Refs**: CWE-400, CWE-434, OWASP A03:2025, CVE-2022-41853 (PyMuPDF vulnerability)

---

## Rule: PyMuPDF JavaScript and Link Extraction Security

**Level**: `strict`

**When**: Extracting links, annotations, or JavaScript from PDFs

**Do**:
```python
import fitz
import re
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_PATTERNS = [
    r'javascript:',
    r'data:',
    r'file:',
    r'vbscript:',
]

def extract_links_safely(doc: fitz.Document) -> list[dict]:
    """Extract and sanitize links from PDF."""
    safe_links = []

    for page_num in range(doc.page_count):
        page = doc[page_num]
        links = page.get_links()

        for link in links:
            uri = link.get('uri', '')

            # Skip JavaScript and dangerous URIs
            if any(re.search(pattern, uri, re.IGNORECASE) for pattern in BLOCKED_PATTERNS):
                continue

            # Validate URL scheme
            try:
                parsed = urlparse(uri)
                if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                    continue
            except Exception:
                continue

            safe_links.append({
                'page': page_num,
                'uri': uri,
                'type': link.get('kind', 'unknown')
            })

    return safe_links

def check_for_javascript(doc: fitz.Document) -> bool:
    """Check if PDF contains JavaScript (potential risk)."""
    # Check document-level JavaScript
    js = doc.get_page_javascripts()
    if js:
        return True

    # Check for JavaScript in annotations
    for page_num in range(doc.page_count):
        page = doc[page_num]
        for annot in page.annots() or []:
            if annot.type[0] == 13:  # Widget annotation
                # May contain JavaScript actions
                return True

    return False
```

**Don't**:
```python
import fitz

def extract_all_links(doc):
    links = []
    for page in doc:
        # Extracts all URIs without validation
        for link in page.get_links():
            links.append(link['uri'])  # Includes javascript: URIs
    return links

def execute_pdf_javascript(doc):
    # NEVER execute JavaScript from untrusted PDFs
    js_code = doc.get_page_javascripts()
    for script in js_code:
        exec(script)  # Critical vulnerability
```

**Why**: PDFs can contain JavaScript code and malicious URI schemes (javascript:, data:, file:) that can execute code or access local files when links are followed. Extracting and displaying these without sanitization can lead to XSS attacks or local file access.

**Refs**: CWE-79, CWE-94, OWASP A03:2025

---

## Rule: Marker Model Loading Security

**Level**: `strict`

**When**: Using Marker for PDF to markdown conversion with ML models

**Do**:
```python
from marker.converters.pdf import PdfConverter
from marker.models import create_model_dict

def create_secure_converter() -> PdfConverter:
    """Create Marker converter with secure model loading."""
    # Load models with trust_remote_code disabled
    model_dict = create_model_dict()

    # Verify models are from trusted sources
    for model_name, model in model_dict.items():
        # Check model doesn't use remote code
        if hasattr(model, 'config'):
            if getattr(model.config, 'trust_remote_code', False):
                raise ValueError(f"Model {model_name} uses untrusted remote code")

    converter = PdfConverter(
        artifact_dict=model_dict,
    )

    return converter

def convert_pdf_safely(converter: PdfConverter, file_path: str) -> str:
    """Convert PDF with security validation."""
    import os

    # Validate file exists and is readable
    if not os.path.isfile(file_path):
        raise ValueError("File not found")

    # Size check
    if os.path.getsize(file_path) > 50 * 1024 * 1024:  # 50MB
        raise ValueError("File too large for conversion")

    # Convert with resource monitoring
    result = converter(file_path)

    return result.markdown
```

**Don't**:
```python
from transformers import AutoModel

def load_marker_model(model_name: str):
    # Dangerous: allows arbitrary code execution from model repos
    model = AutoModel.from_pretrained(
        model_name,
        trust_remote_code=True  # NEVER for untrusted models
    )
    return model

def convert_any_pdf(file_path):
    # No validation, no resource limits
    from marker.converters.pdf import PdfConverter
    converter = PdfConverter()
    return converter(file_path).markdown
```

**Why**: ML models can contain arbitrary Python code that executes during loading. The `trust_remote_code=True` setting allows models from Hugging Face Hub to run custom code, which can be exploited to execute malware, steal credentials, or compromise the system.

**Refs**: CWE-502, CWE-94, OWASP LLM06 (Sensitive Information Disclosure), MITRE ATLAS AML.T0010 (ML Supply Chain Compromise)

---

## Rule: Marker Output Sanitization

**Level**: `warning`

**When**: Using Marker output in web applications or downstream processing

**Do**:
```python
import html
import re
from marker.converters.pdf import PdfConverter

def sanitize_markdown_output(markdown: str) -> str:
    """Sanitize Marker output to prevent injection attacks."""
    # Remove potential HTML/script injection in markdown
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'on\w+\s*=',  # Event handlers
        r'javascript:',
        r'data:text/html',
    ]

    sanitized = markdown
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)

    return sanitized

def convert_and_sanitize(converter: PdfConverter, file_path: str) -> str:
    """Convert PDF and sanitize output."""
    result = converter(file_path)

    # Sanitize markdown content
    safe_markdown = sanitize_markdown_output(result.markdown)

    # If rendering to HTML, use safe markdown renderer
    # with HTML escaping enabled

    return safe_markdown

def render_markdown_safely(markdown: str) -> str:
    """Render markdown to HTML with XSS protection."""
    import markdown as md

    # Use safe mode with restricted HTML
    html_output = md.markdown(
        markdown,
        extensions=['tables', 'fenced_code'],
        # Don't allow raw HTML in markdown
        extension_configs={
            'html': {'safe_mode': 'escape'}
        }
    )

    return html_output
```

**Don't**:
```python
from marker.converters.pdf import PdfConverter

def convert_and_display(file_path):
    converter = PdfConverter()
    result = converter(file_path)

    # Directly embedding untrusted content - XSS risk
    return f"<div>{result.markdown}</div>"

def store_raw_output(result):
    # Storing without sanitization - injection risk for downstream
    database.store(result.markdown)  # May contain malicious content
```

**Why**: Marker extracts text that may contain content crafted to exploit markdown or HTML renderers. Malicious PDFs can embed content that becomes executable code when rendered as HTML, leading to XSS attacks or content injection in downstream systems.

**Refs**: CWE-79, CWE-116, OWASP A03:2025

---

## Rule: Tesseract Input Validation

**Level**: `strict`

**When**: Processing images with Tesseract OCR

**Do**:
```python
import pytesseract
from PIL import Image
import os
from pathlib import Path

MAX_IMAGE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_DIMENSIONS = (10000, 10000)  # Max width x height
ALLOWED_FORMATS = {'PNG', 'JPEG', 'TIFF', 'BMP', 'GIF', 'WEBP'}

def validate_image(file_path: str) -> Image.Image:
    """Validate image before OCR processing."""
    path = Path(file_path)

    # Check file exists
    if not path.is_file():
        raise ValueError("File not found")

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_IMAGE_SIZE:
        raise ValueError(f"Image too large: {file_size} bytes")

    # Open and validate image
    try:
        img = Image.open(file_path)
        img.verify()  # Verify image integrity
        img = Image.open(file_path)  # Reopen after verify
    except Exception as e:
        raise ValueError(f"Invalid image file: {e}")

    # Check format
    if img.format not in ALLOWED_FORMATS:
        raise ValueError(f"Unsupported format: {img.format}")

    # Check dimensions (prevent decompression bombs)
    if img.size[0] > MAX_DIMENSIONS[0] or img.size[1] > MAX_DIMENSIONS[1]:
        raise ValueError(f"Image dimensions too large: {img.size}")

    # Check for decompression bomb
    pixel_count = img.size[0] * img.size[1]
    if pixel_count > 178956970:  # PIL default limit
        raise ValueError("Image pixel count exceeds safety limit")

    return img

def ocr_image_safely(file_path: str, lang: str = 'eng') -> str:
    """Perform OCR with validated input."""
    # Validate language parameter
    allowed_langs = {'eng', 'fra', 'deu', 'spa', 'ita', 'por', 'nld'}
    if lang not in allowed_langs:
        raise ValueError(f"Unsupported language: {lang}")

    # Validate image
    img = validate_image(file_path)

    # Perform OCR with safe configuration
    text = pytesseract.image_to_string(
        img,
        lang=lang,
        config='--psm 3'  # Fully automatic page segmentation
    )

    return text
```

**Don't**:
```python
import pytesseract
from PIL import Image

def ocr_any_image(file_path, lang):
    # No validation - vulnerable to malicious images
    img = Image.open(file_path)  # Could be malformed

    # User-controlled language - command injection risk
    text = pytesseract.image_to_string(
        img,
        lang=lang,  # Could be "; rm -rf /"
        config=f'--user-words {user_file}'  # Path traversal risk
    )

    return text
```

**Why**: Malicious images can exploit vulnerabilities in image parsing libraries (PIL/Pillow), cause memory exhaustion through decompression bombs, or trigger buffer overflows. Unsanitized Tesseract parameters can lead to command injection since Tesseract is a command-line tool.

**Refs**: CWE-434, CWE-78, CWE-400, OWASP A03:2025

---

## Rule: Tesseract Resource Limits

**Level**: `strict`

**When**: Running Tesseract OCR in production environments

**Do**:
```python
import pytesseract
from PIL import Image
import multiprocessing
import signal

OCR_TIMEOUT = 60  # seconds
MAX_MEMORY_MB = 1024

def ocr_with_timeout(img: Image.Image, timeout: int = OCR_TIMEOUT) -> str:
    """Run OCR with timeout protection."""
    def timeout_handler(signum, frame):
        raise TimeoutError("OCR operation timed out")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        result = pytesseract.image_to_string(img)
        return result
    finally:
        signal.alarm(0)

def ocr_with_resource_limits(img: Image.Image) -> str:
    """Run OCR in subprocess with resource limits."""
    import resource

    def run_ocr():
        # Set memory limit
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(
            resource.RLIMIT_AS,
            (MAX_MEMORY_MB * 1024 * 1024, hard)
        )
        return pytesseract.image_to_string(img)

    # Run in separate process with timeout
    with multiprocessing.Pool(1) as pool:
        result = pool.apply_async(run_ocr)
        try:
            return result.get(timeout=OCR_TIMEOUT)
        except multiprocessing.TimeoutError:
            pool.terminate()
            raise TimeoutError("OCR exceeded time limit")

def batch_ocr_safely(
    images: list[Image.Image],
    max_concurrent: int = 4
) -> list[str]:
    """Process multiple images with controlled concurrency."""
    results = []

    with multiprocessing.Pool(max_concurrent) as pool:
        async_results = [
            pool.apply_async(
                pytesseract.image_to_string,
                (img,)
            )
            for img in images
        ]

        for async_result in async_results:
            try:
                text = async_result.get(timeout=OCR_TIMEOUT)
                results.append(text)
            except multiprocessing.TimeoutError:
                results.append("")  # Skip timed-out images

    return results
```

**Don't**:
```python
import pytesseract
from PIL import Image

def ocr_all_images(image_paths):
    results = []
    for path in image_paths:
        # No timeout - can hang indefinitely
        img = Image.open(path)
        # No memory limits - can exhaust system
        text = pytesseract.image_to_string(img)
        results.append(text)
    return results

def parallel_ocr_unlimited(images):
    # Unlimited parallelism - can overwhelm system
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor() as executor:  # No max_workers limit
        results = list(executor.map(pytesseract.image_to_string, images))
    return results
```

**Why**: Tesseract OCR can consume significant CPU and memory, especially with complex images or adversarial inputs designed to maximize processing time. Without resource limits, attackers can cause denial of service by submitting images that trigger worst-case performance.

**Refs**: CWE-400, CWE-770, OWASP A05:2025 (Security Misconfiguration)

---

## Rule: Azure Document Intelligence API Security

**Level**: `strict`

**When**: Using Azure AI Document Intelligence (Form Recognizer)

**Do**:
```python
from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential
from azure.identity import DefaultAzureCredential
import os

def create_secure_client() -> DocumentAnalysisClient:
    """Create Document Intelligence client with secure authentication."""
    endpoint = os.environ.get("AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT")

    if not endpoint:
        raise ValueError("Endpoint not configured")

    # Prefer managed identity over API keys
    try:
        credential = DefaultAzureCredential()
        client = DocumentAnalysisClient(
            endpoint=endpoint,
            credential=credential
        )
    except Exception:
        # Fallback to API key (less secure)
        api_key = os.environ.get("AZURE_DOCUMENT_INTELLIGENCE_KEY")
        if not api_key:
            raise ValueError("No credentials available")

        client = DocumentAnalysisClient(
            endpoint=endpoint,
            credential=AzureKeyCredential(api_key)
        )

    return client

def analyze_document_safely(
    client: DocumentAnalysisClient,
    file_path: str,
    model_id: str = "prebuilt-document"
) -> dict:
    """Analyze document with security controls."""
    # Validate model ID (only allow prebuilt models by default)
    allowed_models = {
        "prebuilt-document",
        "prebuilt-layout",
        "prebuilt-read",
        "prebuilt-invoice",
        "prebuilt-receipt",
        "prebuilt-idDocument",
        "prebuilt-businessCard",
    }

    if model_id not in allowed_models:
        # Custom models need explicit approval
        if not model_id.startswith("custom-") or not is_approved_model(model_id):
            raise ValueError(f"Model not allowed: {model_id}")

    # Validate file
    if not os.path.isfile(file_path):
        raise ValueError("File not found")

    file_size = os.path.getsize(file_path)
    if file_size > 500 * 1024 * 1024:  # 500MB Azure limit
        raise ValueError("File exceeds size limit")

    # Analyze with polling
    with open(file_path, "rb") as f:
        poller = client.begin_analyze_document(
            model_id=model_id,
            document=f
        )

    result = poller.result()

    return {
        "content": result.content,
        "pages": len(result.pages),
        "tables": len(result.tables) if result.tables else 0,
    }

def is_approved_model(model_id: str) -> bool:
    """Check if custom model is approved for use."""
    # Implement approval check against allowlist
    approved_models = os.environ.get("APPROVED_CUSTOM_MODELS", "").split(",")
    return model_id in approved_models
```

**Don't**:
```python
from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential

def create_client():
    # Hardcoded credentials - exposure risk
    client = DocumentAnalysisClient(
        endpoint="https://myservice.cognitiveservices.azure.com/",
        credential=AzureKeyCredential("abc123secretkey")  # Never hardcode
    )
    return client

def analyze_with_any_model(client, file_path, model_id):
    # No model validation - can use unreviewed custom models
    with open(file_path, "rb") as f:
        poller = client.begin_analyze_document(
            model_id=model_id,  # User-controlled, no validation
            document=f
        )
    return poller.result()
```

**Why**: Hardcoded credentials can be exposed through source control or logs. API keys provide full access without audit trails or fine-grained permissions. Custom models may not have undergone security review and could be trained on sensitive or malicious data.

**Refs**: CWE-798, CWE-522, OWASP A07:2025 (Identification and Authentication Failures)

---

## Rule: Azure Document Intelligence Model Selection

**Level**: `warning`

**When**: Selecting models for Azure Document Intelligence analysis

**Do**:
```python
from azure.ai.formrecognizer import DocumentAnalysisClient
from enum import Enum

class DocumentModel(str, Enum):
    """Approved document analysis models."""
    GENERAL = "prebuilt-document"
    LAYOUT = "prebuilt-layout"
    READ = "prebuilt-read"
    INVOICE = "prebuilt-invoice"
    RECEIPT = "prebuilt-receipt"
    ID_DOCUMENT = "prebuilt-idDocument"

def select_model_for_document(
    document_type: str,
    sensitivity: str = "normal"
) -> str:
    """Select appropriate model based on document type and sensitivity."""
    model_map = {
        "general": DocumentModel.GENERAL,
        "text_only": DocumentModel.READ,
        "structured": DocumentModel.LAYOUT,
        "invoice": DocumentModel.INVOICE,
        "receipt": DocumentModel.RECEIPT,
        "id": DocumentModel.ID_DOCUMENT,
    }

    if document_type not in model_map:
        # Default to general for unknown types
        return DocumentModel.GENERAL.value

    # For sensitive documents, use read-only model (less data extraction)
    if sensitivity == "high" and document_type not in ["id"]:
        return DocumentModel.READ.value

    return model_map[document_type].value

def analyze_with_appropriate_model(
    client: DocumentAnalysisClient,
    file_path: str,
    document_type: str
) -> dict:
    """Analyze using the appropriate model for document type."""
    model_id = select_model_for_document(document_type)

    with open(file_path, "rb") as f:
        poller = client.begin_analyze_document(
            model_id=model_id,
            document=f
        )

    result = poller.result()

    # Filter output based on document type
    if document_type == "text_only":
        return {"content": result.content}

    return {
        "content": result.content,
        "key_value_pairs": [
            {"key": kv.key.content, "value": kv.value.content if kv.value else None}
            for kv in (result.key_value_pairs or [])
        ],
    }
```

**Don't**:
```python
def analyze_everything(client, file_path):
    # Using most powerful model for all documents - over-extraction risk
    with open(file_path, "rb") as f:
        poller = client.begin_analyze_document(
            model_id="prebuilt-document",  # Extracts maximum data
            document=f
        )

    result = poller.result()

    # Returning all extracted data without filtering
    return {
        "content": result.content,
        "key_value_pairs": result.key_value_pairs,
        "entities": result.entities,
        "tables": result.tables,
        "documents": result.documents,  # May contain PII
    }
```

**Why**: Different models extract different levels of information. Using overly powerful models can extract sensitive PII or financial data unnecessarily. Model selection should follow the principle of least privilege - extract only what is needed for the use case.

**Refs**: CWE-200, OWASP A01:2025 (Broken Access Control), NIST AI RMF (Data Minimization)

---

## Rule: OCR Result Sanitization

**Level**: `strict`

**When**: Using OCR output in applications, databases, or downstream systems

**Do**:
```python
import re
import html

def sanitize_ocr_output(text: str) -> str:
    """Sanitize OCR output to prevent injection attacks."""
    if not text:
        return ""

    # Remove null bytes and control characters (except newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # Remove potential SQL injection patterns
    sql_patterns = [
        r';\s*DROP\s+',
        r';\s*DELETE\s+',
        r';\s*INSERT\s+',
        r';\s*UPDATE\s+',
        r'--\s*$',
        r'/\*.*?\*/',
    ]
    for pattern in sql_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)

    return text

def sanitize_for_html(text: str) -> str:
    """Sanitize OCR output for HTML display."""
    # First apply general sanitization
    text = sanitize_ocr_output(text)

    # HTML encode special characters
    text = html.escape(text)

    return text

def sanitize_for_database(text: str) -> str:
    """Sanitize OCR output for database storage."""
    # Apply general sanitization
    text = sanitize_ocr_output(text)

    # Escape quotes for SQL (use parameterized queries instead when possible)
    text = text.replace("'", "''")

    # Limit length to prevent overflow
    max_length = 100000
    if len(text) > max_length:
        text = text[:max_length]

    return text

def store_ocr_result_safely(
    db_connection,
    document_id: str,
    ocr_text: str
) -> None:
    """Store OCR result using parameterized query."""
    sanitized_text = sanitize_ocr_output(ocr_text)

    # Always use parameterized queries
    cursor = db_connection.cursor()
    cursor.execute(
        "INSERT INTO ocr_results (document_id, content) VALUES (?, ?)",
        (document_id, sanitized_text)
    )
    db_connection.commit()
```

**Don't**:
```python
def store_ocr_directly(db_connection, doc_id, ocr_text):
    # Direct string interpolation - SQL injection vulnerability
    query = f"INSERT INTO ocr_results VALUES ('{doc_id}', '{ocr_text}')"
    db_connection.execute(query)

def display_ocr_result(ocr_text):
    # Direct HTML embedding - XSS vulnerability
    return f"<div class='ocr-result'>{ocr_text}</div>"

def use_ocr_in_command(ocr_text):
    import subprocess
    # Using OCR text in shell command - command injection
    subprocess.run(f"echo {ocr_text} | process_text", shell=True)
```

**Why**: OCR can extract text that contains injection payloads intentionally embedded in documents. Attackers can create documents with text designed to exploit SQL injection, XSS, or command injection vulnerabilities when the OCR output is used unsafely in downstream systems.

**Refs**: CWE-79, CWE-89, CWE-78, OWASP A03:2025

---

## Rule: Multi-Format Document Handling Security

**Level**: `warning`

**When**: Processing multiple document formats (PDF, images, Office documents)

**Do**:
```python
from pathlib import Path
from enum import Enum
import mimetypes
import magic  # python-magic

class DocumentType(str, Enum):
    PDF = "pdf"
    IMAGE = "image"
    OFFICE = "office"
    UNKNOWN = "unknown"

# Allowed MIME types per category
ALLOWED_MIME_TYPES = {
    DocumentType.PDF: {"application/pdf"},
    DocumentType.IMAGE: {
        "image/png",
        "image/jpeg",
        "image/tiff",
        "image/bmp",
        "image/gif",
        "image/webp",
    },
    DocumentType.OFFICE: {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    },
}

def detect_document_type(file_path: str) -> DocumentType:
    """Detect document type using magic bytes, not extension."""
    # Use libmagic for reliable detection
    mime = magic.from_file(file_path, mime=True)

    for doc_type, mime_types in ALLOWED_MIME_TYPES.items():
        if mime in mime_types:
            return doc_type

    return DocumentType.UNKNOWN

def validate_document_format(file_path: str) -> tuple[DocumentType, str]:
    """Validate document format and return type with MIME."""
    path = Path(file_path)

    if not path.is_file():
        raise ValueError("File not found")

    # Detect actual type (not based on extension)
    detected_type = detect_document_type(file_path)
    mime_type = magic.from_file(file_path, mime=True)

    if detected_type == DocumentType.UNKNOWN:
        raise ValueError(f"Unsupported document type: {mime_type}")

    # Verify extension matches content (prevent extension spoofing)
    extension = path.suffix.lower()
    expected_extensions = {
        DocumentType.PDF: {".pdf"},
        DocumentType.IMAGE: {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".gif", ".webp"},
        DocumentType.OFFICE: {".docx", ".xlsx", ".pptx"},
    }

    if extension not in expected_extensions.get(detected_type, set()):
        raise ValueError(f"Extension {extension} doesn't match content type {detected_type}")

    return detected_type, mime_type

def process_document_by_type(file_path: str) -> str:
    """Process document using appropriate handler for its type."""
    doc_type, mime_type = validate_document_format(file_path)

    if doc_type == DocumentType.PDF:
        return process_pdf_document(file_path)
    elif doc_type == DocumentType.IMAGE:
        return process_image_document(file_path)
    elif doc_type == DocumentType.OFFICE:
        return process_office_document(file_path)
    else:
        raise ValueError(f"No handler for type: {doc_type}")

def process_pdf_document(file_path: str) -> str:
    """Process PDF with PyMuPDF."""
    import fitz
    doc = fitz.open(file_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()
    return text

def process_image_document(file_path: str) -> str:
    """Process image with Tesseract."""
    import pytesseract
    from PIL import Image
    img = Image.open(file_path)
    return pytesseract.image_to_string(img)

def process_office_document(file_path: str) -> str:
    """Process Office document with appropriate library."""
    # Use python-docx, openpyxl, or python-pptx
    # Implementation depends on document type
    raise NotImplementedError("Office processing not implemented")
```

**Don't**:
```python
def process_by_extension(file_path):
    # Trusting file extension - easily spoofed
    if file_path.endswith('.pdf'):
        return process_pdf(file_path)
    elif file_path.endswith('.jpg'):
        return process_image(file_path)
    # Attacker can rename malware.exe to document.pdf

def process_all_formats(file_path):
    # No validation - tries all processors
    try:
        return process_pdf(file_path)
    except:
        pass
    try:
        return process_image(file_path)
    except:
        pass
    # May execute dangerous parsers on wrong file types
```

**Why**: File extensions can be spoofed to bypass security controls. Attackers can rename malicious files to have allowed extensions. Processing files with the wrong parser can trigger vulnerabilities or bypass sanitization. Magic byte detection provides more reliable format identification.

**Refs**: CWE-434, CWE-345, OWASP A04:2025 (Insecure Design)

---

## Summary

| Rule | Level | Primary Risk | Key Control |
|------|-------|--------------|-------------|
| PyMuPDF File Validation | strict | Resource exhaustion, malformed PDFs | Size/page limits, encryption check |
| PyMuPDF JavaScript/Links | strict | Code execution, XSS | URI sanitization, block javascript: |
| Marker Model Loading | strict | Arbitrary code execution | trust_remote_code=False |
| Marker Output Sanitization | warning | XSS, injection | Sanitize markdown, escape HTML |
| Tesseract Input Validation | strict | Malicious images, command injection | Format validation, parameter sanitization |
| Tesseract Resource Limits | strict | DoS, resource exhaustion | Timeout, memory limits |
| Azure API Security | strict | Credential exposure | Managed identity, no hardcoding |
| Azure Model Selection | warning | Over-extraction of PII | Model allowlist, least privilege |
| OCR Result Sanitization | strict | SQL/XSS/command injection | Parameterized queries, HTML encoding |
| Multi-Format Handling | warning | Extension spoofing, wrong parser | Magic byte detection, type validation |
