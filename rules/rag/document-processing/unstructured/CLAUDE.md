# Unstructured Document Processing Security Rules

Security patterns for the Unstructured library used in RAG document ingestion pipelines.

---

## Quick Reference

| Rule | Level | Risk | Primary Defense |
|------|-------|------|-----------------|
| Partition Function Security | `strict` | Resource exhaustion, DoS | Strategy limits, resource controls |
| PDF Processing Security | `strict` | Memory exhaustion, OCR abuse | Mode selection, OCR controls |
| Table Extraction Security | `warning` | Memory exhaustion, malformed data | Size limits, structure validation |
| HTML Processing Security | `strict` | XSS, script injection | Script removal, sanitization |
| Image Extraction Security | `warning` | Metadata leakage, decompression bombs | EXIF stripping, dimension limits |
| Element Metadata Security | `warning` | PII exposure, data leakage | PII filtering, field validation |
| Chunking Strategy Security | `warning` | Context manipulation, resource abuse | Size limits, overlap control |
| API Service Security | `strict` | Credential exposure, rate limit abuse | Authentication, rate limiting |
| Output Validation | `warning` | Injection payloads, data overflow | Element limits, content filtering |

---

## Rule: Partition Function Security

**Level**: `strict`

**When**: Using `partition()`, `partition_pdf()`, `partition_html()`, or other partition functions

**Do**:
```python
from unstructured.partition.auto import partition
from unstructured.partition.pdf import partition_pdf
import os
import resource
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class PartitionSecurityConfig:
    """Security configuration for partition operations."""
    max_file_size_mb: int = 100
    max_pages: int = 500
    max_elements: int = 10000
    timeout_seconds: int = 300
    max_memory_mb: int = 2048
    allowed_strategies: tuple = ("fast", "hi_res", "ocr_only")
    default_strategy: str = "fast"

class SecurePartitioner:
    """Secure wrapper for Unstructured partition functions."""

    def __init__(self, config: Optional[PartitionSecurityConfig] = None):
        self.config = config or PartitionSecurityConfig()

    def partition_document(
        self,
        filename: str,
        strategy: Optional[str] = None,
        **kwargs
    ) -> List:
        """Partition document with security controls."""

        # Validate file size
        file_size_mb = os.path.getsize(filename) / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            raise ValueError(
                f"File size {file_size_mb:.1f}MB exceeds limit of "
                f"{self.config.max_file_size_mb}MB"
            )

        # Validate strategy
        if strategy is None:
            strategy = self.config.default_strategy

        if strategy not in self.config.allowed_strategies:
            raise ValueError(
                f"Strategy '{strategy}' not allowed. "
                f"Allowed: {self.config.allowed_strategies}"
            )

        # Set resource limits
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(
            resource.RLIMIT_AS,
            (self.config.max_memory_mb * 1024 * 1024, hard)
        )

        try:
            # Partition with controlled parameters
            elements = partition(
                filename=filename,
                strategy=strategy,
                max_partition_length=50000,  # Limit element size
                include_page_breaks=True,
                **kwargs
            )

            # Validate output
            if len(elements) > self.config.max_elements:
                raise ValueError(
                    f"Document produced {len(elements)} elements, "
                    f"exceeds limit of {self.config.max_elements}"
                )

            return list(elements)

        finally:
            # Restore resource limits
            resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

    def partition_with_timeout(
        self,
        filename: str,
        **kwargs
    ) -> List:
        """Partition with timeout protection."""
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError(
                f"Partition exceeded {self.config.timeout_seconds}s timeout"
            )

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.config.timeout_seconds)

        try:
            return self.partition_document(filename, **kwargs)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
```

**Don't**:
```python
# VULNERABLE: No resource controls
from unstructured.partition.auto import partition

def process_document(filename):
    # No file size check - can process 10GB files
    # No strategy validation - hi_res on all docs (expensive)
    # No element limit - can return millions of elements
    # No timeout - can run forever

    elements = partition(filename)  # Uncontrolled execution
    return elements

# VULNERABLE: Using hi_res for all documents
elements = partition(filename, strategy="hi_res")  # Resource intensive
```

**Why**: Partition functions can consume excessive memory and CPU with large or malformed documents. The `hi_res` strategy uses ML models that can exhaust resources. Without limits, attackers can cause DoS by uploading crafted documents.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), OWASP A05:2021 (Security Misconfiguration)

---

## Rule: PDF Processing Security

**Level**: `strict`

**When**: Using `partition_pdf()` for PDF document processing

**Do**:
```python
from unstructured.partition.pdf import partition_pdf
from typing import List, Optional
from dataclasses import dataclass
import os

@dataclass
class PDFSecurityConfig:
    """Security configuration for PDF processing."""
    max_file_size_mb: int = 50
    max_pages: int = 200
    strategy: str = "fast"  # Use "fast" by default, "hi_res" only when needed
    ocr_languages: list = None  # Limit OCR languages
    infer_table_structure: bool = False  # Disable by default (expensive)
    extract_images_in_pdf: bool = False  # Disable by default (memory intensive)

    def __post_init__(self):
        if self.ocr_languages is None:
            self.ocr_languages = ["eng"]  # English only by default

class SecurePDFPartitioner:
    """Secure PDF partitioning with controlled OCR and processing."""

    def __init__(self, config: Optional[PDFSecurityConfig] = None):
        self.config = config or PDFSecurityConfig()

    def partition(self, filename: str, use_hi_res: bool = False) -> List:
        """Partition PDF with security controls."""

        # Validate file size
        file_size_mb = os.path.getsize(filename) / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            raise ValueError(
                f"PDF size {file_size_mb:.1f}MB exceeds {self.config.max_file_size_mb}MB limit"
            )

        # Validate page count before full processing
        page_count = self._get_page_count(filename)
        if page_count > self.config.max_pages:
            raise ValueError(
                f"PDF has {page_count} pages, exceeds {self.config.max_pages} limit"
            )

        # Select strategy based on requirements
        strategy = "hi_res" if use_hi_res else self.config.strategy

        # Partition with security controls
        elements = partition_pdf(
            filename=filename,
            strategy=strategy,
            languages=self.config.ocr_languages,
            infer_table_structure=self.config.infer_table_structure,
            extract_images_in_pdf=self.config.extract_images_in_pdf,
            max_partition_length=50000,
            include_page_breaks=True,
        )

        return list(elements)

    def _get_page_count(self, filename: str) -> int:
        """Get PDF page count without full parsing."""
        import fitz
        doc = fitz.open(filename)
        count = doc.page_count
        doc.close()
        return count

    def partition_ocr_only(self, filename: str) -> List:
        """Use OCR-only mode for scanned documents."""

        # Same validations
        file_size_mb = os.path.getsize(filename) / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            raise ValueError(f"PDF exceeds size limit")

        page_count = self._get_page_count(filename)
        if page_count > self.config.max_pages:
            raise ValueError(f"PDF exceeds page limit")

        # OCR-only is resource intensive, apply stricter limits
        if page_count > self.config.max_pages // 2:
            raise ValueError(
                f"OCR mode limited to {self.config.max_pages // 2} pages"
            )

        elements = partition_pdf(
            filename=filename,
            strategy="ocr_only",
            languages=self.config.ocr_languages,
            max_partition_length=30000,  # Stricter for OCR
        )

        return list(elements)


# Usage
config = PDFSecurityConfig(
    max_file_size_mb=25,
    max_pages=100,
    strategy="fast",
    ocr_languages=["eng", "spa"],  # Only English and Spanish
)
partitioner = SecurePDFPartitioner(config)
elements = partitioner.partition("/path/to/document.pdf")
```

**Don't**:
```python
# VULNERABLE: No OCR controls
from unstructured.partition.pdf import partition_pdf

def process_pdf(filename):
    # hi_res on everything - ML model for every page
    elements = partition_pdf(
        filename,
        strategy="hi_res",
        languages=None,  # OCR tries all languages
        infer_table_structure=True,  # ML table detection on every page
        extract_images_in_pdf=True,  # Extracts and processes all images
    )
    return elements

# VULNERABLE: No validation before expensive operations
elements = partition_pdf(untrusted_pdf, strategy="ocr_only")
```

**Why**: PDF processing with OCR and ML models (`hi_res`, `ocr_only`) consumes significant resources. Attackers can upload PDFs with thousands of pages or embedded images to exhaust memory and CPU. Limiting languages and disabling expensive features by default prevents abuse.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits), OWASP A05:2021

---

## Rule: Table Extraction Security

**Level**: `warning`

**When**: Extracting tables from documents with `infer_table_structure=True`

**Do**:
```python
from unstructured.partition.pdf import partition_pdf
from unstructured.documents.elements import Table
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class SecureTableExtractor:
    """Secure table extraction with size and structure limits."""

    def __init__(
        self,
        max_table_rows: int = 1000,
        max_table_cols: int = 100,
        max_cell_length: int = 10000,
        max_tables_per_doc: int = 50
    ):
        self.max_table_rows = max_table_rows
        self.max_table_cols = max_table_cols
        self.max_cell_length = max_cell_length
        self.max_tables_per_doc = max_tables_per_doc

    def extract_tables(self, filename: str) -> List[Dict]:
        """Extract tables with security validation."""

        elements = partition_pdf(
            filename=filename,
            strategy="hi_res",
            infer_table_structure=True,
            max_partition_length=50000,
        )

        tables = []
        table_count = 0

        for element in elements:
            if isinstance(element, Table):
                table_count += 1

                # Limit number of tables
                if table_count > self.max_tables_per_doc:
                    logger.warning(
                        f"Document has {table_count}+ tables, "
                        f"limit is {self.max_tables_per_doc}"
                    )
                    break

                # Validate and sanitize table
                validated_table = self._validate_table(element, table_count)
                if validated_table:
                    tables.append(validated_table)

        return tables

    def _validate_table(self, table_element: Table, index: int) -> Dict:
        """Validate table structure and content."""

        # Get table HTML/text
        table_text = str(table_element)

        # Check total size
        if len(table_text) > self.max_cell_length * 100:
            logger.warning(f"Table {index} exceeds size limit, truncating")
            table_text = table_text[:self.max_cell_length * 100]

        # Parse and validate structure if HTML
        if hasattr(table_element, 'metadata') and table_element.metadata:
            text_as_html = table_element.metadata.text_as_html
            if text_as_html:
                # Count rows and columns
                row_count = text_as_html.count('<tr')
                col_count = text_as_html.count('<td') // max(row_count, 1)

                if row_count > self.max_table_rows:
                    logger.warning(
                        f"Table {index} has {row_count} rows, "
                        f"limit is {self.max_table_rows}"
                    )
                    return None

                if col_count > self.max_table_cols:
                    logger.warning(
                        f"Table {index} has {col_count} cols, "
                        f"limit is {self.max_table_cols}"
                    )
                    return None

        return {
            'index': index,
            'text': table_text,
            'metadata': {
                'page_number': getattr(
                    table_element.metadata, 'page_number', None
                ) if table_element.metadata else None,
            }
        }
```

**Don't**:
```python
# VULNERABLE: No table size limits
from unstructured.partition.pdf import partition_pdf
from unstructured.documents.elements import Table

def extract_all_tables(filename):
    elements = partition_pdf(
        filename,
        strategy="hi_res",
        infer_table_structure=True,  # No limits on table processing
    )

    tables = []
    for element in elements:
        if isinstance(element, Table):
            tables.append(element.text)  # Could be gigabytes of data

    return tables  # Memory exhaustion possible
```

**Why**: Malformed documents can contain tables with thousands of rows/columns or deeply nested structures that exhaust memory during extraction. Attackers can craft documents specifically to abuse table extraction ML models.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits)

---

## Rule: HTML Processing Security

**Level**: `strict`

**When**: Using `partition_html()` to process HTML content

**Do**:
```python
from unstructured.partition.html import partition_html
from unstructured.cleaners.core import clean_extra_whitespace
import bleach
from typing import List
import re

class SecureHTMLPartitioner:
    """Secure HTML partitioning with script removal and sanitization."""

    # Allowed HTML tags (whitelist approach)
    ALLOWED_TAGS = [
        'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'table', 'tr', 'td', 'th', 'thead', 'tbody',
        'strong', 'em', 'b', 'i', 'u', 'span', 'div', 'a',
        'blockquote', 'pre', 'code',
    ]

    # Allowed attributes (minimal)
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title'],
        'td': ['colspan', 'rowspan'],
        'th': ['colspan', 'rowspan'],
    }

    def __init__(
        self,
        max_content_length: int = 10_000_000,  # 10MB
        strip_scripts: bool = True,
        strip_styles: bool = True,
        strip_iframes: bool = True,
    ):
        self.max_content_length = max_content_length
        self.strip_scripts = strip_scripts
        self.strip_styles = strip_styles
        self.strip_iframes = strip_iframes

    def partition(self, filename: str = None, text: str = None) -> List:
        """Partition HTML with security sanitization."""

        if text:
            html_content = text
        elif filename:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                html_content = f.read(self.max_content_length + 1)
        else:
            raise ValueError("Either filename or text must be provided")

        # Check content length
        if len(html_content) > self.max_content_length:
            raise ValueError(
                f"HTML content exceeds {self.max_content_length} byte limit"
            )

        # Pre-sanitize HTML before partition
        sanitized_html = self._sanitize_html(html_content)

        # Partition sanitized content
        elements = partition_html(
            text=sanitized_html,
            include_page_breaks=False,
            max_partition_length=50000,
        )

        # Post-process elements
        clean_elements = []
        for element in elements:
            # Clean whitespace
            element.apply(clean_extra_whitespace)

            # Additional text sanitization
            if hasattr(element, 'text'):
                element.text = self._sanitize_text(element.text)

            clean_elements.append(element)

        return clean_elements

    def _sanitize_html(self, html: str) -> str:
        """Remove dangerous HTML elements and attributes."""

        # Remove script tags and content
        if self.strip_scripts:
            html = re.sub(
                r'<script[^>]*>.*?</script>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            # Remove event handlers
            html = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)

        # Remove style tags
        if self.strip_styles:
            html = re.sub(
                r'<style[^>]*>.*?</style>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )

        # Remove iframes
        if self.strip_iframes:
            html = re.sub(
                r'<iframe[^>]*>.*?</iframe>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            html = re.sub(r'<iframe[^>]*/>', '', html, flags=re.IGNORECASE)

        # Use bleach for thorough sanitization
        html = bleach.clean(
            html,
            tags=self.ALLOWED_TAGS,
            attributes=self.ALLOWED_ATTRIBUTES,
            strip=True,
        )

        return html

    def _sanitize_text(self, text: str) -> str:
        """Sanitize extracted text content."""

        # Remove potential javascript: URLs
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)

        # Remove data: URLs
        text = re.sub(r'data:[^,]*,', '', text, flags=re.IGNORECASE)

        return text


# Usage
partitioner = SecureHTMLPartitioner(
    max_content_length=5_000_000,  # 5MB limit
    strip_scripts=True,
    strip_styles=True,
)
elements = partitioner.partition(filename="/path/to/page.html")
```

**Don't**:
```python
# VULNERABLE: No HTML sanitization
from unstructured.partition.html import partition_html

def process_html(filename):
    # Scripts, iframes, event handlers all pass through
    elements = partition_html(filename)

    # Extracted text may contain:
    # - XSS payloads
    # - JavaScript URLs
    # - Malicious event handlers

    return elements

# VULNERABLE: Processing untrusted HTML without sanitization
elements = partition_html(text=user_submitted_html)
```

**Why**: HTML documents can contain XSS payloads, malicious scripts, and event handlers that may be preserved in extracted text or metadata. Even after extraction, javascript: URLs and data: URLs can be dangerous if the content is rendered later.

**Refs**: CWE-79 (XSS), CWE-80 (Script in Attributes), OWASP A03:2021 (Injection)

---

## Rule: Image Extraction Security

**Level**: `warning`

**When**: Extracting images from documents using `extract_images_in_pdf=True`

**Do**:
```python
from unstructured.partition.pdf import partition_pdf
from PIL import Image
import io
import hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class ImageSecurityConfig:
    """Security configuration for image extraction."""
    max_width: int = 4096
    max_height: int = 4096
    max_megapixels: int = 16
    max_file_size_kb: int = 10240  # 10MB per image
    max_images_per_doc: int = 100
    strip_exif: bool = True
    allowed_formats: tuple = ('PNG', 'JPEG', 'GIF', 'BMP')

class SecureImageExtractor:
    """Secure image extraction with EXIF stripping and size limits."""

    def __init__(self, config: Optional[ImageSecurityConfig] = None):
        self.config = config or ImageSecurityConfig()

    def extract_images(self, filename: str) -> List[Dict]:
        """Extract images from PDF with security controls."""

        elements = partition_pdf(
            filename=filename,
            strategy="hi_res",
            extract_images_in_pdf=True,
        )

        images = []
        image_count = 0

        for element in elements:
            if hasattr(element.metadata, 'image_base64'):
                image_data = element.metadata.image_base64
                if image_data:
                    image_count += 1

                    if image_count > self.config.max_images_per_doc:
                        break

                    # Process image securely
                    secure_image = self._process_image(
                        image_data, image_count
                    )
                    if secure_image:
                        images.append(secure_image)

        return images

    def _process_image(self, base64_data: str, index: int) -> Optional[Dict]:
        """Process and sanitize extracted image."""
        import base64

        try:
            # Decode base64
            image_bytes = base64.b64decode(base64_data)

            # Check raw size
            if len(image_bytes) > self.config.max_file_size_kb * 1024:
                return None

            # Open image
            img = Image.open(io.BytesIO(image_bytes))

            # Check format
            if img.format not in self.config.allowed_formats:
                return None

            # Check dimensions
            width, height = img.size
            megapixels = (width * height) / 1_000_000

            if width > self.config.max_width or height > self.config.max_height:
                return None

            if megapixels > self.config.max_megapixels:
                return None

            # Strip EXIF metadata
            if self.config.strip_exif:
                img = self._strip_exif(img)

            # Convert to safe format
            output = io.BytesIO()
            img.save(output, format='PNG')
            clean_bytes = output.getvalue()

            return {
                'index': index,
                'data': base64.b64encode(clean_bytes).decode('utf-8'),
                'width': width,
                'height': height,
                'hash': hashlib.sha256(clean_bytes).hexdigest()[:16],
                'exif_stripped': self.config.strip_exif,
            }

        except Exception:
            return None

    def _strip_exif(self, img: Image.Image) -> Image.Image:
        """Remove EXIF metadata from image."""
        data = list(img.getdata())
        img_clean = Image.new(img.mode, img.size)
        img_clean.putdata(data)
        return img_clean


# Usage
extractor = SecureImageExtractor(ImageSecurityConfig(
    max_width=2048,
    max_height=2048,
    max_images_per_doc=50,
    strip_exif=True,
))
images = extractor.extract_images("/path/to/document.pdf")
```

**Don't**:
```python
# VULNERABLE: No image security controls
from unstructured.partition.pdf import partition_pdf

def extract_all_images(filename):
    elements = partition_pdf(
        filename,
        strategy="hi_res",
        extract_images_in_pdf=True,  # No limits
    )

    images = []
    for element in elements:
        if hasattr(element.metadata, 'image_base64'):
            # EXIF not stripped - GPS, device info exposed
            # No size validation - decompression bombs
            # No format validation - malicious images
            images.append(element.metadata.image_base64)

    return images  # Sensitive metadata leaked
```

**Why**: Extracted images contain EXIF metadata that can leak sensitive information (GPS coordinates, device serial numbers, timestamps). Large or malformed images can cause decompression bombs. EXIF stripping and dimension limits prevent these issues.

**Refs**: CWE-200 (Information Exposure), CWE-400 (Resource Exhaustion), OWASP A01:2021

---

## Rule: Element Metadata Security

**Level**: `warning`

**When**: Processing and storing element metadata from Unstructured output

**Do**:
```python
from unstructured.documents.elements import Element
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import re

@dataclass
class MetadataSecurityConfig:
    """Configuration for metadata sanitization."""
    allowed_fields: tuple = (
        'page_number', 'filename', 'file_directory', 'filetype',
        'text_as_html', 'languages', 'emphasized_text_contents',
        'coordinates', 'element_id',
    )
    max_field_length: int = 10000
    redact_pii: bool = True
    validate_coordinates: bool = True

class SecureMetadataProcessor:
    """Secure processing of element metadata."""

    PII_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'phone'),
        (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', 'ssn'),
    ]

    def __init__(self, config: Optional[MetadataSecurityConfig] = None):
        self.config = config or MetadataSecurityConfig()

    def process_elements(self, elements: List[Element]) -> List[Dict]:
        """Process elements with metadata sanitization."""

        processed = []
        for element in elements:
            secure_element = {
                'type': type(element).__name__,
                'text': self._sanitize_text(str(element)),
                'metadata': self._sanitize_metadata(element.metadata),
            }
            processed.append(secure_element)

        return processed

    def _sanitize_metadata(self, metadata: Any) -> Dict:
        """Sanitize element metadata."""

        if metadata is None:
            return {}

        sanitized = {}

        for field in self.config.allowed_fields:
            value = getattr(metadata, field, None)
            if value is not None:
                sanitized[field] = self._sanitize_value(field, value)

        # Validate coordinates if present
        if self.config.validate_coordinates and 'coordinates' in sanitized:
            coords = sanitized['coordinates']
            if coords and not self._validate_coordinates(coords):
                del sanitized['coordinates']

        return sanitized

    def _sanitize_value(self, field: str, value: Any) -> Any:
        """Sanitize individual metadata value."""

        if value is None:
            return None

        # Handle coordinates specially
        if field == 'coordinates':
            return self._sanitize_coordinates(value)

        # Convert to string for text processing
        if isinstance(value, (list, tuple)):
            return [self._sanitize_value(field, v) for v in value[:100]]

        str_value = str(value)

        # Truncate long values
        if len(str_value) > self.config.max_field_length:
            str_value = str_value[:self.config.max_field_length] + '...'

        # Redact PII
        if self.config.redact_pii:
            for pattern, pii_type in self.PII_PATTERNS:
                str_value = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', str_value)

        return str_value

    def _sanitize_coordinates(self, coords: Any) -> Optional[Dict]:
        """Sanitize coordinate data."""

        if not hasattr(coords, 'points'):
            return None

        # Validate coordinate values are reasonable
        try:
            points = coords.points
            for point in points:
                x, y = point
                if not (0 <= x <= 100000 and 0 <= y <= 100000):
                    return None
        except (TypeError, ValueError):
            return None

        return {
            'points': [(float(p[0]), float(p[1])) for p in coords.points],
            'system': getattr(coords, 'system', None),
        }

    def _validate_coordinates(self, coords: Dict) -> bool:
        """Validate coordinate structure."""
        if not isinstance(coords, dict):
            return False

        points = coords.get('points', [])
        if len(points) > 1000:  # Reasonable limit
            return False

        return True

    def _sanitize_text(self, text: str) -> str:
        """Sanitize element text content."""

        # Truncate
        if len(text) > self.config.max_field_length:
            text = text[:self.config.max_field_length] + '...'

        # Redact PII
        if self.config.redact_pii:
            for pattern, pii_type in self.PII_PATTERNS:
                text = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', text)

        return text


# Usage
from unstructured.partition.auto import partition

elements = partition("/path/to/document.pdf")
processor = SecureMetadataProcessor(MetadataSecurityConfig(
    redact_pii=True,
    validate_coordinates=True,
))
secure_elements = processor.process_elements(elements)
```

**Don't**:
```python
# VULNERABLE: No metadata sanitization
def process_elements(elements):
    results = []
    for element in elements:
        # Store all metadata without filtering
        results.append({
            'text': element.text,
            'metadata': element.metadata.__dict__,  # All fields exposed
        })
    return results  # PII, file paths, etc. all stored
```

**Why**: Element metadata can contain sensitive information including file paths, author names with email addresses, and coordinate data that could reveal document structure. PII filtering and field whitelisting prevent unintended data exposure.

**Refs**: CWE-200 (Information Exposure), CWE-359 (Privacy Violation), OWASP A01:2021

---

## Rule: Chunking Strategy Security

**Level**: `warning`

**When**: Using Unstructured's chunking functions like `chunk_by_title`

**Do**:
```python
from unstructured.chunking.title import chunk_by_title
from unstructured.chunking.basic import chunk_elements
from unstructured.documents.elements import Element
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class ChunkingSecurityConfig:
    """Security configuration for chunking operations."""
    max_characters: int = 2000
    new_after_n_chars: int = 1500
    overlap: int = 100
    max_overlap_ratio: float = 0.3  # Max overlap as ratio of chunk size
    max_chunks_per_doc: int = 5000
    combine_text_under_n_chars: int = 200

class SecureChunker:
    """Secure document chunking with controlled parameters."""

    def __init__(self, config: Optional[ChunkingSecurityConfig] = None):
        self.config = config or ChunkingSecurityConfig()

    def chunk_by_title(self, elements: List[Element]) -> List[Element]:
        """Chunk elements by title with security controls."""

        # Validate overlap ratio
        if self.config.overlap > self.config.max_characters * self.config.max_overlap_ratio:
            raise ValueError(
                f"Overlap {self.config.overlap} exceeds "
                f"{self.config.max_overlap_ratio * 100}% of max_characters"
            )

        # Perform chunking
        chunks = chunk_by_title(
            elements,
            max_characters=self.config.max_characters,
            new_after_n_chars=self.config.new_after_n_chars,
            overlap=self.config.overlap,
            combine_text_under_n_chars=self.config.combine_text_under_n_chars,
        )

        chunk_list = list(chunks)

        # Validate output
        if len(chunk_list) > self.config.max_chunks_per_doc:
            raise ValueError(
                f"Document produced {len(chunk_list)} chunks, "
                f"exceeds limit of {self.config.max_chunks_per_doc}"
            )

        # Validate individual chunks
        validated_chunks = []
        for i, chunk in enumerate(chunk_list):
            chunk_text = str(chunk)

            # Enforce max_characters strictly
            if len(chunk_text) > self.config.max_characters * 1.5:
                # Chunk is too large, possibly malformed
                chunk.text = chunk_text[:self.config.max_characters]

            validated_chunks.append(chunk)

        return validated_chunks

    def chunk_basic(self, elements: List[Element]) -> List[Element]:
        """Basic chunking with security controls."""

        chunks = chunk_elements(
            elements,
            max_characters=self.config.max_characters,
            overlap=self.config.overlap,
        )

        chunk_list = list(chunks)

        if len(chunk_list) > self.config.max_chunks_per_doc:
            raise ValueError(f"Too many chunks: {len(chunk_list)}")

        return chunk_list


# Usage
from unstructured.partition.auto import partition

elements = partition("/path/to/document.pdf")

chunker = SecureChunker(ChunkingSecurityConfig(
    max_characters=1500,
    new_after_n_chars=1200,
    overlap=100,
    max_chunks_per_doc=1000,
))

chunks = chunker.chunk_by_title(elements)
```

**Don't**:
```python
# VULNERABLE: No chunking controls
from unstructured.chunking.title import chunk_by_title

def chunk_document(elements):
    # Large overlap can duplicate content excessively
    # No limit on output chunks
    chunks = chunk_by_title(
        elements,
        max_characters=10000,  # Very large chunks
        overlap=5000,  # 50% overlap - massive duplication
    )

    return list(chunks)  # Could be millions of chunks
```

**Why**: Excessive overlap can cause content duplication that inflates storage and retrieval costs. Very large chunks reduce retrieval precision. Unbounded chunk counts can exhaust memory. Controlling these parameters prevents resource abuse and improves RAG quality.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Allocation Without Limits)

---

## Rule: API Service Security

**Level**: `strict`

**When**: Using Unstructured's hosted API service instead of local processing

**Do**:
```python
from unstructured_client import UnstructuredClient
from unstructured_client.models import shared
from unstructured_client.models.errors import SDKError
import os
from typing import List, Optional
from dataclasses import dataclass
import time
import logging

logger = logging.getLogger(__name__)

@dataclass
class APISecurityConfig:
    """Security configuration for Unstructured API."""
    max_file_size_mb: int = 25  # API limit
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_delay_seconds: int = 5

class SecureUnstructuredAPI:
    """Secure wrapper for Unstructured API with rate limiting."""

    def __init__(self, config: Optional[APISecurityConfig] = None):
        self.config = config or APISecurityConfig()

        # Get API key from environment (never hardcode)
        api_key = os.environ.get('UNSTRUCTURED_API_KEY')
        if not api_key:
            raise ValueError(
                "UNSTRUCTURED_API_KEY environment variable not set"
            )

        # Get API URL (default to hosted service)
        api_url = os.environ.get(
            'UNSTRUCTURED_API_URL',
            'https://api.unstructured.io/general/v0/general'
        )

        self.client = UnstructuredClient(
            api_key_auth=api_key,
            server_url=api_url,
        )

        # Rate limiting state
        self._request_times: List[float] = []

    def partition(
        self,
        filename: str,
        strategy: str = "auto",
        **kwargs
    ) -> List:
        """Partition document via API with security controls."""

        # Validate file size
        file_size_mb = os.path.getsize(filename) / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            raise ValueError(
                f"File {file_size_mb:.1f}MB exceeds "
                f"{self.config.max_file_size_mb}MB API limit"
            )

        # Check rate limit
        self._check_rate_limit()

        # Read file
        with open(filename, 'rb') as f:
            file_content = f.read()

        # Create request
        req = shared.PartitionParameters(
            files=shared.Files(
                content=file_content,
                file_name=os.path.basename(filename),
            ),
            strategy=strategy,
            **kwargs
        )

        # Make request with retry
        for attempt in range(self.config.max_retries):
            try:
                self._record_request()

                res = self.client.general.partition(req)

                if res.elements:
                    return res.elements
                else:
                    raise ValueError("API returned no elements")

            except SDKError as e:
                logger.warning(
                    f"API error (attempt {attempt + 1}): {e}"
                )

                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay_seconds)
                else:
                    raise

        raise RuntimeError("All retry attempts failed")

    def _check_rate_limit(self):
        """Check and enforce rate limiting."""
        now = time.time()

        # Remove old requests outside window
        window_start = now - self.config.rate_limit_window_seconds
        self._request_times = [
            t for t in self._request_times if t > window_start
        ]

        # Check limit
        if len(self._request_times) >= self.config.rate_limit_requests:
            sleep_time = self._request_times[0] - window_start
            if sleep_time > 0:
                logger.info(f"Rate limit reached, sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)

    def _record_request(self):
        """Record request time for rate limiting."""
        self._request_times.append(time.time())


# Usage
# Ensure API key is set: export UNSTRUCTURED_API_KEY=your_key_here

api = SecureUnstructuredAPI(APISecurityConfig(
    max_file_size_mb=20,
    rate_limit_requests=50,
    rate_limit_window_seconds=60,
))

elements = api.partition(
    "/path/to/document.pdf",
    strategy="hi_res",
)
```

**Don't**:
```python
# VULNERABLE: Hardcoded credentials
from unstructured_client import UnstructuredClient

client = UnstructuredClient(
    api_key_auth="sk-abc123...",  # NEVER hardcode API keys
    server_url="https://api.unstructured.io/general/v0/general",
)

# VULNERABLE: No rate limiting
def process_many_documents(files):
    results = []
    for f in files:
        # No rate limiting - will hit API limits
        # No retry logic - fails on transient errors
        # No file size validation - API will reject large files
        res = client.general.partition(...)
        results.append(res)
    return results

# VULNERABLE: No error handling
elements = client.general.partition(req)  # Unhandled errors
```

**Why**: API keys should never be hardcoded in source code where they can be exposed in version control. Rate limiting prevents account suspension and excessive costs. Retry logic handles transient API errors gracefully.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-307 (Improper Authentication), OWASP A07:2021 (Identification and Authentication Failures)

---

## Rule: Output Validation

**Level**: `warning`

**When**: Processing and storing Unstructured output before embedding or retrieval

**Do**:
```python
from unstructured.documents.elements import (
    Element, NarrativeText, Title, ListItem, Table
)
from typing import List, Dict, Optional
from dataclasses import dataclass
import re
import logging

logger = logging.getLogger(__name__)

@dataclass
class OutputValidationConfig:
    """Configuration for output validation."""
    max_elements: int = 10000
    max_element_length: int = 50000
    max_total_length: int = 10_000_000  # 10MB
    filter_empty: bool = True
    filter_short: int = 10  # Minimum chars
    detect_injection: bool = True

class SecureOutputValidator:
    """Validate and filter Unstructured output."""

    INJECTION_PATTERNS = [
        r'ignore\s*(?:previous|above|all)\s*instructions',
        r'disregard\s*(?:instructions|context)',
        r'system\s*(?:prompt|message)\s*:',
        r'<\|(?:im_start|im_end|endoftext)\|>',
        r'```\s*(?:system|assistant|user)',
    ]

    def __init__(self, config: Optional[OutputValidationConfig] = None):
        self.config = config or OutputValidationConfig()

    def validate(self, elements: List[Element]) -> List[Dict]:
        """Validate and filter elements."""

        # Check element count
        if len(elements) > self.config.max_elements:
            logger.warning(
                f"Element count {len(elements)} exceeds limit "
                f"{self.config.max_elements}, truncating"
            )
            elements = elements[:self.config.max_elements]

        validated = []
        total_length = 0
        injection_warnings = []

        for i, element in enumerate(elements):
            element_text = str(element)

            # Skip empty elements
            if self.config.filter_empty and not element_text.strip():
                continue

            # Skip very short elements
            if len(element_text) < self.config.filter_short:
                continue

            # Check element length
            if len(element_text) > self.config.max_element_length:
                logger.warning(f"Element {i} exceeds length limit, truncating")
                element_text = element_text[:self.config.max_element_length]

            # Check total length
            total_length += len(element_text)
            if total_length > self.config.max_total_length:
                logger.warning("Total output length exceeded, stopping")
                break

            # Check for injection patterns
            if self.config.detect_injection:
                injection = self._detect_injection(element_text)
                if injection:
                    injection_warnings.append({
                        'element_index': i,
                        'pattern': injection,
                    })

            # Create validated output
            validated.append({
                'index': i,
                'type': type(element).__name__,
                'text': element_text,
                'metadata': self._extract_safe_metadata(element),
            })

        # Log injection warnings
        if injection_warnings:
            logger.warning(
                f"Detected {len(injection_warnings)} potential "
                f"injection patterns in output"
            )

        return validated

    def _detect_injection(self, text: str) -> Optional[str]:
        """Detect potential prompt injection patterns."""
        text_lower = text.lower()

        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return pattern

        return None

    def _extract_safe_metadata(self, element: Element) -> Dict:
        """Extract safe metadata fields."""
        metadata = {}

        if element.metadata:
            # Only include safe fields
            safe_fields = [
                'page_number', 'element_id', 'languages'
            ]

            for field in safe_fields:
                value = getattr(element.metadata, field, None)
                if value is not None:
                    metadata[field] = value

        return metadata

    def get_statistics(self, validated: List[Dict]) -> Dict:
        """Get output statistics for monitoring."""

        type_counts = {}
        for item in validated:
            item_type = item['type']
            type_counts[item_type] = type_counts.get(item_type, 0) + 1

        total_chars = sum(len(item['text']) for item in validated)

        return {
            'element_count': len(validated),
            'total_characters': total_chars,
            'type_distribution': type_counts,
            'avg_element_length': total_chars / len(validated) if validated else 0,
        }


# Usage
from unstructured.partition.auto import partition

elements = partition("/path/to/document.pdf")

validator = SecureOutputValidator(OutputValidationConfig(
    max_elements=5000,
    max_element_length=30000,
    detect_injection=True,
))

validated_output = validator.validate(elements)
stats = validator.get_statistics(validated_output)

logger.info(f"Processed {stats['element_count']} elements, "
            f"{stats['total_characters']} total chars")
```

**Don't**:
```python
# VULNERABLE: No output validation
from unstructured.partition.auto import partition

def process_document(filename):
    elements = partition(filename)

    # Store all elements without validation
    output = []
    for element in elements:
        output.append({
            'text': str(element),  # No length limit
            'metadata': element.metadata.__dict__,  # All metadata
        })

    return output  # Unbounded output, injection payloads pass through
```

**Why**: Unstructured output can contain excessive elements, very long text that impacts embedding costs, and potential injection payloads embedded in documents. Validation ensures output quality and detects suspicious content before it enters the RAG pipeline.

**Refs**: CWE-400 (Resource Exhaustion), CWE-74 (Injection), OWASP A03:2021 (Injection)

---

## Implementation Example: Complete Secure Pipeline

```python
from unstructured.partition.auto import partition
from typing import Dict, List
import logging
import os

logger = logging.getLogger(__name__)

class SecureUnstructuredPipeline:
    """Complete secure document processing pipeline using Unstructured."""

    def __init__(self):
        self.partitioner = SecurePartitioner()
        self.pdf_partitioner = SecurePDFPartitioner()
        self.html_partitioner = SecureHTMLPartitioner()
        self.image_extractor = SecureImageExtractor()
        self.metadata_processor = SecureMetadataProcessor()
        self.chunker = SecureChunker()
        self.validator = SecureOutputValidator()

    def process(self, filename: str) -> Dict:
        """Process document through complete security pipeline."""

        logger.info(f"Processing: {filename}")

        # Determine file type and use appropriate partitioner
        ext = os.path.splitext(filename)[1].lower()

        if ext == '.pdf':
            elements = self.pdf_partitioner.partition(filename)
        elif ext in ['.html', '.htm']:
            elements = self.html_partitioner.partition(filename=filename)
        else:
            elements = self.partitioner.partition_with_timeout(filename)

        # Validate output
        validated = self.validator.validate(elements)

        # Process metadata
        secure_elements = self.metadata_processor.process_elements(elements)

        # Chunk for embedding
        chunks = self.chunker.chunk_by_title(elements)
        validated_chunks = self.validator.validate(chunks)

        # Get statistics
        stats = self.validator.get_statistics(validated_chunks)

        return {
            'filename': filename,
            'elements': secure_elements,
            'chunks': validated_chunks,
            'statistics': stats,
        }


# Usage
pipeline = SecureUnstructuredPipeline()
result = pipeline.process("/path/to/document.pdf")

print(f"Processed {result['statistics']['element_count']} elements")
print(f"Created {len(result['chunks'])} chunks")
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-15 | Initial release with 9 core rules |

---

## References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-798: Use of Hard-coded Credentials
- OWASP A01:2021 - Broken Access Control
- OWASP A03:2021 - Injection
- OWASP A05:2021 - Security Misconfiguration
- OWASP A07:2021 - Identification and Authentication Failures
