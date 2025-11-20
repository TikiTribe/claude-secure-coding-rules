# Local/Open-Source Embeddings Security Rules

Security patterns for sentence-transformers, BGE, E5, and other locally-hosted embedding models.

## Quick Reference

| Rule | Level | Trigger |
|------|-------|---------|
| Model Loading Security | `strict` | Loading any local embedding model |
| Tokenizer Security | `strict` | Text tokenization before embedding |
| GPU Memory Management | `warning` | Batch inference on GPU |
| Model Cache Security | `warning` | Downloading/caching models |
| Inference Resource Limits | `warning` | Production inference pipelines |
| Model Quantization Security | `advisory` | Applying quantization for efficiency |
| Pooling Strategy Security | `warning` | Custom pooling configurations |

---

## Rule: Model Loading Security

**Level**: `strict`

**When**: Loading any local embedding model (sentence-transformers, BGE, E5, HuggingFace models)

**Do**: Disable remote code execution, use safetensors format, validate model sources

```python
from sentence_transformers import SentenceTransformer
from transformers import AutoModel, AutoTokenizer
from huggingface_hub import hf_hub_download
import hashlib
import os

class SecureModelLoader:
    # Trusted model sources and their expected checksums
    TRUSTED_MODELS = {
        "BAAI/bge-base-en-v1.5": {
            "source": "huggingface",
            "checksum": None,  # Set to expected SHA256 for production
        },
        "intfloat/e5-base-v2": {
            "source": "huggingface",
            "checksum": None,
        },
        "sentence-transformers/all-MiniLM-L6-v2": {
            "source": "huggingface",
            "checksum": None,
        },
    }

    def __init__(self, cache_dir: str = "./secure_model_cache"):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, mode=0o700, exist_ok=True)

    def load_sentence_transformer(self, model_name: str) -> SentenceTransformer:
        """Load sentence-transformers model with security controls."""
        self._validate_model_source(model_name)

        model = SentenceTransformer(
            model_name,
            cache_folder=self.cache_dir,
            trust_remote_code=False,  # CRITICAL: Prevent arbitrary code execution
            use_auth_token=os.environ.get("HF_TOKEN"),  # Use env var, not hardcoded
        )

        return model

    def load_hf_model(self, model_name: str):
        """Load HuggingFace model with security controls."""
        self._validate_model_source(model_name)

        # Load tokenizer and model with security settings
        tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            cache_dir=self.cache_dir,
            trust_remote_code=False,  # CRITICAL: Prevent arbitrary code execution
            use_fast=True,
        )

        model = AutoModel.from_pretrained(
            model_name,
            cache_dir=self.cache_dir,
            trust_remote_code=False,  # CRITICAL: Prevent arbitrary code execution
            use_safetensors=True,  # Prefer safetensors over pickle
        )

        return tokenizer, model

    def load_bge_model(self, model_name: str = "BAAI/bge-base-en-v1.5"):
        """Load BGE model with secure defaults."""
        return self.load_hf_model(model_name)

    def load_e5_model(self, model_name: str = "intfloat/e5-base-v2"):
        """Load E5 model with secure defaults."""
        return self.load_hf_model(model_name)

    def _validate_model_source(self, model_name: str) -> None:
        """Validate model is from trusted source."""
        if model_name not in self.TRUSTED_MODELS:
            # For unknown models, require explicit approval
            if not os.environ.get("ALLOW_UNTRUSTED_MODELS"):
                raise ValueError(
                    f"Model '{model_name}' not in trusted list. "
                    "Set ALLOW_UNTRUSTED_MODELS=1 to override."
                )

    def verify_model_integrity(self, model_path: str, expected_hash: str) -> bool:
        """Verify model file integrity using SHA256."""
        sha256 = hashlib.sha256()
        with open(model_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest() == expected_hash


# Usage
loader = SecureModelLoader()
model = loader.load_sentence_transformer("sentence-transformers/all-MiniLM-L6-v2")

# BGE with secure loading
tokenizer, bge_model = loader.load_bge_model("BAAI/bge-base-en-v1.5")

# E5 with secure loading
tokenizer, e5_model = loader.load_e5_model("intfloat/e5-base-v2")
```

**Don't**: Enable remote code execution or load models from untrusted sources

```python
# VULNERABLE: trust_remote_code enables arbitrary code execution
model = SentenceTransformer("malicious/model", trust_remote_code=True)

# VULNERABLE: Loading from unknown source without validation
model = AutoModel.from_pretrained("random-user/untrusted-model")

# VULNERABLE: Using pickle format (can execute arbitrary code on load)
model = AutoModel.from_pretrained(
    "model-name",
    use_safetensors=False  # Falls back to potentially unsafe pickle
)

# VULNERABLE: Hardcoded credentials
model = SentenceTransformer("private/model", use_auth_token="hf_abc123...")

# VULNERABLE: No source validation
def load_any_model(user_provided_name):
    return SentenceTransformer(user_provided_name)  # User controls model source
```

**Why**: Models with `trust_remote_code=True` can execute arbitrary Python during loading, enabling remote code execution attacks. Pickle-based model formats can contain malicious payloads that execute on deserialization. Loading from untrusted sources exposes systems to poisoned models with backdoors or malicious behavior.

**Refs**: CWE-502 (Deserialization of Untrusted Data), OWASP LLM05 (Supply Chain Vulnerabilities), MITRE ATLAS AML.T0010 (ML Supply Chain Compromise)

---

## Rule: Tokenizer Security

**Level**: `strict`

**When**: Tokenizing text for embedding generation

**Do**: Enforce token limits, handle special tokens safely, validate tokenizer output

```python
from transformers import AutoTokenizer
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)

class SecureTokenizer:
    def __init__(
        self,
        tokenizer,
        max_length: int = 512,
        truncation: bool = True,
        strict_limits: bool = True
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.truncation = truncation
        self.strict_limits = strict_limits

        # Get special tokens to monitor
        self.special_tokens = set(tokenizer.all_special_tokens)

    def tokenize(self, texts: List[str]) -> dict:
        """Tokenize with security controls."""
        # Pre-validation
        validated_texts = []
        for i, text in enumerate(texts):
            validated = self._validate_input(text, i)
            validated_texts.append(validated)

        # Tokenize with enforced limits
        encoded = self.tokenizer(
            validated_texts,
            padding=True,
            truncation=self.truncation,
            max_length=self.max_length,
            return_tensors="pt",
            return_attention_mask=True,
            return_length=True,
        )

        # Post-validation
        self._validate_output(encoded, validated_texts)

        return encoded

    def _validate_input(self, text: str, index: int) -> str:
        """Validate and sanitize input text."""
        if not isinstance(text, str):
            raise TypeError(f"Input {index} must be string, got {type(text)}")

        # Check for embedded special tokens that could manipulate model behavior
        for special in self.special_tokens:
            if special in text and special not in ["", " "]:
                logger.warning(
                    f"Special token '{special}' found in input {index}, removing"
                )
                text = text.replace(special, "")

        # Check for control characters
        text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")

        # Estimate token count for resource management
        estimated_tokens = len(text.split()) * 1.3  # Rough estimate
        if estimated_tokens > self.max_length * 2:
            logger.warning(
                f"Input {index} likely exceeds max length, will be truncated"
            )

        return text

    def _validate_output(self, encoded: dict, texts: List[str]) -> None:
        """Validate tokenizer output for anomalies."""
        lengths = encoded.get("length", [])

        for i, length in enumerate(lengths):
            if self.strict_limits and length >= self.max_length:
                logger.warning(
                    f"Text {i} was truncated from ~{len(texts[i].split())} words "
                    f"to {self.max_length} tokens"
                )

            # Check for unusual token patterns
            if length < 3 and len(texts[i]) > 50:
                logger.error(
                    f"Suspicious tokenization for text {i}: "
                    f"{len(texts[i])} chars -> {length} tokens"
                )

    def get_token_count(self, text: str) -> int:
        """Get exact token count for a text."""
        return len(self.tokenizer.encode(text, add_special_tokens=True))


# Usage with sentence-transformers
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
secure_tokenizer = SecureTokenizer(
    model.tokenizer,
    max_length=256,
    strict_limits=True
)

# Usage with HuggingFace models
tokenizer = AutoTokenizer.from_pretrained(
    "BAAI/bge-base-en-v1.5",
    trust_remote_code=False
)
secure_tokenizer = SecureTokenizer(tokenizer, max_length=512)

texts = ["Document to embed", "Another document"]
encoded = secure_tokenizer.tokenize(texts)
```

**Don't**: Allow unlimited token sequences or ignore special token injection

```python
# VULNERABLE: No length limits - can cause OOM
encoded = tokenizer(text, return_tensors="pt")  # No max_length

# VULNERABLE: Truncation disabled - unpredictable behavior
encoded = tokenizer(text, truncation=False, max_length=512)

# VULNERABLE: No special token filtering
def embed(user_text):
    # User can inject "</s>" or "<|endoftext|>" to manipulate model
    return model.encode(user_text)

# VULNERABLE: No validation of tokenizer output
tokens = tokenizer.encode(text)
model(tokens)  # Could be malformed
```

**Why**: Unbounded token sequences can exhaust GPU memory causing denial of service. Special token injection can manipulate model behavior or cause unexpected outputs. Without output validation, malformed tokenization can cause inference failures or incorrect embeddings.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), OWASP LLM01 (Prompt Injection), CWE-20 (Improper Input Validation)

---

## Rule: GPU Memory Management

**Level**: `warning`

**When**: Running batch inference on GPU

**Do**: Implement batch size limits, memory monitoring, and graceful degradation

```python
import torch
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

class GPUMemoryManager:
    def __init__(
        self,
        max_memory_fraction: float = 0.8,
        initial_batch_size: int = 32,
        min_batch_size: int = 1
    ):
        self.max_memory_fraction = max_memory_fraction
        self.current_batch_size = initial_batch_size
        self.min_batch_size = min_batch_size
        self._oom_count = 0

    def get_memory_stats(self) -> dict:
        """Get current GPU memory statistics."""
        if not torch.cuda.is_available():
            return {"device": "cpu"}

        allocated = torch.cuda.memory_allocated()
        reserved = torch.cuda.memory_reserved()
        total = torch.cuda.get_device_properties(0).total_memory

        return {
            "allocated_gb": allocated / 1e9,
            "reserved_gb": reserved / 1e9,
            "total_gb": total / 1e9,
            "utilization": allocated / total,
            "available_gb": (total - allocated) / 1e9,
        }

    def check_memory_available(self, required_gb: float = 0.5) -> bool:
        """Check if sufficient GPU memory is available."""
        stats = self.get_memory_stats()
        if stats.get("device") == "cpu":
            return True
        return stats["available_gb"] >= required_gb

    def adaptive_batch_size(self) -> int:
        """Get adaptive batch size based on memory pressure."""
        stats = self.get_memory_stats()
        if stats.get("device") == "cpu":
            return self.current_batch_size

        utilization = stats["utilization"]

        if utilization > self.max_memory_fraction:
            # Reduce batch size
            self.current_batch_size = max(
                self.min_batch_size,
                self.current_batch_size // 2
            )
            logger.warning(
                f"High memory utilization ({utilization:.1%}), "
                f"reducing batch size to {self.current_batch_size}"
            )
        elif utilization < self.max_memory_fraction * 0.5 and self._oom_count == 0:
            # Can increase batch size
            self.current_batch_size = min(
                self.current_batch_size * 2,
                128  # Hard cap
            )

        return self.current_batch_size

    def clear_cache(self) -> None:
        """Clear GPU cache to free memory."""
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()


class SecureEmbeddingInference:
    def __init__(self, model, memory_manager: GPUMemoryManager):
        self.model = model
        self.memory_manager = memory_manager

    def encode(
        self,
        texts: List[str],
        batch_size: Optional[int] = None,
        show_progress: bool = False
    ) -> List[List[float]]:
        """Encode texts with memory-safe batching."""
        if batch_size is None:
            batch_size = self.memory_manager.adaptive_batch_size()

        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            try:
                # Check memory before batch
                if not self.memory_manager.check_memory_available(0.5):
                    self.memory_manager.clear_cache()
                    if not self.memory_manager.check_memory_available(0.5):
                        raise MemoryError("Insufficient GPU memory")

                # Encode batch
                with torch.no_grad():
                    embeddings = self.model.encode(
                        batch,
                        convert_to_tensor=False,
                        show_progress_bar=show_progress,
                    )

                all_embeddings.extend(embeddings.tolist() if hasattr(embeddings, 'tolist') else embeddings)

            except RuntimeError as e:
                if "out of memory" in str(e).lower():
                    self.memory_manager._oom_count += 1
                    self.memory_manager.clear_cache()

                    # Reduce batch size and retry
                    new_batch_size = max(1, batch_size // 2)
                    logger.warning(f"OOM error, retrying with batch_size={new_batch_size}")

                    if new_batch_size < self.memory_manager.min_batch_size:
                        raise MemoryError("Cannot process even minimum batch size")

                    # Recursive retry with smaller batch
                    result = self.encode(batch, batch_size=new_batch_size)
                    all_embeddings.extend(result)
                else:
                    raise

        return all_embeddings


# Usage
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
memory_manager = GPUMemoryManager(max_memory_fraction=0.75, initial_batch_size=32)
secure_inference = SecureEmbeddingInference(model, memory_manager)

# Safe batch encoding
texts = ["text1", "text2", ...many texts...]
embeddings = secure_inference.encode(texts)
```

**Don't**: Use fixed large batch sizes or ignore OOM errors

```python
# VULNERABLE: Fixed large batch causes OOM on smaller GPUs
embeddings = model.encode(texts, batch_size=256)  # Will crash on 8GB GPU

# VULNERABLE: No memory monitoring
for batch in batches:
    embeddings.append(model.encode(batch))  # Memory accumulates

# VULNERABLE: Ignoring OOM errors
try:
    result = model.encode(huge_batch)
except RuntimeError:
    pass  # Silent failure, no retry logic

# VULNERABLE: No cache clearing
while True:
    model.encode(get_next_batch())  # Memory fragments accumulate
```

**Why**: GPU out-of-memory errors crash the entire process without graceful degradation. Memory fragmentation over time reduces effective capacity. Without adaptive batching, systems fail unpredictably based on input size and available memory.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits), OWASP LLM10 (Model Denial of Service)

---

## Rule: Model Cache Security

**Level**: `warning`

**When**: Downloading and caching models from HuggingFace Hub or other sources

**Do**: Secure cache directory permissions, verify integrity, isolate cache per application

```python
import os
import stat
import hashlib
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class SecureModelCache:
    def __init__(
        self,
        cache_dir: str = "./model_cache",
        permissions: int = 0o700,  # Owner read/write/execute only
        verify_integrity: bool = True
    ):
        self.cache_dir = Path(cache_dir).resolve()
        self.permissions = permissions
        self.verify_integrity = verify_integrity
        self._setup_cache()

    def _setup_cache(self) -> None:
        """Create cache directory with secure permissions."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions
        os.chmod(self.cache_dir, self.permissions)

        # Verify permissions were applied
        actual_perms = stat.S_IMODE(os.stat(self.cache_dir).st_mode)
        if actual_perms != self.permissions:
            logger.warning(
                f"Cache permissions mismatch: expected {oct(self.permissions)}, "
                f"got {oct(actual_perms)}"
            )

    def get_cache_path(self, model_name: str) -> Path:
        """Get secure cache path for a model."""
        # Sanitize model name to prevent path traversal
        safe_name = model_name.replace("/", "--").replace("\\", "--")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "-_.")
        return self.cache_dir / safe_name

    def verify_model_files(self, model_path: Path, expected_hashes: dict) -> bool:
        """Verify integrity of cached model files."""
        if not self.verify_integrity:
            return True

        for filename, expected_hash in expected_hashes.items():
            file_path = model_path / filename
            if not file_path.exists():
                logger.error(f"Missing model file: {filename}")
                return False

            actual_hash = self._compute_hash(file_path)
            if actual_hash != expected_hash:
                logger.error(
                    f"Integrity check failed for {filename}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )
                return False

        return True

    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def cleanup_untrusted(self) -> int:
        """Remove unverified or corrupted cache entries."""
        removed = 0
        for item in self.cache_dir.iterdir():
            if item.is_dir():
                # Check for integrity markers
                marker = item / ".verified"
                if not marker.exists():
                    logger.warning(f"Removing unverified cache entry: {item}")
                    import shutil
                    shutil.rmtree(item)
                    removed += 1
        return removed


# Usage with environment variable
import os

# Set secure cache location via environment
os.environ["TRANSFORMERS_CACHE"] = "/secure/path/model_cache"
os.environ["HF_HOME"] = "/secure/path/hf_home"
os.environ["SENTENCE_TRANSFORMERS_HOME"] = "/secure/path/st_cache"

# Initialize secure cache
cache = SecureModelCache(
    cache_dir=os.environ["TRANSFORMERS_CACHE"],
    permissions=0o700,
    verify_integrity=True
)

# Load model with secure cache
from sentence_transformers import SentenceTransformer

model = SentenceTransformer(
    "sentence-transformers/all-MiniLM-L6-v2",
    cache_folder=str(cache.cache_dir)
)
```

**Don't**: Use default cache locations with open permissions

```python
# VULNERABLE: Default cache in home directory with default permissions
model = SentenceTransformer("model-name")  # Caches to ~/.cache/

# VULNERABLE: World-readable cache directory
os.makedirs("/tmp/model_cache", mode=0o777)  # Anyone can read/modify

# VULNERABLE: No integrity verification
model = AutoModel.from_pretrained("model-name")
# Could load tampered model files

# VULNERABLE: Shared cache between applications
os.environ["TRANSFORMERS_CACHE"] = "/shared/cache"  # Cross-app contamination

# VULNERABLE: Path traversal in model name
user_model = "../../../etc/passwd"  # Could escape cache directory
model = SentenceTransformer(user_model)
```

**Why**: Insecure cache permissions allow other users/processes to read model weights or inject malicious models. Without integrity verification, attackers can replace cached models with poisoned versions. Shared caches enable cross-application attacks.

**Refs**: CWE-276 (Incorrect Default Permissions), CWE-354 (Improper Validation of Integrity Check Value), CWE-22 (Path Traversal)

---

## Rule: Inference Resource Limits

**Level**: `warning`

**When**: Running production embedding inference pipelines

**Do**: Implement timeouts, max sequence length, and resource quotas

```python
import signal
import time
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
import logging

logger = logging.getLogger(__name__)

class ResourceLimitedInference:
    def __init__(
        self,
        model,
        max_sequence_length: int = 512,
        inference_timeout: float = 30.0,  # seconds
        max_batch_size: int = 64,
        max_total_tokens: int = 100000,
    ):
        self.model = model
        self.max_sequence_length = max_sequence_length
        self.inference_timeout = inference_timeout
        self.max_batch_size = max_batch_size
        self.max_total_tokens = max_total_tokens
        self._executor = ThreadPoolExecutor(max_workers=1)

    def encode(self, texts: List[str]) -> List[List[float]]:
        """Encode with resource limits and timeout."""
        # Validate batch size
        if len(texts) > self.max_batch_size:
            raise ValueError(
                f"Batch size {len(texts)} exceeds limit {self.max_batch_size}"
            )

        # Estimate and validate total tokens
        total_chars = sum(len(t) for t in texts)
        estimated_tokens = total_chars // 4  # Rough estimate
        if estimated_tokens > self.max_total_tokens:
            raise ValueError(
                f"Estimated tokens {estimated_tokens} exceeds limit {self.max_total_tokens}"
            )

        # Truncate individual texts
        truncated_texts = [
            self._truncate_text(t) for t in texts
        ]

        # Run with timeout
        future = self._executor.submit(
            self._encode_internal,
            truncated_texts
        )

        try:
            result = future.result(timeout=self.inference_timeout)
            return result
        except FuturesTimeout:
            logger.error(f"Inference timeout after {self.inference_timeout}s")
            raise TimeoutError(
                f"Embedding inference exceeded {self.inference_timeout}s timeout"
            )

    def _truncate_text(self, text: str) -> str:
        """Truncate text to approximately max_sequence_length tokens."""
        # Rough truncation by characters (4 chars ~= 1 token)
        max_chars = self.max_sequence_length * 4
        if len(text) > max_chars:
            logger.debug(f"Truncating text from {len(text)} to {max_chars} chars")
            return text[:max_chars]
        return text

    def _encode_internal(self, texts: List[str]) -> List[List[float]]:
        """Internal encoding without resource checks."""
        return self.model.encode(
            texts,
            convert_to_numpy=True,
            show_progress_bar=False,
        ).tolist()


# Usage
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

inference = ResourceLimitedInference(
    model,
    max_sequence_length=256,
    inference_timeout=10.0,
    max_batch_size=32,
    max_total_tokens=50000
)

try:
    embeddings = inference.encode(texts)
except TimeoutError as e:
    logger.error(f"Inference failed: {e}")
    # Fallback or error response
except ValueError as e:
    logger.error(f"Resource limit exceeded: {e}")
    # Reject request
```

**Don't**: Allow unbounded inference without timeouts or limits

```python
# VULNERABLE: No timeout - can hang indefinitely
embeddings = model.encode(texts)

# VULNERABLE: No sequence length limit
embeddings = model.encode(very_long_texts)  # OOM or extreme latency

# VULNERABLE: No batch size limit
embeddings = model.encode(thousands_of_texts)  # Resource exhaustion

# VULNERABLE: No total token limit
def embed_all(texts):
    return model.encode(texts)  # Could process unlimited data
```

**Why**: Without timeouts, inference can hang indefinitely on malformed inputs or under attack. Unbounded sequence lengths cause memory exhaustion or extreme latency. No batch limits enable denial of service through resource exhaustion.

**Refs**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits), OWASP LLM10 (Model Denial of Service)

---

## Rule: Model Quantization Security

**Level**: `advisory`

**When**: Applying quantization (int8, fp16, GPTQ, AWQ) for efficiency

**Do**: Validate embedding quality after quantization, test retrieval accuracy

```python
import numpy as np
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)

class QuantizationValidator:
    def __init__(
        self,
        quality_threshold: float = 0.95,  # Minimum cosine similarity
        test_samples: int = 100
    ):
        self.quality_threshold = quality_threshold
        self.test_samples = test_samples

    def validate_quantized_model(
        self,
        original_model,
        quantized_model,
        test_texts: List[str]
    ) -> dict:
        """Validate quantized model maintains embedding quality."""
        # Sample test texts
        if len(test_texts) > self.test_samples:
            import random
            test_texts = random.sample(test_texts, self.test_samples)

        # Generate embeddings from both models
        original_embeddings = original_model.encode(test_texts)
        quantized_embeddings = quantized_model.encode(test_texts)

        # Calculate similarity metrics
        similarities = []
        for orig, quant in zip(original_embeddings, quantized_embeddings):
            sim = self._cosine_similarity(orig, quant)
            similarities.append(sim)

        mean_similarity = np.mean(similarities)
        min_similarity = np.min(similarities)

        result = {
            "mean_similarity": float(mean_similarity),
            "min_similarity": float(min_similarity),
            "samples_tested": len(test_texts),
            "passed": mean_similarity >= self.quality_threshold,
            "threshold": self.quality_threshold,
        }

        if not result["passed"]:
            logger.error(
                f"Quantization quality check FAILED: "
                f"mean similarity {mean_similarity:.4f} < {self.quality_threshold}"
            )
        else:
            logger.info(
                f"Quantization quality check passed: "
                f"mean similarity {mean_similarity:.4f}"
            )

        return result

    def validate_retrieval_accuracy(
        self,
        original_model,
        quantized_model,
        queries: List[str],
        documents: List[str],
        expected_matches: List[int]  # Index of expected top match
    ) -> dict:
        """Validate retrieval accuracy is maintained."""
        original_correct = 0
        quantized_correct = 0

        # Encode documents
        orig_doc_embs = original_model.encode(documents)
        quant_doc_embs = quantized_model.encode(documents)

        for query, expected in zip(queries, expected_matches):
            # Original model retrieval
            orig_query_emb = original_model.encode([query])[0]
            orig_scores = [
                self._cosine_similarity(orig_query_emb, doc_emb)
                for doc_emb in orig_doc_embs
            ]
            if np.argmax(orig_scores) == expected:
                original_correct += 1

            # Quantized model retrieval
            quant_query_emb = quantized_model.encode([query])[0]
            quant_scores = [
                self._cosine_similarity(quant_query_emb, doc_emb)
                for doc_emb in quant_doc_embs
            ]
            if np.argmax(quant_scores) == expected:
                quantized_correct += 1

        return {
            "original_accuracy": original_correct / len(queries),
            "quantized_accuracy": quantized_correct / len(queries),
            "accuracy_drop": (original_correct - quantized_correct) / len(queries),
        }

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


# Usage
from sentence_transformers import SentenceTransformer

# Load original model
original = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

# Load quantized version (example with torch int8)
import torch

quantized = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
quantized = torch.quantization.quantize_dynamic(
    quantized, {torch.nn.Linear}, dtype=torch.qint8
)

# Validate quality
validator = QuantizationValidator(quality_threshold=0.98)

test_texts = [
    "Machine learning models",
    "Natural language processing",
    # ... more diverse test samples
]

result = validator.validate_quantized_model(original, quantized, test_texts)

if not result["passed"]:
    logger.error("Do not use quantized model - quality degraded")
```

**Don't**: Deploy quantized models without quality validation

```python
# VULNERABLE: No quality validation after quantization
quantized_model = quantize(original_model)
deploy(quantized_model)  # May have severely degraded embeddings

# VULNERABLE: Assuming quantization is lossless
model = load_int8_model()  # Precision loss not measured

# VULNERABLE: No retrieval accuracy testing
quantized = apply_gptq(model)
# Embeddings may be similar but retrieval ranking degraded
```

**Why**: Quantization can degrade embedding quality in ways that severely impact retrieval accuracy. Small changes in embedding values can cause large changes in similarity rankings. Without validation, degraded models can silently reduce RAG system effectiveness.

**Refs**: NIST AI RMF (Validate), ISO/IEC 23894 (AI System Verification), MITRE ATLAS AML.T0018 (Degrade Model Performance)

---

## Rule: Pooling Strategy Security

**Level**: `warning`

**When**: Using custom pooling strategies (mean, CLS, max) for embeddings

**Do**: Validate pooling strategy matches model training, verify embedding quality

```python
import torch
from transformers import AutoModel, AutoTokenizer
from typing import List, Literal
import logging

logger = logging.getLogger(__name__)

class SecurePoolingEmbedder:
    # Known correct pooling strategies per model family
    MODEL_POOLING_STRATEGIES = {
        "bge": "cls",          # BGE uses [CLS] token
        "e5": "mean",          # E5 uses mean pooling
        "gte": "mean",         # GTE uses mean pooling
        "all-MiniLM": "mean",  # sentence-transformers uses mean
        "all-mpnet": "mean",   # sentence-transformers uses mean
        "instructor": "mean",  # Instructor uses mean
    }

    def __init__(
        self,
        model_name: str,
        pooling_strategy: Literal["mean", "cls", "max"] = None,
        validate_strategy: bool = True
    ):
        self.model_name = model_name
        self.validate_strategy = validate_strategy

        # Load model and tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            trust_remote_code=False
        )
        self.model = AutoModel.from_pretrained(
            model_name,
            trust_remote_code=False
        )
        self.model.eval()

        # Determine pooling strategy
        if pooling_strategy:
            self.pooling = pooling_strategy
        else:
            self.pooling = self._detect_pooling_strategy()

        if validate_strategy:
            self._validate_pooling()

    def _detect_pooling_strategy(self) -> str:
        """Detect correct pooling strategy for model."""
        model_lower = self.model_name.lower()

        for model_family, strategy in self.MODEL_POOLING_STRATEGIES.items():
            if model_family.lower() in model_lower:
                logger.info(f"Detected pooling strategy '{strategy}' for {self.model_name}")
                return strategy

        # Default to mean pooling with warning
        logger.warning(
            f"Unknown model family for {self.model_name}, defaulting to mean pooling"
        )
        return "mean"

    def _validate_pooling(self) -> None:
        """Validate pooling strategy is correct for model."""
        model_lower = self.model_name.lower()

        # Check for known misconfigurations
        if "bge" in model_lower and self.pooling != "cls":
            logger.error(
                f"BGE models require CLS pooling, got '{self.pooling}'. "
                "Embeddings will be incorrect."
            )

        if "e5" in model_lower and self.pooling != "mean":
            logger.error(
                f"E5 models require mean pooling, got '{self.pooling}'. "
                "Embeddings will be incorrect."
            )

    def encode(self, texts: List[str], normalize: bool = True) -> List[List[float]]:
        """Encode texts with correct pooling strategy."""
        # Handle E5 instruction prefix
        if "e5" in self.model_name.lower():
            texts = [f"query: {t}" if not t.startswith(("query:", "passage:")) else t
                    for t in texts]

        # Handle BGE instruction prefix
        if "bge" in self.model_name.lower() and "instruction" in self.model_name.lower():
            # BGE instruction models may need prefix
            pass  # Follow model-specific documentation

        # Tokenize
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )

        # Get embeddings
        with torch.no_grad():
            outputs = self.model(**encoded)

        # Apply pooling
        if self.pooling == "cls":
            embeddings = outputs.last_hidden_state[:, 0, :]  # [CLS] token
        elif self.pooling == "mean":
            # Mean pooling with attention mask
            attention_mask = encoded["attention_mask"]
            embeddings = self._mean_pooling(outputs.last_hidden_state, attention_mask)
        elif self.pooling == "max":
            embeddings = outputs.last_hidden_state.max(dim=1)[0]

        # Normalize
        if normalize:
            embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)

        return embeddings.numpy().tolist()

    def _mean_pooling(self, token_embeddings: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Mean pooling with attention mask."""
        input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(
            input_mask_expanded.sum(1), min=1e-9
        )


# Usage examples

# BGE with correct CLS pooling
bge_embedder = SecurePoolingEmbedder(
    "BAAI/bge-base-en-v1.5",
    pooling_strategy="cls",  # Explicitly correct
    validate_strategy=True
)

# E5 with correct mean pooling and instruction handling
e5_embedder = SecurePoolingEmbedder(
    "intfloat/e5-base-v2",
    pooling_strategy="mean",
    validate_strategy=True
)

# E5 query embedding (note: E5 requires "query:" prefix for queries)
query_texts = ["What is machine learning?"]
query_embeddings = e5_embedder.encode(query_texts)  # Adds prefix automatically

# E5 passage embedding
passage_texts = ["passage: Machine learning is a subset of AI..."]
passage_embeddings = e5_embedder.encode(passage_texts)
```

**Don't**: Use incorrect pooling strategy for the model

```python
# VULNERABLE: Wrong pooling for BGE (should be CLS)
bge_embeddings = mean_pooling(bge_outputs)  # Incorrect embeddings

# VULNERABLE: Wrong pooling for E5 (should be mean)
e5_embeddings = outputs[:, 0, :]  # CLS pooling, should be mean

# VULNERABLE: No instruction prefix for E5
e5_model.encode(["What is AI?"])  # Missing "query:" prefix

# VULNERABLE: No validation of pooling choice
class Embedder:
    def __init__(self, model, pooling):
        self.pooling = pooling  # User can specify wrong value

# VULNERABLE: Hardcoded pooling across all models
def embed(model, texts):
    return outputs[:, 0, :]  # CLS for all models - wrong for most
```

**Why**: Each embedding model is trained with a specific pooling strategy. Using the wrong strategy produces embeddings in a different vector space than intended, severely degrading retrieval quality. This is a silent failure - embeddings are generated but are semantically incorrect.

**Refs**: NIST AI RMF (Correct Implementation), ISO/IEC 23894 (AI System Configuration), MITRE ATLAS AML.T0018 (Degrade Model Performance)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release with 7 security rules for local embeddings |
