# CLAUDE.md - Neural Rerankers Security Rules

Security rules for search and reranking systems including BM25, Cohere Rerank, Jina Reranker, FlashRank, and ColBERT.

## Rule: BM25 Index Security

**Level**: `warning`

**When**: Using BM25 or other lexical search indexes with persistence

**Do**: Validate index updates and secure persistence

```python
import os
import hashlib
from rank_bm25 import BM25Okapi
import pickle
from pathlib import Path

class SecureBM25Index:
    def __init__(self, index_path: str, allowed_dir: str = "/app/indexes"):
        # Validate index path
        resolved = Path(index_path).resolve()
        if not str(resolved).startswith(allowed_dir):
            raise ValueError("Index path outside allowed directory")

        self.index_path = resolved
        self.checksum_path = resolved.with_suffix('.checksum')
        self.index = None
        self.corpus = []

    def build_index(self, documents: list[str], max_docs: int = 100000):
        # Limit corpus size
        if len(documents) > max_docs:
            raise ValueError(f"Corpus exceeds maximum size: {max_docs}")

        # Validate and tokenize
        tokenized = []
        for doc in documents:
            if not isinstance(doc, str):
                raise TypeError("Documents must be strings")
            # Limit document length
            tokens = doc.lower().split()[:10000]
            tokenized.append(tokens)

        self.corpus = documents
        self.index = BM25Okapi(tokenized)

    def save_index(self):
        """Save index with integrity checksum"""
        data = {'index': self.index, 'corpus': self.corpus}
        serialized = pickle.dumps(data)

        # Generate checksum
        checksum = hashlib.sha256(serialized).hexdigest()

        # Write atomically
        temp_path = self.index_path.with_suffix('.tmp')
        with open(temp_path, 'wb') as f:
            f.write(serialized)

        with open(self.checksum_path, 'w') as f:
            f.write(checksum)

        os.rename(temp_path, self.index_path)

    def load_index(self):
        """Load index with integrity verification"""
        with open(self.index_path, 'rb') as f:
            serialized = f.read()

        # Verify checksum
        actual_checksum = hashlib.sha256(serialized).hexdigest()
        with open(self.checksum_path, 'r') as f:
            expected_checksum = f.read().strip()

        if actual_checksum != expected_checksum:
            raise ValueError("Index integrity check failed - possible tampering")

        data = pickle.loads(serialized)
        self.index = data['index']
        self.corpus = data['corpus']
```

**Don't**: Allow unvalidated index updates or insecure persistence

```python
# UNSAFE: No validation or integrity checks
import pickle

def load_bm25_index(path):
    # No path validation - path traversal risk
    with open(path, 'rb') as f:
        # No integrity check - tampered index risk
        return pickle.load(f)

def update_index(index, new_docs):
    # No size limits - resource exhaustion
    # No type validation - injection risk
    index.extend(new_docs)
```

**Why**: BM25 indexes can be tampered with to manipulate search results. Unlimited corpus sizes lead to memory exhaustion. Insecure persistence enables index poisoning attacks.

**Refs**: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion), OWASP LLM01:2025

---

## Rule: PII Redaction Before External Rerank APIs

**Level**: `strict`

**When**: Sending queries or document snippets to any external reranking API (Cohere, Jina Cloud, etc.)

**Do**: Scrub PII from text before transmission; log a redaction summary, not the raw text

```python
import re
import logging

logger = logging.getLogger(__name__)

# Patterns cover common PII tokens; extend per your data classification policy.
_PII_PATTERNS: list[tuple[str, str]] = [
    (r'\b\d{3}-\d{2}-\d{4}\b', '<SSN>'),                         # US SSN
    (r'\b(?:\d[ -]?){13,16}\b', '<CC>'),                          # Credit card
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
     '<EMAIL>'),                                                    # E-mail
    (r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
     '<PHONE>'),                                                    # US phone
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IPv4>'),       # IPv4
]
_COMPILED = [(re.compile(p), r) for p, r in _PII_PATTERNS]


def redact_pii(text: str) -> tuple[str, int]:
    """
    Replace PII tokens with placeholders.

    Returns (redacted_text, redaction_count).
    Raises TypeError if text is not str.
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")

    count = 0
    for pattern, replacement in _COMPILED:
        text, n = pattern.subn(replacement, text)
        count += n

    return text, count


def redact_batch(texts: list[str]) -> list[str]:
    """Redact PII from a list of strings; logs aggregate redaction count."""
    results = []
    total_redactions = 0
    for t in texts:
        clean, n = redact_pii(t)
        results.append(clean)
        total_redactions += n

    if total_redactions:
        logger.warning("PII redacted before external API: count=%d", total_redactions)

    return results
```

**Don't**: Send raw user text to external APIs without scrubbing

```python
# UNSAFE: raw user query shipped to Cohere — may contain SSN, e-mail, PHI
response = cohere_client.rerank(query=user_query, documents=docs)
```

**Why**: External reranking APIs process text on third-party infrastructure. PII transmitted without redaction violates GDPR Article 25 (data minimisation), CCPA, and HIPAA where PHI is involved. Redact before the network boundary, not after.

**Refs**: CWE-200 (Exposure of Sensitive Information), OWASP LLM06:2025, GDPR Article 25

---

## Rule: Cohere Rerank API Security

**Level**: `strict`

**When**: Using Cohere Rerank API for neural reranking

**Do**: Use `cohere.ClientV2` (cohere >= 5.0), secure API keys, implement rate limiting, validate inputs, and redact PII before transmission

```python
import os
import cohere  # requires cohere>=5.0
from datetime import datetime, timedelta
from collections import defaultdict
import logging

from .pii import redact_batch  # redact_pii rule defined above

logger = logging.getLogger(__name__)

class SecureCohereReranker:
    def __init__(self):
        # Load API key from secure source
        api_key = os.environ.get('COHERE_API_KEY')
        if not api_key:
            raise ValueError("COHERE_API_KEY not configured")

        # cohere>=5.0: use ClientV2; legacy cohere.Client was removed in v5
        self.client = cohere.ClientV2(api_key)
        self.rate_limits: dict[str, list[datetime]] = defaultdict(list)
        self.max_requests_per_minute = 100
        self.max_documents = 1000
        self.max_query_length = 500

    def _check_rate_limit(self, user_id: str) -> bool:
        """Enforce per-user rate limiting"""
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)

        # Clean old entries
        self.rate_limits[user_id] = [
            ts for ts in self.rate_limits[user_id] if ts > minute_ago
        ]

        if len(self.rate_limits[user_id]) >= self.max_requests_per_minute:
            return False

        self.rate_limits[user_id].append(now)
        return True

    def rerank(
        self,
        query: str,
        documents: list[str],
        user_id: str,
        top_n: int = 10,
        model: str = "rerank-english-v3.0"
    ) -> list[dict]:
        # Rate limiting
        if not self._check_rate_limit(user_id):
            raise ValueError("Rate limit exceeded")

        # Input validation
        if not query or len(query) > self.max_query_length:
            raise ValueError(f"Query must be 1-{self.max_query_length} characters")

        if not documents or len(documents) > self.max_documents:
            raise ValueError(f"Documents must be 1-{self.max_documents}")

        # Validate model
        allowed_models = ["rerank-english-v3.0", "rerank-multilingual-v3.0"]
        if model not in allowed_models:
            raise ValueError(f"Model must be one of: {allowed_models}")

        # Redact PII before sending to third-party API
        clean_query, _ = redact_pii(query)
        clean_docs = redact_batch(documents)

        try:
            response = self.client.rerank(
                query=clean_query,
                documents=clean_docs,
                top_n=min(top_n, len(clean_docs)),
                model=model
            )

            # Log for audit — never log raw query
            logger.info(
                "Cohere rerank: user=%s, docs=%d, model=%s",
                user_id, len(documents), model
            )

            return [
                {
                    'index': result.index,
                    'relevance_score': result.relevance_score,
                    'document': documents[result.index]  # Return original (caller owns it)
                }
                for result in response.results
            ]

        except cohere.CohereAPIError as e:
            logger.error("Cohere API error: %s", e)
            raise
```

**Don't**: Use the legacy `cohere.Client`, hardcode API keys, or skip rate limiting

```python
import cohere

# UNSAFE: legacy v4 client removed in cohere>=5.0 — raises ImportError or AttributeError
client = cohere.Client("sk-live-xxxxx")  # hardcoded key + wrong class

def rerank(query, documents):
    # No PII redaction - data privacy violation
    # No rate limiting - cost explosion risk
    # No input validation - API abuse
    return client.rerank(query=query, documents=documents, top_n=100)
```

**Why**: `cohere.Client` was removed in cohere SDK v5; production code using it will break silently on upgrade. Exposed API keys lead to unauthorized usage and cost exploitation. Without rate limiting, attackers can exhaust API quotas. Unvalidated inputs increase API costs and enable prompt injection. PII sent to third-party APIs creates regulatory liability.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-770 (Resource Allocation), OWASP LLM01:2025, OWASP LLM06:2025

---

## Rule: Jina Reranker Security

**Level**: `warning`

**When**: Using Jina Reranker for local neural reranking

**Do**: Load with `use_safetensors=True`, enforce resource limits, and apply an inference timeout to prevent tail-latency DoS

```python
import os
import threading
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class SecureJinaReranker:
    def __init__(
        self,
        model_name: str = "jinaai/jina-reranker-v1-base-en",
        allowed_model_dir: str = "/app/models",
        max_length: int = 512,
        max_batch_size: int = 32,
        inference_timeout_s: float = 30.0
    ):
        self.max_length = max_length
        self.max_batch_size = max_batch_size
        # Bound inference wall-time; prevents a crafted large batch from holding
        # the server thread indefinitely (DoS via tail latency).
        self.inference_timeout_s = inference_timeout_s

        # Validate model source
        if model_name.startswith('/'):
            # Local path — validate confinement
            resolved = Path(model_name).resolve()
            if not str(resolved).startswith(allowed_model_dir):
                raise ValueError("Model path outside allowed directory")
            model_path = str(resolved)
        else:
            # HuggingFace model — validate against allowlist
            allowed_models = [
                "jinaai/jina-reranker-v1-base-en",
                "jinaai/jina-reranker-v1-turbo-en",
                "jinaai/jina-reranker-v2-base-multilingual"
            ]
            if model_name not in allowed_models:
                raise ValueError(f"Model not in allowed list: {allowed_models}")
            model_path = model_name

        # Set memory limits before loading weights
        if torch.cuda.is_available():
            torch.cuda.set_per_process_memory_fraction(0.5)

        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        # use_safetensors=True refuses to load legacy pickle-based .bin weights,
        # eliminating the arbitrary-code-execution risk of torch.load().
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_path,
            use_safetensors=True
        )
        self.model.eval()

    def rerank(
        self,
        query: str,
        documents: list[str],
        top_n: int = 10
    ) -> list[dict]:
        if not documents:
            return []

        if len(query) > 1000:
            raise ValueError("Query exceeds maximum length")

        if len(documents) > 1000:
            raise ValueError("Too many documents")

        # Process in batches; each batch is individually time-bounded.
        scores: list[float] = []
        for i in range(0, len(documents), self.max_batch_size):
            batch = documents[i:i + self.max_batch_size]
            batch_scores = self._score_batch_with_timeout(query, batch)
            scores.extend(batch_scores)

        results = sorted(
            enumerate(scores),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]

        return [
            {
                'index': idx,
                'relevance_score': score,
                'document': documents[idx]
            }
            for idx, score in results
        ]

    def _score_batch_with_timeout(
        self, query: str, documents: list[str]
    ) -> list[float]:
        """Run _score_batch on a background thread; raise if it exceeds the timeout."""
        result: list[float] = []
        exc: list[BaseException] = []

        def target():
            try:
                result.extend(self._score_batch(query, documents))
            except Exception as e:
                exc.append(e)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(timeout=self.inference_timeout_s)

        if t.is_alive():
            # Thread is still running — treat as DoS attempt.
            logger.error(
                "Jina inference timed out after %.1fs for batch size %d",
                self.inference_timeout_s, len(documents)
            )
            raise TimeoutError(
                f"Inference exceeded {self.inference_timeout_s}s timeout"
            )

        if exc:
            raise exc[0]

        return result

    def _score_batch(self, query: str, documents: list[str]) -> list[float]:
        pairs = [[query, doc] for doc in documents]

        with torch.no_grad():
            inputs = self.tokenizer(
                pairs,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors='pt'
            )
            outputs = self.model(**inputs)
            scores = outputs.logits.squeeze(-1).tolist()

        return scores if isinstance(scores, list) else [scores]
```

**Don't**: Load models without safetensors or skip timeout protection

```python
from transformers import AutoModelForSequenceClassification

# UNSAFE: loads legacy .bin weights via torch.load — arbitrary code execution risk
model = AutoModelForSequenceClassification.from_pretrained(model_path)

# UNSAFE: no timeout — one oversized batch can block the server indefinitely
def rerank(model, query, documents):
    pairs = [[query, doc] for doc in documents]
    return model(**tokenizer(pairs))
```

**Why**: Pickle-based `.bin` weight files execute arbitrary Python on `torch.load`. `use_safetensors=True` restricts loading to the safe tensor-only format. Without an inference timeout, a crafted large batch keeps a worker thread alive indefinitely, enabling DoS through tail-latency exhaustion.

**Refs**: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion), MITRE ATLAS AML.T0043

---

## Rule: FlashRank Security

**Level**: `warning`

**When**: Using FlashRank for CPU-optimized reranking

**Do**: Configure CPU optimization securely, enforce batch limits, and bound inference time

```python
import os
import threading
import logging
from flashrank import Ranker, RerankRequest
from pathlib import Path

logger = logging.getLogger(__name__)

class SecureFlashRanker:
    def __init__(
        self,
        model_name: str = "ms-marco-MiniLM-L-12-v2",
        cache_dir: str = "/app/models/flashrank",
        max_batch_size: int = 100,
        max_length: int = 512,
        inference_timeout_s: float = 20.0
    ):
        self.max_batch_size = max_batch_size
        self.max_length = max_length
        # Bound CPU inference wall-time; prevents slow-batch DoS.
        self.inference_timeout_s = inference_timeout_s

        # Validate cache directory
        cache_path = Path(cache_dir).resolve()
        allowed_base = Path("/app/models").resolve()
        if not str(cache_path).startswith(str(allowed_base)):
            raise ValueError("Cache directory outside allowed path")

        # Validate model name
        allowed_models = [
            "ms-marco-MiniLM-L-12-v2",
            "ms-marco-TinyBERT-L-2-v2",
            "rank-T5-flan"
        ]
        if model_name not in allowed_models:
            raise ValueError(f"Model must be one of: {allowed_models}")

        # Limit CPU threads
        max_threads = min(os.cpu_count() or 4, 8)
        os.environ['OMP_NUM_THREADS'] = str(max_threads)

        self.ranker = Ranker(
            model_name=model_name,
            cache_dir=str(cache_path),
            max_length=max_length
        )

    def rerank(
        self,
        query: str,
        documents: list[dict],
        top_n: int = 10
    ) -> list[dict]:
        """
        Rerank documents with FlashRank.

        Args:
            query: Search query
            documents: List of dicts with 'id' and 'text' keys
            top_n: Number of results to return
        """
        if not documents:
            return []

        if len(query) > 1000:
            raise ValueError("Query exceeds maximum length")

        if len(documents) > self.max_batch_size:
            raise ValueError(f"Batch size exceeds limit: {self.max_batch_size}")

        for doc in documents:
            if 'id' not in doc or 'text' not in doc:
                raise ValueError("Documents must have 'id' and 'text' keys")
            if len(doc['text']) > 10000:
                raise ValueError("Document text exceeds maximum length")

        request = RerankRequest(query=query, passages=documents)
        return self._rerank_with_timeout(request, top_n)

    def _rerank_with_timeout(
        self, request: RerankRequest, top_n: int
    ) -> list[dict]:
        """Run ranker.rerank on a background thread with wall-time bound."""
        result: list[dict] = []
        exc: list[BaseException] = []

        def target():
            try:
                result.extend(self.ranker.rerank(request))
            except Exception as e:
                exc.append(e)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(timeout=self.inference_timeout_s)

        if t.is_alive():
            logger.error(
                "FlashRank inference timed out after %.1fs", self.inference_timeout_s
            )
            raise TimeoutError(
                f"Inference exceeded {self.inference_timeout_s}s timeout"
            )

        if exc:
            raise exc[0]

        return [
            {'id': r['id'], 'text': r['text'], 'score': r['score']}
            for r in result[:top_n]
        ]
```

**Don't**: Allow unlimited CPU usage, unvalidated inputs, or unbounded inference time

```python
from flashrank import Ranker

# UNSAFE: No resource limits and no timeout — CPU exhaustion DoS
ranker = Ranker()

def rerank(query, documents):
    return ranker.rerank(RerankRequest(query=query, passages=documents))
```

**Why**: FlashRank is CPU-intensive; unlimited batches cause resource exhaustion. Unvalidated document formats cause crashes. Without an inference timeout a crafted slow batch can exhaust worker threads.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Resource Allocation)

---

## Rule: ColBERT Security

**Level**: `warning`

**When**: Using ColBERT for token-level reranking with index storage

**Do**: Require safetensors for checkpoint files, secure index storage, validate token-level operations, and apply an inference timeout

```python
import hashlib
import threading
import logging
from pathlib import Path
from colbert import Indexer, Searcher
from colbert.infra import ColBERTConfig

logger = logging.getLogger(__name__)

class SecureColBERT:
    def __init__(
        self,
        index_path: str,
        checkpoint: str = "colbert-ir/colbertv2.0",
        allowed_index_dir: str = "/app/indexes",
        max_query_tokens: int = 32,
        max_doc_tokens: int = 180,
        inference_timeout_s: float = 30.0
    ):
        self.max_query_tokens = max_query_tokens
        self.max_doc_tokens = max_doc_tokens
        self.inference_timeout_s = inference_timeout_s

        # Validate index path
        resolved = Path(index_path).resolve()
        if not str(resolved).startswith(allowed_index_dir):
            raise ValueError("Index path outside allowed directory")

        self.index_path = resolved

        # Validate checkpoint
        allowed_checkpoints = [
            "colbert-ir/colbertv2.0",
            "colbert-ir/colbertv1.9"
        ]
        if checkpoint not in allowed_checkpoints:
            raise ValueError(f"Checkpoint must be one of: {allowed_checkpoints}")

        self.config = ColBERTConfig(
            checkpoint=checkpoint,
            index_root=str(resolved.parent),
            index_name=resolved.name,
            query_maxlen=max_query_tokens,
            doc_maxlen=max_doc_tokens
        )

    def create_index(
        self,
        collection: list[str],
        collection_path: str,
        max_docs: int = 100000
    ):
        """Create ColBERT index with validation"""
        if len(collection) > max_docs:
            raise ValueError(f"Collection exceeds limit: {max_docs}")

        # Validate collection path
        coll_path = Path(collection_path).resolve()
        if not str(coll_path).startswith("/app/data"):
            raise ValueError("Collection path outside allowed directory")

        # Write collection
        with open(coll_path, 'w') as f:
            for doc in collection:
                if not isinstance(doc, str):
                    raise TypeError("Documents must be strings")
                # Sanitize — remove tabs and newlines used as delimiters
                clean = doc.replace('\t', ' ').replace('\n', ' ')
                f.write(f"{clean}\n")

        indexer = Indexer(
            checkpoint=self.config.checkpoint,
            config=self.config
        )
        indexer.index(
            name=self.config.index_name,
            collection=str(coll_path)
        )

        self._save_index_checksum()

    def _save_index_checksum(self):
        """Save checksum for index integrity verification.

        Hashes .safetensors files only; refuses to verify .pt (pickle) artifacts
        so a downgrade attack that replaces safe weights with pickle weights is
        caught at load time rather than silently accepted.
        """
        checksum_file = self.index_path / "index.checksum"

        # Require safetensors format; .pt files contain pickled data
        safetensor_files = sorted(self.index_path.glob("*.safetensors"))
        if not safetensor_files:
            raise ValueError(
                "No .safetensors files found in index directory. "
                "ColBERT must be configured to write safetensors format. "
                "Refusing to checksum .pt files — they may contain pickle payloads."
            )

        hasher = hashlib.sha256()
        for f in safetensor_files:
            with open(f, 'rb') as fh:
                hasher.update(fh.read())

        with open(checksum_file, 'w') as f:
            f.write(hasher.hexdigest())

    def _verify_index_integrity(self) -> bool:
        """Verify index hasn't been tampered with."""
        checksum_file = self.index_path / "index.checksum"
        if not checksum_file.exists():
            return False

        with open(checksum_file, 'r') as f:
            expected = f.read().strip()

        safetensor_files = sorted(self.index_path.glob("*.safetensors"))
        if not safetensor_files:
            logger.error("No .safetensors index files found — index may have been replaced with .pt files")
            return False

        hasher = hashlib.sha256()
        for f in safetensor_files:
            with open(f, 'rb') as fh:
                hasher.update(fh.read())

        return hasher.hexdigest() == expected

    def search(self, query: str, k: int = 10) -> list[dict]:
        """Search with integrity verification and inference timeout."""
        if not self._verify_index_integrity():
            raise ValueError("Index integrity check failed")

        if len(query.split()) > self.max_query_tokens:
            raise ValueError(f"Query exceeds {self.max_query_tokens} tokens")

        result: list[tuple] = []
        exc: list[BaseException] = []

        def target():
            try:
                searcher = Searcher(
                    index=self.config.index_name,
                    config=self.config
                )
                result.extend(searcher.search(query, k=k))
            except Exception as e:
                exc.append(e)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(timeout=self.inference_timeout_s)

        if t.is_alive():
            logger.error(
                "ColBERT search timed out after %.1fs", self.inference_timeout_s
            )
            raise TimeoutError(
                f"Search exceeded {self.inference_timeout_s}s timeout"
            )

        if exc:
            raise exc[0]

        return [
            {'doc_id': doc_id, 'rank': rank, 'score': score}
            for rank, (doc_id, score) in enumerate(result)
        ]
```

**Don't**: Accept `.pt` index files, skip integrity checks, or omit inference timeouts

```python
from colbert import Searcher

# UNSAFE: .pt files are pickled — arbitrary code on load; no timeout; no path validation
def search(index_path, query):
    searcher = Searcher(index=index_path)
    return searcher.search(query, k=1000)
```

**Why**: ColBERT `.pt` index files are pickled tensors; loading them executes arbitrary Python. Integrity checks detect poisoned embeddings. Without an inference timeout, adversarial queries with maximum token counts exhaust workers via tail latency.

**Refs**: CWE-345 (Insufficient Verification), CWE-400 (Resource Exhaustion), CWE-502 (Deserialization), MITRE ATLAS AML.T0020

---

## Rule: Score Manipulation Prevention

**Level**: `warning`

**When**: Processing reranker output scores for ranking decisions

**Do**: Validate score bounds and detect anomalous distributions

```python
import numpy as np
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class ScoreValidator:
    def __init__(
        self,
        min_score: float = 0.0,
        max_score: float = 1.0,
        anomaly_threshold: float = 3.0  # Standard deviations
    ):
        self.min_score = min_score
        self.max_score = max_score
        self.anomaly_threshold = anomaly_threshold
        self.score_history: list[list[float]] = []
        self.max_history = 1000

    def validate_scores(
        self,
        scores: list[float],
        user_id: Optional[str] = None
    ) -> list[float]:
        """Validate and normalize reranker scores"""
        if not scores:
            return []

        validated = []
        for i, score in enumerate(scores):
            if not isinstance(score, (int, float)):
                raise ValueError(f"Score {i} is not numeric: {type(score)}")

            if score < self.min_score or score > self.max_score:
                logger.warning(
                    "Score out of bounds: %s, clamping to [%s, %s]",
                    score, self.min_score, self.max_score
                )
                score = max(self.min_score, min(self.max_score, score))

            validated.append(float(score))

        if self._is_anomalous(validated):
            logger.warning(
                "Anomalous score distribution detected: user=%s, scores=%s...",
                user_id, validated[:5]
            )

        self.score_history.append(validated)
        if len(self.score_history) > self.max_history:
            self.score_history.pop(0)

        return validated

    def _is_anomalous(self, scores: list[float]) -> bool:
        if len(self.score_history) < 10:
            return False

        all_scores = [s for batch in self.score_history for s in batch]
        hist_mean = np.mean(all_scores)
        hist_std = np.std(all_scores)

        if hist_std == 0:
            return False

        current_mean = np.mean(scores)
        z_score = abs(current_mean - hist_mean) / hist_std
        return z_score > self.anomaly_threshold

    def normalize_scores(
        self,
        scores: list[float],
        method: str = "minmax"
    ) -> list[float]:
        if not scores:
            return []

        if method == "minmax":
            min_s = min(scores)
            max_s = max(scores)
            if max_s == min_s:
                return [0.5] * len(scores)
            return [(s - min_s) / (max_s - min_s) for s in scores]

        if method == "softmax":
            exp_scores = np.exp(scores - np.max(scores))
            return (exp_scores / exp_scores.sum()).tolist()

        raise ValueError(f"Unknown normalization method: {method}")


validator = ScoreValidator(min_score=0.0, max_score=1.0)

def process_rerank_results(results: list[dict], user_id: str) -> list[dict]:
    scores = [r['score'] for r in results]
    validated = validator.validate_scores(scores, user_id)
    normalized = validator.normalize_scores(validated)

    for r, norm_score in zip(results, normalized):
        r['validated_score'] = norm_score

    return results
```

**Don't**: Trust raw scores without validation

```python
# UNSAFE: No score validation
def process_results(results):
    # No bounds checking - score manipulation
    # No anomaly detection - poisoning attacks
    # No normalization - inconsistent rankings
    return sorted(results, key=lambda x: x['score'], reverse=True)
```

**Why**: Attackers can manipulate reranker inputs to produce extreme scores. Without bounds checking, malicious scores can dominate rankings. Anomaly detection catches systematic manipulation attempts.

**Refs**: CWE-20 (Input Validation), MITRE ATLAS AML.T0020 (Poisoning)

---

## Rule: Result Ordering Integrity

**Level**: `warning`

**When**: Re-ranking search results before presentation

**Do**: Audit re-ranking operations and track position changes

```python
import hashlib
import json
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class ReRankAuditor:
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file

    def audit_rerank(
        self,
        query: str,
        original_order: list[str],  # Document IDs
        reranked_order: list[str],
        scores: list[float],
        user_id: str,
        model: str
    ) -> dict:
        """
        Audit a re-ranking operation for integrity.

        Returns audit record with position changes.
        """
        if set(original_order) != set(reranked_order):
            raise ValueError("Document set changed during re-ranking")

        position_changes = []
        for new_pos, doc_id in enumerate(reranked_order):
            old_pos = original_order.index(doc_id)
            change = old_pos - new_pos
            position_changes.append({
                'doc_id': doc_id,
                'old_position': old_pos,
                'new_position': new_pos,
                'change': change,
                'score': scores[new_pos]
            })

        changes = [abs(pc['change']) for pc in position_changes]
        max_change = max(changes)
        avg_change = sum(changes) / len(changes)

        audit_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'model': model,
            'query_hash': hashlib.sha256(query.encode()).hexdigest()[:16],
            'num_documents': len(original_order),
            'max_position_change': max_change,
            'avg_position_change': round(avg_change, 2),
            'position_changes': position_changes,
            'integrity_hash': self._compute_integrity_hash(
                original_order, reranked_order, scores
            )
        }

        if max_change > len(original_order) * 0.5:
            logger.warning(
                "Large position change detected: max=%d, user=%s, query_hash=%s",
                max_change, user_id, audit_record['query_hash']
            )

        if self.log_file:
            self._write_audit_log(audit_record)

        return audit_record

    def _compute_integrity_hash(
        self,
        original: list[str],
        reranked: list[str],
        scores: list[float]
    ) -> str:
        data = {'original': original, 'reranked': reranked, 'scores': scores}
        return hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()[:32]

    def _write_audit_log(self, record: dict):
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(record) + '\n')


auditor = ReRankAuditor(log_file="/var/log/rerank_audit.jsonl")

def rerank_with_audit(
    reranker,
    query: str,
    documents: list[dict],
    user_id: str
) -> list[dict]:
    original_ids = [d['id'] for d in documents]
    results = reranker.rerank(query, documents)
    reranked_ids = [r['id'] for r in results]
    scores = [r['score'] for r in results]

    audit = auditor.audit_rerank(
        query=query,
        original_order=original_ids,
        reranked_order=reranked_ids,
        scores=scores,
        user_id=user_id,
        model=reranker.model_name
    )

    for r in results:
        r['audit_hash'] = audit['integrity_hash']

    return results
```

**Don't**: Rerank without auditing position changes

```python
# UNSAFE: No audit trail
def rerank(query, documents):
    results = reranker.rerank(query, documents)
    # No position tracking - manipulation undetected
    # No logging - no forensic capability
    # No integrity hash - results can be tampered
    return results
```

**Why**: Re-ranking can be manipulated to promote or demote specific results. Position tracking detects systematic manipulation. Audit logs enable forensic analysis of ranking attacks.

**Refs**: CWE-778 (Insufficient Logging), OWASP LLM01:2025, MITRE ATLAS AML.T0020

---

## Rule: Cross-Encoder Input Validation

**Level**: `strict`

**When**: Using cross-encoder models that process query-document pairs

**Do**: Strictly validate and limit query-document pair inputs, including Unicode homoglyph and invisible-character detection

```python
import re
import unicodedata
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Invisible / zero-width characters used in prompt injection and smuggling attacks.
# U+200B ZERO WIDTH SPACE through U+200F and U+FEFF BOM are the most common vectors.
_INVISIBLE_CHARS = re.compile(
    r'[­​-‏‪-‮⁠-⁤⁪-⁯﻿  ]'
)

# Unicode confusable / homoglyph detection: flag any character outside the Basic
# Latin + Latin-1 Supplement blocks that could visually impersonate ASCII.
# This is a conservative heuristic; extend with unicodedata.is_normalized checks
# or the ICU confusables dataset for stricter enforcement.
_NON_BASIC_LATIN = re.compile(r'[^\x00-\xff]')


def _detect_unicode_attacks(text: str, field: str, user_id: Optional[str]) -> None:
    """
    Raise ValueError if text contains invisible characters or non-Latin-1 codepoints
    that could be used for homoglyph / confusable substitution attacks.

    Call before any model inference so adversarial Unicode is blocked at the boundary.
    """
    if _INVISIBLE_CHARS.search(text):
        logger.warning(
            "Invisible/zero-width character detected in %s: user=%s, preview=%r",
            field, user_id, text[:80]
        )
        raise ValueError(
            f"Invalid content in {field}: invisible or zero-width characters are not permitted"
        )

    suspicious_chars = _NON_BASIC_LATIN.findall(text)
    if suspicious_chars:
        # Log unique codepoints to aid forensics without logging the full payload.
        unique = sorted({unicodedata.name(c, f'U+{ord(c):04X}') for c in suspicious_chars})
        logger.warning(
            "Non-Latin-1 / potential homoglyph characters in %s: user=%s, codepoints=%s",
            field, user_id, unique[:20]
        )
        raise ValueError(
            f"Invalid content in {field}: non-ASCII characters outside Latin-1 are not permitted"
        )


class CrossEncoderValidator:
    def __init__(
        self,
        max_query_length: int = 512,
        max_doc_length: int = 4096,
        max_pairs: int = 100,
        max_total_tokens: int = 50000
    ):
        self.max_query_length = max_query_length
        self.max_doc_length = max_doc_length
        self.max_pairs = max_pairs
        self.max_total_tokens = max_total_tokens

        # Structural injection markers: role delimiters, instruction wrappers,
        # and common "ignore previous instructions" trigger phrases.
        self.suspicious_patterns = [
            r'\[INST\]',
            r'\[/INST\]',
            r'<<SYS>>',
            r'<\|system\|>',
            r'<\|user\|>',
            r'<\|assistant\|>',
            r'Human:',
            r'Assistant:',
            r'ignore previous',
            r'disregard above',
        ]
        self.pattern_regex = re.compile(
            '|'.join(self.suspicious_patterns),
            re.IGNORECASE
        )

    def validate_pair(
        self,
        query: str,
        document: str,
        user_id: Optional[str] = None
    ) -> tuple[str, str]:
        """Validate a single query-document pair."""
        if not isinstance(query, str) or not isinstance(document, str):
            raise TypeError("Query and document must be strings")

        if len(query) > self.max_query_length:
            raise ValueError(f"Query exceeds {self.max_query_length} characters")

        if len(document) > self.max_doc_length:
            raise ValueError(f"Document exceeds {self.max_doc_length} characters")

        for text, name in [(query, 'query'), (document, 'document')]:
            # Check structural injection markers
            if self.pattern_regex.search(text):
                logger.warning(
                    "Suspicious pattern in %s: user=%s, preview=%r",
                    name, user_id, text[:100]
                )
                raise ValueError(f"Invalid content in {name}")

            # Check Unicode homoglyphs and invisible characters
            _detect_unicode_attacks(text, name, user_id)

        return query, document

    def validate_batch(
        self,
        query: str,
        documents: list[str],
        user_id: Optional[str] = None
    ) -> tuple[str, list[str]]:
        """Validate a batch of query-document pairs."""
        if not documents:
            raise ValueError("Documents list is empty")

        if len(documents) > self.max_pairs:
            raise ValueError(f"Too many documents: {len(documents)} > {self.max_pairs}")

        validated_query, _ = self.validate_pair(query, "", user_id)

        validated_docs = []
        total_chars = len(query)

        for doc in documents:
            _, validated_doc = self.validate_pair("", doc, user_id)
            validated_docs.append(validated_doc)
            total_chars += len(doc)

        # Rough token estimate (1 token ~ 4 chars)
        estimated_tokens = total_chars / 4
        if estimated_tokens > self.max_total_tokens:
            raise ValueError(
                f"Total tokens exceed limit: ~{int(estimated_tokens)} > {self.max_total_tokens}"
            )

        return validated_query, validated_docs


validator = CrossEncoderValidator()

def secure_rerank(
    reranker,
    query: str,
    documents: list[str],
    user_id: str
) -> list[dict]:
    validated_query, validated_docs = validator.validate_batch(
        query, documents, user_id
    )
    return reranker.rerank(validated_query, validated_docs)
```

**Don't**: Pass unvalidated inputs to cross-encoders or ignore Unicode attack vectors

```python
# UNSAFE: No input validation, no Unicode checks
def rerank(query, documents):
    # Homoglyph substitution and zero-width characters bypass naive pattern filters
    # No length limits - OOM attacks
    # No content validation - prompt injection
    pairs = [[query, doc] for doc in documents]
    return model.predict(pairs)
```

**Why**: Cross-encoders process query and document together, making them vulnerable to injection through either input. Unicode homoglyphs (e.g., Cyrillic `а` for Latin `a`) and zero-width characters (U+200B–U+200F) bypass ASCII-only pattern filters while appearing visually identical to benign text. Excessive input sizes cause memory exhaustion.

**Refs**: CWE-20 (Input Validation), CWE-400 (Resource Exhaustion), OWASP LLM01:2025 (Prompt Injection), Unicode TR39 (Security Mechanisms)

---

## Summary

| Rule | Level | Primary Risk |
|------|-------|--------------|
| BM25 Index Security | warning | Index tampering, memory exhaustion |
| PII Redaction Before External Rerank APIs | strict | Data privacy, regulatory liability |
| Cohere Rerank API Security | strict | Legacy SDK breakage, API key exposure, cost exploitation |
| Jina Reranker Security | warning | Pickle deserialization RCE, DoS via tail latency |
| FlashRank Security | warning | CPU exhaustion, DoS via tail latency |
| ColBERT Security | warning | Pickle RCE via .pt index files, index poisoning |
| Score Manipulation Prevention | warning | Ranking manipulation |
| Result Ordering Integrity | warning | Undetected manipulation |
| Cross-Encoder Input Validation | strict | Prompt injection, homoglyph attacks, resource exhaustion |
