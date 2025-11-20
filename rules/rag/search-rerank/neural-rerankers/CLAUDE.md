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

**Refs**: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion), OWASP LLM01

---

## Rule: Cohere Rerank API Security

**Level**: `strict`

**When**: Using Cohere Rerank API for neural reranking

**Do**: Secure API keys, implement rate limiting, validate inputs

```python
import os
import cohere
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class SecureCohereReranker:
    def __init__(self):
        # Load API key from secure source
        api_key = os.environ.get('COHERE_API_KEY')
        if not api_key:
            raise ValueError("COHERE_API_KEY not configured")

        self.client = cohere.Client(api_key)
        self.rate_limits = defaultdict(list)
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

        try:
            response = self.client.rerank(
                query=query,
                documents=documents,
                top_n=min(top_n, len(documents)),
                model=model
            )

            # Log for audit
            logger.info(f"Cohere rerank: user={user_id}, docs={len(documents)}, model={model}")

            return [
                {
                    'index': result.index,
                    'relevance_score': result.relevance_score,
                    'document': documents[result.index]
                }
                for result in response.results
            ]

        except cohere.CohereAPIError as e:
            logger.error(f"Cohere API error: {e}")
            raise
```

**Don't**: Hardcode API keys or skip rate limiting

```python
import cohere

# UNSAFE: Hardcoded API key
client = cohere.Client("sk-live-xxxxx")

def rerank(query, documents):
    # No rate limiting - cost explosion risk
    # No input validation - API abuse
    # No size limits - expensive API calls
    return client.rerank(
        query=query,
        documents=documents,
        top_n=100
    )
```

**Why**: Exposed API keys lead to unauthorized usage and cost exploitation. Without rate limiting, attackers can exhaust API quotas. Unvalidated inputs increase API costs and enable prompt injection.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-770 (Resource Allocation), OWASP LLM01

---

## Rule: Jina Reranker Security

**Level**: `warning`

**When**: Using Jina Reranker for local neural reranking

**Do**: Secure model loading and enforce resource limits

```python
import os
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from pathlib import Path

class SecureJinaReranker:
    def __init__(
        self,
        model_name: str = "jinaai/jina-reranker-v1-base-en",
        allowed_model_dir: str = "/app/models",
        max_length: int = 512,
        max_batch_size: int = 32
    ):
        self.max_length = max_length
        self.max_batch_size = max_batch_size

        # Validate model source
        if model_name.startswith('/'):
            # Local path - validate
            resolved = Path(model_name).resolve()
            if not str(resolved).startswith(allowed_model_dir):
                raise ValueError("Model path outside allowed directory")
            model_path = str(resolved)
        else:
            # HuggingFace model - validate name
            allowed_models = [
                "jinaai/jina-reranker-v1-base-en",
                "jinaai/jina-reranker-v1-turbo-en",
                "jinaai/jina-reranker-v2-base-multilingual"
            ]
            if model_name not in allowed_models:
                raise ValueError(f"Model not in allowed list: {allowed_models}")
            model_path = model_name

        # Set memory limits
        if torch.cuda.is_available():
            torch.cuda.set_per_process_memory_fraction(0.5)

        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.eval()

    def rerank(
        self,
        query: str,
        documents: list[str],
        top_n: int = 10
    ) -> list[dict]:
        if not documents:
            return []

        # Validate inputs
        if len(query) > 1000:
            raise ValueError("Query exceeds maximum length")

        if len(documents) > 1000:
            raise ValueError("Too many documents")

        # Process in batches
        scores = []
        for i in range(0, len(documents), self.max_batch_size):
            batch = documents[i:i + self.max_batch_size]
            batch_scores = self._score_batch(query, batch)
            scores.extend(batch_scores)

        # Sort and return top_n
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

**Don't**: Load untrusted models or skip resource limits

```python
from transformers import AutoModelForSequenceClassification

# UNSAFE: No model validation
def load_reranker(model_path):
    # Arbitrary model loading - malicious model risk
    return AutoModelForSequenceClassification.from_pretrained(model_path)

def rerank(model, query, documents):
    # No batch limits - memory exhaustion
    # No length limits - OOM errors
    pairs = [[query, doc] for doc in documents]
    return model(**tokenizer(pairs))
```

**Why**: Arbitrary model loading can execute malicious code. Without memory limits, large batches cause OOM. Untrusted models may contain backdoors that manipulate rankings.

**Refs**: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion), MITRE ATLAS AML.T0043

---

## Rule: FlashRank Security

**Level**: `warning`

**When**: Using FlashRank for CPU-optimized reranking

**Do**: Configure CPU optimization securely and enforce batch limits

```python
import os
from flashrank import Ranker, RerankRequest
from pathlib import Path

class SecureFlashRanker:
    def __init__(
        self,
        model_name: str = "ms-marco-MiniLM-L-12-v2",
        cache_dir: str = "/app/models/flashrank",
        max_batch_size: int = 100,
        max_length: int = 512
    ):
        self.max_batch_size = max_batch_size
        self.max_length = max_length

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

        # Validate input sizes
        if len(query) > 1000:
            raise ValueError("Query exceeds maximum length")

        if len(documents) > self.max_batch_size:
            raise ValueError(f"Batch size exceeds limit: {self.max_batch_size}")

        # Validate document format
        for doc in documents:
            if 'id' not in doc or 'text' not in doc:
                raise ValueError("Documents must have 'id' and 'text' keys")
            if len(doc['text']) > 10000:
                raise ValueError("Document text exceeds maximum length")

        request = RerankRequest(
            query=query,
            passages=documents
        )

        results = self.ranker.rerank(request)

        return [
            {
                'id': r['id'],
                'text': r['text'],
                'score': r['score']
            }
            for r in results[:top_n]
        ]
```

**Don't**: Allow unlimited CPU usage or unvalidated inputs

```python
from flashrank import Ranker

# UNSAFE: No resource limits
ranker = Ranker()

def rerank(query, documents):
    # No batch limits - CPU exhaustion
    # No validation - crash on malformed input
    # No thread limits - system overload
    return ranker.rerank(RerankRequest(
        query=query,
        passages=documents  # Arbitrary size
    ))
```

**Why**: FlashRank is CPU-intensive; unlimited batches cause resource exhaustion. Unvalidated document formats cause crashes. Unrestricted thread usage affects system stability.

**Refs**: CWE-400 (Resource Exhaustion), CWE-770 (Resource Allocation)

---

## Rule: ColBERT Security

**Level**: `warning`

**When**: Using ColBERT for token-level reranking with index storage

**Do**: Secure index storage and validate token-level operations

```python
import os
import hashlib
from pathlib import Path
from colbert import Indexer, Searcher
from colbert.infra import ColBERTConfig

class SecureColBERT:
    def __init__(
        self,
        index_path: str,
        checkpoint: str = "colbert-ir/colbertv2.0",
        allowed_index_dir: str = "/app/indexes",
        max_query_tokens: int = 32,
        max_doc_tokens: int = 180
    ):
        self.max_query_tokens = max_query_tokens
        self.max_doc_tokens = max_doc_tokens

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
                # Sanitize - remove tabs used as delimiter
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

        # Generate index checksum
        self._save_index_checksum()

    def _save_index_checksum(self):
        """Save checksum for index integrity verification"""
        checksum_file = self.index_path / "index.checksum"

        # Hash key index files
        files_to_hash = list(self.index_path.glob("*.pt"))
        hasher = hashlib.sha256()

        for f in sorted(files_to_hash):
            with open(f, 'rb') as fh:
                hasher.update(fh.read())

        with open(checksum_file, 'w') as f:
            f.write(hasher.hexdigest())

    def search(
        self,
        query: str,
        k: int = 10
    ) -> list[dict]:
        """Search with integrity verification"""
        # Verify index integrity
        if not self._verify_index_integrity():
            raise ValueError("Index integrity check failed")

        # Validate query
        if len(query.split()) > self.max_query_tokens:
            raise ValueError(f"Query exceeds {self.max_query_tokens} tokens")

        searcher = Searcher(
            index=self.config.index_name,
            config=self.config
        )

        results = searcher.search(query, k=k)

        return [
            {
                'doc_id': doc_id,
                'rank': rank,
                'score': score
            }
            for rank, (doc_id, score) in enumerate(results)
        ]

    def _verify_index_integrity(self) -> bool:
        """Verify index hasn't been tampered with"""
        checksum_file = self.index_path / "index.checksum"
        if not checksum_file.exists():
            return False

        with open(checksum_file, 'r') as f:
            expected = f.read().strip()

        files_to_hash = list(self.index_path.glob("*.pt"))
        hasher = hashlib.sha256()

        for f in sorted(files_to_hash):
            with open(f, 'rb') as fh:
                hasher.update(fh.read())

        return hasher.hexdigest() == expected
```

**Don't**: Store indexes without integrity checks or skip token validation

```python
from colbert import Searcher

# UNSAFE: No index validation
def search(index_path, query):
    # No path validation - path traversal
    # No integrity check - tampered index
    # No token limits - resource exhaustion
    searcher = Searcher(index=index_path)
    return searcher.search(query, k=1000)
```

**Why**: ColBERT indexes can be poisoned to manipulate token-level relevance. Without integrity checks, attackers can inject malicious embeddings. Excessive token counts cause memory exhaustion.

**Refs**: CWE-345 (Insufficient Verification), CWE-400 (Resource Exhaustion), MITRE ATLAS AML.T0020

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
            # Type validation
            if not isinstance(score, (int, float)):
                raise ValueError(f"Score {i} is not numeric: {type(score)}")

            # Bounds validation
            if score < self.min_score or score > self.max_score:
                logger.warning(
                    f"Score out of bounds: {score}, clamping to [{self.min_score}, {self.max_score}]"
                )
                score = max(self.min_score, min(self.max_score, score))

            validated.append(float(score))

        # Check for anomalous distribution
        if self._is_anomalous(validated):
            logger.warning(
                f"Anomalous score distribution detected: user={user_id}, "
                f"scores={validated[:5]}..."
            )

        # Update history
        self.score_history.append(validated)
        if len(self.score_history) > self.max_history:
            self.score_history.pop(0)

        return validated

    def _is_anomalous(self, scores: list[float]) -> bool:
        """Detect anomalous score distributions"""
        if len(self.score_history) < 10:
            return False

        # Calculate historical statistics
        all_scores = [s for batch in self.score_history for s in batch]
        hist_mean = np.mean(all_scores)
        hist_std = np.std(all_scores)

        if hist_std == 0:
            return False

        # Check if current batch is anomalous
        current_mean = np.mean(scores)
        z_score = abs(current_mean - hist_mean) / hist_std

        return z_score > self.anomaly_threshold

    def normalize_scores(
        self,
        scores: list[float],
        method: str = "minmax"
    ) -> list[float]:
        """Normalize scores to consistent range"""
        if not scores:
            return []

        if method == "minmax":
            min_s = min(scores)
            max_s = max(scores)
            if max_s == min_s:
                return [0.5] * len(scores)
            return [(s - min_s) / (max_s - min_s) for s in scores]

        elif method == "softmax":
            exp_scores = np.exp(scores - np.max(scores))
            return (exp_scores / exp_scores.sum()).tolist()

        else:
            raise ValueError(f"Unknown normalization method: {method}")


# Usage
validator = ScoreValidator(min_score=0.0, max_score=1.0)

def process_rerank_results(results: list[dict], user_id: str) -> list[dict]:
    scores = [r['score'] for r in results]

    # Validate and normalize
    validated = validator.validate_scores(scores, user_id)
    normalized = validator.normalize_scores(validated)

    # Update results with validated scores
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
        # Validate no documents were added/removed
        if set(original_order) != set(reranked_order):
            raise ValueError("Document set changed during re-ranking")

        # Calculate position changes
        position_changes = []
        for new_pos, doc_id in enumerate(reranked_order):
            old_pos = original_order.index(doc_id)
            change = old_pos - new_pos  # Positive = moved up
            position_changes.append({
                'doc_id': doc_id,
                'old_position': old_pos,
                'new_position': new_pos,
                'change': change,
                'score': scores[new_pos]
            })

        # Calculate statistics
        changes = [abs(pc['change']) for pc in position_changes]
        max_change = max(changes)
        avg_change = sum(changes) / len(changes)

        # Create audit record
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

        # Log suspicious patterns
        if max_change > len(original_order) * 0.5:
            logger.warning(
                f"Large position change detected: max={max_change}, "
                f"user={user_id}, query_hash={audit_record['query_hash']}"
            )

        # Persist audit log
        if self.log_file:
            self._write_audit_log(audit_record)

        return audit_record

    def _compute_integrity_hash(
        self,
        original: list[str],
        reranked: list[str],
        scores: list[float]
    ) -> str:
        """Compute hash for verifying audit integrity"""
        data = {
            'original': original,
            'reranked': reranked,
            'scores': scores
        }
        return hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()[:32]

    def _write_audit_log(self, record: dict):
        """Append audit record to log file"""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(record) + '\n')


# Usage
auditor = ReRankAuditor(log_file="/var/log/rerank_audit.jsonl")

def rerank_with_audit(
    reranker,
    query: str,
    documents: list[dict],
    user_id: str
) -> list[dict]:
    # Get original order
    original_ids = [d['id'] for d in documents]

    # Perform reranking
    results = reranker.rerank(query, documents)

    # Audit the operation
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

    # Attach audit info to results
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

**Refs**: CWE-778 (Insufficient Logging), OWASP LLM01, MITRE ATLAS AML.T0020

---

## Rule: Cross-Encoder Input Validation

**Level**: `strict`

**When**: Using cross-encoder models that process query-document pairs

**Do**: Strictly validate and limit query-document pair inputs

```python
import re
from typing import Optional
import logging

logger = logging.getLogger(__name__)

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

        # Patterns that could indicate injection attempts
        self.suspicious_patterns = [
            r'\[INST\]',           # Instruction markers
            r'\[/INST\]',
            r'<<SYS>>',            # System prompt markers
            r'<\|system\|>',
            r'<\|user\|>',
            r'<\|assistant\|>',
            r'Human:',             # Role markers
            r'Assistant:',
            r'ignore previous',    # Prompt injection
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
        """Validate a single query-document pair"""
        # Type validation
        if not isinstance(query, str) or not isinstance(document, str):
            raise TypeError("Query and document must be strings")

        # Length validation
        if len(query) > self.max_query_length:
            raise ValueError(f"Query exceeds {self.max_query_length} characters")

        if len(document) > self.max_doc_length:
            raise ValueError(f"Document exceeds {self.max_doc_length} characters")

        # Check for injection patterns
        for text, name in [(query, 'query'), (document, 'document')]:
            if self.pattern_regex.search(text):
                logger.warning(
                    f"Suspicious pattern in {name}: user={user_id}, "
                    f"text_preview={text[:100]}"
                )
                raise ValueError(f"Invalid content in {name}")

        return query, document

    def validate_batch(
        self,
        query: str,
        documents: list[str],
        user_id: Optional[str] = None
    ) -> tuple[str, list[str]]:
        """Validate a batch of query-document pairs"""
        if not documents:
            raise ValueError("Documents list is empty")

        if len(documents) > self.max_pairs:
            raise ValueError(f"Too many documents: {len(documents)} > {self.max_pairs}")

        # Validate query
        validated_query, _ = self.validate_pair(query, "", user_id)

        # Validate documents and calculate total tokens
        validated_docs = []
        total_chars = len(query)

        for i, doc in enumerate(documents):
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


# Usage
validator = CrossEncoderValidator()

def secure_rerank(
    reranker,
    query: str,
    documents: list[str],
    user_id: str
) -> list[dict]:
    # Validate inputs
    validated_query, validated_docs = validator.validate_batch(
        query, documents, user_id
    )

    # Perform reranking with validated inputs
    return reranker.rerank(validated_query, validated_docs)
```

**Don't**: Pass unvalidated inputs to cross-encoders

```python
# UNSAFE: No input validation
def rerank(query, documents):
    # No length limits - OOM attacks
    # No content validation - prompt injection
    # No pair limits - resource exhaustion
    pairs = [[query, doc] for doc in documents]
    return model.predict(pairs)
```

**Why**: Cross-encoders process query and document together, making them vulnerable to injection attacks through either input. Excessive input sizes cause memory exhaustion. Malicious patterns can manipulate model behavior.

**Refs**: CWE-20 (Input Validation), CWE-400 (Resource Exhaustion), OWASP LLM01 (Prompt Injection)

---

## Summary

| Rule | Level | Primary Risk |
|------|-------|--------------|
| BM25 Index Security | warning | Index tampering, memory exhaustion |
| Cohere Rerank API Security | strict | API key exposure, cost exploitation |
| Jina Reranker Security | warning | Malicious models, OOM attacks |
| FlashRank Security | warning | CPU exhaustion, system overload |
| ColBERT Security | warning | Index poisoning, token attacks |
| Score Manipulation Prevention | warning | Ranking manipulation |
| Result Ordering Integrity | warning | Undetected manipulation |
| Cross-Encoder Input Validation | strict | Prompt injection, resource exhaustion |
