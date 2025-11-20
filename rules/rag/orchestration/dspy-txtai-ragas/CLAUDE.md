# CLAUDE.md - DSPy, txtai, and Ragas Security Rules

Security rules for DSPy (prompt optimization), txtai (embeddings/search), and Ragas (RAG evaluation).

## Rule: DSPy Prompt Optimization Security

**Level**: `warning`

**When**: Using DSPy teleprompters to optimize prompts with training data

**Do**:
```python
import dspy
from dspy.teleprompt import BootstrapFewShot

class SecureOptimizer:
    def __init__(self):
        self.max_demos = 10
        self.sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        ]

    def validate_training_data(self, examples: list) -> list:
        """Sanitize training data before optimization."""
        import re
        validated = []
        for ex in examples:
            # Check for sensitive data in all fields
            content = str(ex.toDict())
            has_sensitive = any(
                re.search(pattern, content)
                for pattern in self.sensitive_patterns
            )
            if has_sensitive:
                raise ValueError("Training data contains sensitive information")
            validated.append(ex)
        return validated

    def optimize_with_review(self, module, trainset, metric):
        """Optimize prompts with human review checkpoint."""
        # Validate training data
        clean_trainset = self.validate_training_data(trainset)

        teleprompter = BootstrapFewShot(
            metric=metric,
            max_bootstrapped_demos=self.max_demos,
            max_labeled_demos=self.max_demos
        )

        compiled = teleprompter.compile(module, trainset=clean_trainset)

        # Log compiled prompts for review
        self._log_compiled_prompts(compiled)

        return compiled

    def _log_compiled_prompts(self, compiled_module):
        """Log optimized prompts for security review."""
        import logging
        logger = logging.getLogger('dspy.security')

        for name, param in compiled_module.named_parameters():
            if hasattr(param, 'demos'):
                logger.info(f"Compiled demos for {name}: {len(param.demos)}")
                # Flag for manual review if demos exceed threshold
                if len(param.demos) > self.max_demos:
                    logger.warning(f"Demo count exceeds limit for {name}")
```

**Don't**:
```python
import dspy
from dspy.teleprompt import BootstrapFewShot

# Unsafe: No validation of training data
def optimize_prompts(module, trainset):
    teleprompter = BootstrapFewShot(
        max_bootstrapped_demos=100  # No limit
    )
    # Training data may contain sensitive info that gets baked into prompts
    compiled = teleprompter.compile(module, trainset=trainset)
    return compiled  # No review of what was learned
```

**Why**: Optimized prompts can memorize and leak sensitive training data. Malicious examples can inject harmful behaviors into compiled modules that persist across all future uses.

**Refs**: OWASP LLM03 (Training Data Poisoning), CWE-200 (Information Exposure)

---

## Rule: DSPy Signature Security

**Level**: `strict`

**When**: Defining DSPy signatures for input/output contracts

**Do**:
```python
import dspy
from pydantic import BaseModel, Field, validator
import re

class SecureSignature(dspy.Signature):
    """Answer questions with validated inputs and outputs."""

    question: str = dspy.InputField(
        desc="User question (max 500 chars, no special commands)"
    )
    context: str = dspy.InputField(
        desc="Retrieved context (max 2000 chars)"
    )
    answer: str = dspy.OutputField(
        desc="Factual answer based only on provided context"
    )

class ValidatedQA(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict(SecureSignature)
        self.max_question_len = 500
        self.max_context_len = 2000
        self.forbidden_patterns = [
            r'ignore\s+(previous|above|all)',
            r'disregard\s+instructions',
            r'system\s*:',
            r'<\|.*\|>',
        ]

    def forward(self, question: str, context: str) -> str:
        # Validate input lengths
        if len(question) > self.max_question_len:
            raise ValueError(f"Question exceeds {self.max_question_len} chars")
        if len(context) > self.max_context_len:
            raise ValueError(f"Context exceeds {self.max_context_len} chars")

        # Check for injection patterns
        combined = f"{question} {context}".lower()
        for pattern in self.forbidden_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                raise ValueError("Input contains forbidden pattern")

        result = self.predict(question=question, context=context)

        # Validate output doesn't leak system info
        if self._contains_system_leak(result.answer):
            raise ValueError("Output validation failed")

        return result.answer

    def _contains_system_leak(self, text: str) -> bool:
        leak_patterns = [
            r'my\s+instructions\s+are',
            r'i\s+was\s+told\s+to',
            r'system\s+prompt',
        ]
        return any(re.search(p, text.lower()) for p in leak_patterns)
```

**Don't**:
```python
import dspy

# Unsafe: No input validation on signature fields
class UnsafeSignature(dspy.Signature):
    """Answer any question."""
    question = dspy.InputField()  # No constraints
    answer = dspy.OutputField()   # No output validation

class UnsafeQA(dspy.Module):
    def __init__(self):
        super().__init__()
        self.predict = dspy.Predict(UnsafeSignature)

    def forward(self, question):
        # Direct pass-through without validation
        return self.predict(question=question).answer
```

**Why**: Unvalidated signature fields allow prompt injection attacks. Attackers can manipulate inputs to override instructions or extract sensitive information from the model.

**Refs**: OWASP LLM01 (Prompt Injection), CWE-20 (Improper Input Validation)

---

## Rule: DSPy Teleprompter Security

**Level**: `warning`

**When**: Using teleprompters for automated prompt optimization

**Do**:
```python
import dspy
from dspy.teleprompt import BootstrapFewShotWithRandomSearch
import resource
import time

class SecureTeleprompter:
    def __init__(self):
        self.max_iterations = 50
        self.max_time_seconds = 300
        self.max_memory_mb = 1024
        self.max_candidates = 10

    def compile_with_limits(self, module, trainset, metric):
        """Run optimization with resource constraints."""

        # Set memory limit
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(
            resource.RLIMIT_AS,
            (self.max_memory_mb * 1024 * 1024, hard)
        )

        start_time = time.time()

        teleprompter = BootstrapFewShotWithRandomSearch(
            metric=metric,
            max_bootstrapped_demos=4,
            max_labeled_demos=4,
            num_candidate_programs=self.max_candidates,
            num_threads=1  # Limit parallelism
        )

        # Wrap metric with timeout
        def timed_metric(example, pred, trace=None):
            if time.time() - start_time > self.max_time_seconds:
                raise TimeoutError("Optimization exceeded time limit")
            return metric(example, pred, trace)

        try:
            compiled = teleprompter.compile(
                module,
                trainset=trainset[:100]  # Limit training set size
            )

            # Validate compiled module
            self._validate_compiled(compiled)

            return compiled

        finally:
            # Reset resource limits
            resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

    def _validate_compiled(self, compiled):
        """Ensure compiled module meets security requirements."""
        total_demos = 0
        for name, param in compiled.named_parameters():
            if hasattr(param, 'demos'):
                total_demos += len(param.demos)

        if total_demos > 50:
            raise ValueError(f"Compiled module has {total_demos} demos, exceeds limit")
```

**Don't**:
```python
import dspy
from dspy.teleprompt import MIPRO

# Unsafe: No resource limits on optimization
def optimize_unlimited(module, trainset):
    teleprompter = MIPRO(
        metric=my_metric,
        num_candidates=1000,  # Excessive candidates
        # No time or memory limits
    )

    # Full training set with no bounds
    compiled = teleprompter.compile(module, trainset=trainset)
    return compiled
```

**Why**: Unbounded optimization can consume excessive resources (DoS), and attackers can craft training data that causes the optimizer to learn malicious behaviors over many iterations.

**Refs**: OWASP LLM03 (Training Data Poisoning), CWE-400 (Resource Exhaustion)

---

## Rule: DSPy Module Composition Security

**Level**: `warning`

**When**: Chaining multiple DSPy modules together

**Do**:
```python
import dspy
import re

class SecureChain(dspy.Module):
    """Chain modules with intermediate validation."""

    def __init__(self):
        super().__init__()
        self.retriever = dspy.Retrieve(k=3)
        self.summarizer = dspy.ChainOfThought("context -> summary")
        self.answerer = dspy.ChainOfThought("summary, question -> answer")

        self.max_intermediate_len = 1000
        self.allowed_topics = {'general', 'technical', 'support'}

    def forward(self, question: str) -> str:
        # Step 1: Retrieve with validation
        retrieved = self.retriever(question)
        contexts = self._validate_retrieved(retrieved.passages)

        # Step 2: Summarize with output filtering
        summary = self.summarizer(context="\n".join(contexts))
        filtered_summary = self._filter_intermediate(summary.summary)

        # Step 3: Answer with final validation
        answer = self.answerer(
            summary=filtered_summary,
            question=question
        )

        return self._validate_final_output(answer.answer)

    def _validate_retrieved(self, passages: list) -> list:
        """Filter retrieved passages for safety."""
        validated = []
        for passage in passages:
            # Remove potentially harmful content
            if len(passage) > 500:
                passage = passage[:500]
            if not self._contains_harmful_content(passage):
                validated.append(passage)
        return validated

    def _filter_intermediate(self, text: str) -> str:
        """Sanitize intermediate outputs."""
        if len(text) > self.max_intermediate_len:
            text = text[:self.max_intermediate_len]

        # Remove any instruction-like content
        text = re.sub(r'\[INST\].*?\[/INST\]', '', text, flags=re.DOTALL)
        return text

    def _validate_final_output(self, text: str) -> str:
        """Ensure final output is safe."""
        # Check for common attack indicators
        danger_patterns = [
            r'<script',
            r'javascript:',
            r'data:text/html',
        ]
        for pattern in danger_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return "I cannot provide that response."
        return text

    def _contains_harmful_content(self, text: str) -> bool:
        harmful = ['password', 'secret_key', 'private_key']
        return any(h in text.lower() for h in harmful)
```

**Don't**:
```python
import dspy

# Unsafe: No validation between chain steps
class UnsafeChain(dspy.Module):
    def __init__(self):
        super().__init__()
        self.step1 = dspy.ChainOfThought("input -> intermediate")
        self.step2 = dspy.ChainOfThought("intermediate -> output")

    def forward(self, input_text):
        # Direct pass-through without filtering
        result1 = self.step1(input=input_text)
        result2 = self.step2(intermediate=result1.intermediate)
        return result2.output  # No output validation
```

**Why**: Chained modules can amplify attacks through each step. Malicious content in early outputs can manipulate downstream modules, and intermediate results may contain sensitive information that gets passed along.

**Refs**: OWASP LLM01 (Prompt Injection), CWE-94 (Code Injection)

---

## Rule: txtai Embeddings Database Security

**Level**: `strict`

**When**: Using txtai's SQL interface for embeddings search

**Do**:
```python
from txtai.embeddings import Embeddings
from txtai.database import Database
import re

class SecureEmbeddingsDB:
    def __init__(self, path: str):
        self.embeddings = Embeddings({
            "path": path,
            "content": True,
            "backend": "sqlite"
        })
        self.allowed_columns = {'id', 'text', 'score'}
        self.max_results = 100

    def search(self, query: str, limit: int = 10) -> list:
        """Semantic search with validated parameters."""
        # Validate limit
        limit = min(max(1, limit), self.max_results)

        # Use semantic search (safe)
        results = self.embeddings.search(query, limit)
        return results

    def sql_search(self, query: str, params: tuple = None) -> list:
        """SQL search with strict validation."""
        # Whitelist allowed SQL patterns
        allowed_patterns = [
            r'^SELECT\s+(id|text|score|,|\s)+\s+FROM\s+txtai\s+WHERE',
            r'^SELECT\s+\*\s+FROM\s+txtai\s+WHERE\s+similar\(',
        ]

        query_upper = query.strip().upper()
        if not any(re.match(p, query_upper, re.IGNORECASE) for p in allowed_patterns):
            raise ValueError("SQL query does not match allowed patterns")

        # Block dangerous keywords
        dangerous = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'EXEC', '--', ';']
        for keyword in dangerous:
            if keyword in query_upper:
                raise ValueError(f"Forbidden SQL keyword: {keyword}")

        # Always use parameterized queries
        if params:
            return self.embeddings.search(query, parameters=params)
        else:
            return self.embeddings.search(query)

    def hybrid_search(self, text: str, filters: dict = None) -> list:
        """Safe hybrid search with validated filters."""
        # Build parameterized query
        base_query = "SELECT id, text, score FROM txtai WHERE similar(:query)"
        params = {"query": text}

        if filters:
            conditions = []
            for key, value in filters.items():
                # Whitelist filter columns
                if key not in self.allowed_columns:
                    raise ValueError(f"Invalid filter column: {key}")
                param_name = f"filter_{key}"
                conditions.append(f"{key} = :{param_name}")
                params[param_name] = value

            if conditions:
                base_query += " AND " + " AND ".join(conditions)

        base_query += " LIMIT :limit"
        params["limit"] = self.max_results

        return self.embeddings.search(base_query, parameters=params)
```

**Don't**:
```python
from txtai.embeddings import Embeddings

embeddings = Embeddings()

# Unsafe: SQL injection vulnerability
def search_unsafe(user_query: str, user_filter: str):
    # Direct string interpolation
    sql = f"SELECT * FROM txtai WHERE similar('{user_query}')"

    if user_filter:
        # User input directly in SQL
        sql += f" AND {user_filter}"

    return embeddings.search(sql)

# Attacker can inject: user_filter = "1=1; DROP TABLE txtai;--"
```

**Why**: txtai's SQL interface is vulnerable to injection attacks. Malicious queries can extract all data, modify the database, or cause denial of service.

**Refs**: OWASP A03 (Injection), CWE-89 (SQL Injection)

---

## Rule: txtai Graph Index Security

**Level**: `warning`

**When**: Using txtai graph indexes for relationship traversal

**Do**:
```python
from txtai.graph import Graph
from txtai.embeddings import Embeddings
import time

class SecureGraphIndex:
    def __init__(self):
        self.embeddings = Embeddings({
            "path": "embeddings",
            "content": True,
            "graph": {
                "backend": "networkx",
                "batchsize": 256
            }
        })
        self.max_depth = 3
        self.max_nodes = 100
        self.timeout_seconds = 5

    def traverse(self, start_id: str, depth: int = 2) -> list:
        """Traverse graph with security limits."""
        # Enforce depth limit
        depth = min(max(1, depth), self.max_depth)

        start_time = time.time()
        visited = set()
        results = []

        def _traverse(node_id: str, current_depth: int):
            # Check timeout
            if time.time() - start_time > self.timeout_seconds:
                raise TimeoutError("Graph traversal timeout")

            # Check node limit
            if len(visited) >= self.max_nodes:
                return

            if node_id in visited or current_depth > depth:
                return

            visited.add(node_id)

            # Get node and validate
            node = self._get_validated_node(node_id)
            if node:
                results.append(node)

                # Traverse edges
                edges = self.embeddings.graph.edges(node_id)
                for edge in edges[:10]:  # Limit edges per node
                    _traverse(edge[1], current_depth + 1)

        _traverse(start_id, 0)
        return results

    def _get_validated_node(self, node_id: str):
        """Get node with content validation."""
        # Validate node ID format
        if not node_id or len(node_id) > 100:
            return None

        node = self.embeddings.graph.node(node_id)
        if not node:
            return None

        # Filter sensitive attributes
        safe_attrs = {
            k: v for k, v in node.items()
            if k in {'id', 'text', 'score', 'type'}
        }
        return safe_attrs

    def add_relationship(self, source: str, target: str, relation: str):
        """Add relationship with validation."""
        # Validate relationship type
        allowed_relations = {'related_to', 'contains', 'references', 'similar_to'}
        if relation not in allowed_relations:
            raise ValueError(f"Invalid relation type: {relation}")

        # Validate IDs exist
        if not self.embeddings.graph.node(source):
            raise ValueError(f"Source node not found: {source}")
        if not self.embeddings.graph.node(target):
            raise ValueError(f"Target node not found: {target}")

        self.embeddings.graph.addedge(source, target, relation)
```

**Don't**:
```python
from txtai.graph import Graph

# Unsafe: No traversal limits
def traverse_all(graph, start_id, user_depth):
    visited = set()
    results = []

    def _traverse(node_id, depth):
        if node_id in visited:
            return
        visited.add(node_id)

        node = graph.node(node_id)
        results.append(node)  # Returns all attributes

        if depth < user_depth:  # User-controlled depth
            for edge in graph.edges(node_id):  # All edges
                _traverse(edge[1], depth + 1)

    _traverse(start_id, 0)
    return results
```

**Why**: Unbounded graph traversal can cause DoS through resource exhaustion. Deep or cyclic traversals can expose sensitive relationships and data across the entire knowledge graph.

**Refs**: CWE-400 (Resource Exhaustion), CWE-200 (Information Exposure)

---

## Rule: txtai Pipeline Security

**Level**: `warning`

**When**: Building txtai pipelines with multiple components

**Do**:
```python
from txtai.pipeline import Extractor, Labels, Summary, Textractor
from txtai.workflow import Workflow, Task
import tempfile
import os

class SecurePipeline:
    def __init__(self):
        # Initialize components with security settings
        self.extractor = Extractor(
            path="extractor-model",
            quantize=True  # Reduce memory footprint
        )
        self.labels = Labels("labels-model")
        self.summary = Summary("summary-model")

        self.allowed_file_types = {'.txt', '.pdf', '.docx'}
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        self.max_text_length = 50000

    def process_document(self, file_path: str) -> dict:
        """Process document with security validation."""
        # Validate file path
        file_path = self._validate_file_path(file_path)

        # Extract text
        textractor = Textractor()
        text = textractor(file_path)

        # Validate extracted content
        text = self._sanitize_text(text)

        # Process through pipeline with isolation
        results = {
            "summary": self._safe_summarize(text),
            "labels": self._safe_classify(text),
            "entities": self._safe_extract(text)
        }

        return results

    def _validate_file_path(self, file_path: str) -> str:
        """Validate and sanitize file path."""
        # Resolve to absolute path
        abs_path = os.path.abspath(file_path)

        # Check file extension
        ext = os.path.splitext(abs_path)[1].lower()
        if ext not in self.allowed_file_types:
            raise ValueError(f"File type not allowed: {ext}")

        # Check file size
        if os.path.getsize(abs_path) > self.max_file_size:
            raise ValueError("File exceeds maximum size")

        # Prevent path traversal
        if '..' in file_path:
            raise ValueError("Path traversal not allowed")

        return abs_path

    def _sanitize_text(self, text: str) -> str:
        """Sanitize extracted text."""
        if len(text) > self.max_text_length:
            text = text[:self.max_text_length]

        # Remove potential injection patterns
        import re
        text = re.sub(r'<[^>]+>', '', text)  # Remove HTML
        text = re.sub(r'\x00', '', text)  # Remove null bytes

        return text

    def _safe_summarize(self, text: str) -> str:
        """Summarize with output validation."""
        summary = self.summary(text, maxlength=200)
        return summary if len(summary) < 500 else summary[:500]

    def _safe_classify(self, text: str) -> list:
        """Classify with allowed labels."""
        allowed_labels = ['positive', 'negative', 'neutral', 'technical', 'general']
        labels = self.labels(text, allowed_labels)
        return [(l, s) for l, s in labels if l in allowed_labels]

    def _safe_extract(self, text: str) -> list:
        """Extract entities with filtering."""
        questions = ["What are the main topics?", "Who is mentioned?"]
        entities = self.extractor([(q, text) for q in questions])

        # Filter out potentially sensitive extractions
        filtered = []
        for entity in entities:
            if not self._is_sensitive(entity):
                filtered.append(entity)
        return filtered

    def _is_sensitive(self, text: str) -> bool:
        """Check if extraction contains sensitive data."""
        patterns = [r'\d{3}-\d{2}-\d{4}', r'\b\d{16}\b']
        import re
        return any(re.search(p, str(text)) for p in patterns)
```

**Don't**:
```python
from txtai.pipeline import Textractor, Summary
from txtai.workflow import Workflow

# Unsafe: No validation in pipeline
def process_any_file(file_path):
    textractor = Textractor()
    summary = Summary()

    # No file validation
    text = textractor(file_path)

    # No content validation
    result = summary(text)  # Could be massive

    return result
```

**Why**: Pipelines can be exploited through malicious files, oversized inputs, or crafted content that causes components to behave unexpectedly. Each component adds potential attack surface.

**Refs**: CWE-434 (Unrestricted Upload), CWE-400 (Resource Exhaustion)

---

## Rule: Ragas Evaluation Data Security

**Level**: `strict`

**When**: Running Ragas evaluations on RAG systems

**Do**:
```python
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy, context_precision
from datasets import Dataset
import hashlib

class SecureEvaluator:
    def __init__(self):
        self.max_samples = 1000
        self.sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{16}\b',  # Credit card
        ]

    def create_test_dataset(self, questions: list, answers: list,
                           contexts: list, ground_truths: list) -> Dataset:
        """Create evaluation dataset with security validation."""
        # Validate sizes
        if len(questions) > self.max_samples:
            raise ValueError(f"Dataset exceeds max samples: {self.max_samples}")

        # Ensure all lists same length
        if not (len(questions) == len(answers) == len(contexts) == len(ground_truths)):
            raise ValueError("All input lists must have same length")

        # Validate no production data
        for i, (q, a, c, g) in enumerate(zip(questions, answers, contexts, ground_truths)):
            if self._contains_sensitive_data(q) or self._contains_sensitive_data(a):
                raise ValueError(f"Sample {i} contains sensitive data")
            if self._contains_sensitive_data(str(c)) or self._contains_sensitive_data(g):
                raise ValueError(f"Sample {i} contains sensitive data")

        # Create dataset
        data = {
            "question": questions,
            "answer": answers,
            "contexts": contexts,
            "ground_truth": ground_truths
        }

        return Dataset.from_dict(data)

    def evaluate_safely(self, dataset: Dataset) -> dict:
        """Run evaluation with isolation and logging."""
        # Log evaluation start
        dataset_hash = self._hash_dataset(dataset)
        self._log_evaluation_start(dataset_hash, len(dataset))

        # Run evaluation with limited metrics
        results = evaluate(
            dataset,
            metrics=[
                faithfulness,
                answer_relevancy,
                context_precision
            ]
        )

        # Validate results
        self._validate_results(results)

        # Log completion
        self._log_evaluation_complete(dataset_hash, results)

        return results

    def _contains_sensitive_data(self, text: str) -> bool:
        import re
        return any(re.search(p, text) for p in self.sensitive_patterns)

    def _hash_dataset(self, dataset: Dataset) -> str:
        content = str(dataset.to_dict())
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _log_evaluation_start(self, hash_id: str, size: int):
        import logging
        logging.info(f"Evaluation started: {hash_id}, samples: {size}")

    def _log_evaluation_complete(self, hash_id: str, results: dict):
        import logging
        logging.info(f"Evaluation complete: {hash_id}, scores: {results}")

    def _validate_results(self, results: dict):
        """Ensure results are within expected bounds."""
        for metric, value in results.items():
            if not 0 <= value <= 1:
                raise ValueError(f"Invalid metric value for {metric}: {value}")
```

**Don't**:
```python
from ragas import evaluate
from datasets import Dataset

# Unsafe: Using production data for evaluation
def evaluate_with_prod_data(prod_logs):
    # Production data may contain PII
    data = {
        "question": [log["query"] for log in prod_logs],
        "answer": [log["response"] for log in prod_logs],
        "contexts": [log["retrieved_docs"] for log in prod_logs],
        "ground_truth": [log["expected"] for log in prod_logs]
    }

    dataset = Dataset.from_dict(data)

    # No validation, no logging
    return evaluate(dataset)
```

**Why**: Evaluation datasets sent to LLM judges can leak sensitive production data. Ground truth data may contain PII or proprietary information that gets exposed during evaluation.

**Refs**: OWASP LLM06 (Sensitive Information Disclosure), CWE-200 (Information Exposure)

---

## Rule: Ragas Metric Manipulation Prevention

**Level**: `warning`

**When**: Interpreting Ragas evaluation scores

**Do**:
```python
from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy
from datasets import Dataset
import numpy as np

class SecureMetricEvaluator:
    def __init__(self):
        self.min_samples = 30  # Statistical significance
        self.outlier_threshold = 3  # Standard deviations
        self.score_bounds = (0.0, 1.0)

    def evaluate_with_validation(self, dataset: Dataset) -> dict:
        """Evaluate with statistical validation."""
        # Ensure sufficient samples
        if len(dataset) < self.min_samples:
            raise ValueError(f"Need at least {self.min_samples} samples")

        # Run evaluation
        results = evaluate(
            dataset,
            metrics=[faithfulness, answer_relevancy]
        )

        # Get per-sample scores for analysis
        sample_scores = self._get_sample_scores(results)

        # Validate scores
        validated = {}
        for metric, scores in sample_scores.items():
            validation = self._validate_metric(metric, scores)
            validated[metric] = validation

        return validated

    def _get_sample_scores(self, results) -> dict:
        """Extract per-sample scores."""
        scores = {}
        for metric in ['faithfulness', 'answer_relevancy']:
            if metric in results:
                scores[metric] = results[metric]
        return scores

    def _validate_metric(self, metric: str, scores: list) -> dict:
        """Validate metric scores for manipulation."""
        scores = np.array(scores)

        # Check bounds
        if np.any(scores < self.score_bounds[0]) or np.any(scores > self.score_bounds[1]):
            raise ValueError(f"Scores outside valid bounds for {metric}")

        # Detect outliers
        mean = np.mean(scores)
        std = np.std(scores)
        outliers = np.abs(scores - mean) > (self.outlier_threshold * std)

        # Calculate confidence interval
        confidence_interval = 1.96 * std / np.sqrt(len(scores))

        return {
            "mean": float(mean),
            "std": float(std),
            "confidence_interval": float(confidence_interval),
            "outlier_count": int(np.sum(outliers)),
            "outlier_indices": list(np.where(outliers)[0]),
            "sample_size": len(scores),
            "reliable": np.sum(outliers) < len(scores) * 0.1  # <10% outliers
        }

    def compare_evaluations(self, baseline: dict, current: dict) -> dict:
        """Compare evaluations with statistical testing."""
        from scipy import stats

        comparisons = {}
        for metric in baseline.keys():
            if metric not in current:
                continue

            base_mean = baseline[metric]["mean"]
            curr_mean = current[metric]["mean"]

            # Check for suspiciously large improvements
            improvement = (curr_mean - base_mean) / base_mean if base_mean > 0 else 0

            comparisons[metric] = {
                "baseline": base_mean,
                "current": curr_mean,
                "improvement": improvement,
                "suspicious": improvement > 0.5,  # >50% improvement is suspicious
                "statistically_significant": abs(improvement) > baseline[metric]["confidence_interval"]
            }

        return comparisons
```

**Don't**:
```python
from ragas import evaluate

# Unsafe: No validation of scores
def simple_evaluate(dataset):
    results = evaluate(dataset)

    # Taking scores at face value
    return {
        "faithfulness": results["faithfulness"],
        "quality": "good" if results["faithfulness"] > 0.8 else "bad"
    }

# Easy to game by:
# - Cherry-picking test samples
# - Using adversarial ground truths
# - Small sample sizes
```

**Why**: Evaluation metrics can be manipulated through cherry-picked samples, adversarial ground truths, or statistically insignificant sample sizes. This can mask actual model quality issues.

**Refs**: CWE-345 (Insufficient Verification), NIST AI RMF (Measurement)

---

## Rule: Ragas LLM Judge Security

**Level**: `warning`

**When**: Using LLM-as-judge for Ragas evaluations

**Do**:
```python
from ragas import evaluate
from ragas.metrics import faithfulness
from ragas.llms import LangchainLLMWrapper
from langchain_openai import ChatOpenAI
import hashlib
import logging

class SecureLLMJudge:
    def __init__(self, model_name: str = "gpt-4"):
        self.llm = LangchainLLMWrapper(
            ChatOpenAI(
                model=model_name,
                temperature=0,  # Deterministic for reproducibility
                max_tokens=500  # Limit output
            )
        )
        self.logger = logging.getLogger('ragas.judge')
        self.judgment_history = []

    def evaluate_with_monitoring(self, dataset, metrics) -> dict:
        """Run evaluation with judge monitoring."""
        # Log evaluation configuration
        eval_id = self._generate_eval_id(dataset)
        self.logger.info(f"Starting evaluation {eval_id}")

        # Configure metrics to use secure LLM
        for metric in metrics:
            if hasattr(metric, 'llm'):
                metric.llm = self.llm

        # Run evaluation
        results = evaluate(dataset, metrics=metrics)

        # Analyze judge behavior
        self._analyze_judge_bias(eval_id, results)

        return results

    def _analyze_judge_bias(self, eval_id: str, results: dict):
        """Check for potential judge bias or manipulation."""
        for metric, scores in results.items():
            if not isinstance(scores, (list, tuple)):
                continue

            import numpy as np
            scores_array = np.array(scores)

            # Check for suspicious patterns
            issues = []

            # All same score (rubber stamping)
            if np.std(scores_array) < 0.01:
                issues.append("Variance too low - possible rubber stamping")

            # Binary scoring only
            unique = np.unique(scores_array)
            if len(unique) <= 2:
                issues.append("Binary scoring only - limited discrimination")

            # Extreme score bias
            extreme_ratio = np.sum((scores_array < 0.1) | (scores_array > 0.9)) / len(scores_array)
            if extreme_ratio > 0.8:
                issues.append("High extreme score ratio - possible bias")

            if issues:
                self.logger.warning(f"Eval {eval_id}, metric {metric}: {issues}")
                self.judgment_history.append({
                    "eval_id": eval_id,
                    "metric": metric,
                    "issues": issues
                })

    def _generate_eval_id(self, dataset) -> str:
        content = str(len(dataset)) + str(dataset[0] if len(dataset) > 0 else "")
        return hashlib.md5(content.encode()).hexdigest()[:8]

    def get_judge_audit_log(self) -> list:
        """Return audit log of judge behavior issues."""
        return self.judgment_history

    def validate_judge_consistency(self, sample, n_runs: int = 3) -> dict:
        """Test judge consistency on same sample."""
        scores = []

        for _ in range(n_runs):
            result = evaluate(
                sample,
                metrics=[faithfulness],
                llm=self.llm
            )
            scores.append(result["faithfulness"])

        import numpy as np
        std = np.std(scores)

        return {
            "scores": scores,
            "std": std,
            "consistent": std < 0.1  # Expect low variance with temp=0
        }
```

**Don't**:
```python
from ragas import evaluate
from ragas.metrics import faithfulness

# Unsafe: No monitoring of judge behavior
def simple_judge_eval(dataset):
    # Default LLM settings may vary
    results = evaluate(
        dataset,
        metrics=[faithfulness]
    )

    # Trust scores without validation
    return results["faithfulness"]

# Risks:
# - Judge prompt injection through test data
# - Inconsistent scoring
# - Bias not detected
```

**Why**: LLM judges can be manipulated through adversarial inputs in the test data. Without monitoring, biased or inconsistent judgments go undetected, leading to false confidence in model quality.

**Refs**: OWASP LLM01 (Prompt Injection), NIST AI RMF (Human-AI Teaming)

---

## Rule: Cross-Framework Security Integration

**Level**: `advisory`

**When**: Using DSPy, txtai, and Ragas together in evaluation pipelines

**Do**:
```python
import dspy
from txtai.embeddings import Embeddings
from ragas import evaluate
from ragas.metrics import faithfulness, context_precision
from datasets import Dataset
import logging

class SecureRAGEvaluationPipeline:
    """Secure integration of DSPy, txtai, and Ragas."""

    def __init__(self):
        self.logger = logging.getLogger('rag.secure')

        # Initialize with security configs
        self.embeddings = Embeddings({
            "path": "secure-embeddings",
            "content": True
        })

        # DSPy module with validation
        self.qa_module = self._create_secure_module()

        # Evaluation settings
        self.max_eval_samples = 100

    def _create_secure_module(self):
        """Create DSPy module with security controls."""
        class SecureRAG(dspy.Module):
            def __init__(self):
                super().__init__()
                self.retrieve = dspy.Retrieve(k=3)
                self.generate = dspy.ChainOfThought("context, question -> answer")

            def forward(self, question):
                # Input validation
                if len(question) > 500:
                    question = question[:500]

                context = self.retrieve(question)
                answer = self.generate(
                    context=context.passages,
                    question=question
                )
                return answer

        return SecureRAG()

    def run_evaluation_pipeline(self, test_questions: list,
                                ground_truths: list) -> dict:
        """Run complete evaluation with security at each stage."""

        # 1. Validate test data
        self.logger.info("Validating test data")
        test_questions, ground_truths = self._validate_test_data(
            test_questions, ground_truths
        )

        # 2. Generate answers using DSPy
        self.logger.info("Generating answers with DSPy")
        answers = []
        contexts = []

        for question in test_questions:
            try:
                result = self.qa_module(question)
                answers.append(result.answer)
                contexts.append(result.context if hasattr(result, 'context') else [])
            except Exception as e:
                self.logger.error(f"Generation failed: {e}")
                answers.append("")
                contexts.append([])

        # 3. Create evaluation dataset
        self.logger.info("Creating evaluation dataset")
        dataset = Dataset.from_dict({
            "question": test_questions,
            "answer": answers,
            "contexts": contexts,
            "ground_truth": ground_truths
        })

        # 4. Run Ragas evaluation
        self.logger.info("Running Ragas evaluation")
        results = evaluate(
            dataset,
            metrics=[faithfulness, context_precision]
        )

        # 5. Validate and log results
        validated_results = self._validate_results(results)
        self.logger.info(f"Evaluation complete: {validated_results}")

        return validated_results

    def _validate_test_data(self, questions: list, truths: list) -> tuple:
        """Validate test data for security issues."""
        if len(questions) > self.max_eval_samples:
            questions = questions[:self.max_eval_samples]
            truths = truths[:self.max_eval_samples]

        # Check for sensitive data
        import re
        sensitive_pattern = r'\b\d{3}-\d{2}-\d{4}\b'

        for i, (q, t) in enumerate(zip(questions, truths)):
            if re.search(sensitive_pattern, q) or re.search(sensitive_pattern, t):
                raise ValueError(f"Sensitive data in sample {i}")

        return questions, truths

    def _validate_results(self, results: dict) -> dict:
        """Validate evaluation results."""
        validated = {}

        for metric, value in results.items():
            if isinstance(value, (int, float)):
                if not 0 <= value <= 1:
                    self.logger.warning(f"Invalid {metric} value: {value}")
                    continue
                validated[metric] = round(value, 4)

        return validated
```

**Why**: When combining multiple frameworks, security gaps can emerge at integration points. Each framework has different trust boundaries that must be maintained across the pipeline.

**Refs**: OWASP LLM01 (Prompt Injection), NIST AI RMF (Governance), CWE-94 (Code Injection)
