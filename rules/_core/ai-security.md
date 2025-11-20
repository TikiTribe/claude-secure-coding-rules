# AI Security - Core Security Rules

This file provides foundational security rules for AI/ML systems based on NIST AI RMF, ISO/IEC 23894, MITRE ATLAS, and Google SAIF.

## Overview

**Standards**: NIST AI 100-1 (AI RMF), ISO/IEC 23894:2023, ISO/IEC 42005:2025
**Attack Taxonomy**: MITRE ATLAS
**Industry Framework**: Google SAIF
**Scope**: AI system security across data, model, infrastructure, and application layers

---

## Data Security

### Rule: Validate Training Data Integrity

**Level**: `strict`

**When**: Ingesting, preprocessing, or using training data for ML models.

**Do**:
```python
import hashlib
import json
from pathlib import Path

class DatasetValidator:
    def __init__(self, manifest_path: str):
        with open(manifest_path) as f:
            self.manifest = json.load(f)

    def validate_dataset(self, dataset_path: str) -> bool:
        """Verify dataset integrity against manifest."""
        for file_info in self.manifest['files']:
            filepath = Path(dataset_path) / file_info['name']

            # Verify file exists
            if not filepath.exists():
                raise DataIntegrityError(f"Missing file: {filepath}")

            # Verify checksum
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)

            if sha256.hexdigest() != file_info['sha256']:
                raise DataIntegrityError(f"Checksum mismatch: {filepath}")

        return True

    def log_data_provenance(self, dataset_id: str, source: str, transformations: list):
        """Document data lineage for audit trail."""
        provenance = {
            'dataset_id': dataset_id,
            'source': source,
            'transformations': transformations,
            'validated_at': datetime.utcnow().isoformat(),
            'validator_version': self.manifest.get('version')
        }
        audit_logger.info(json.dumps(provenance))
```

**Don't**:
```python
# VULNERABLE: No integrity verification
def load_training_data(path):
    return pd.read_csv(path)  # No checksum, no provenance

# VULNERABLE: Accepting data from untrusted sources
def train_model(user_uploaded_data):
    model.fit(user_uploaded_data)  # Data poisoning risk
```

**Why**: Data poisoning attacks (MITRE ATLAS AML.T0020) corrupt training data to cause model misbehavior. Integrity verification ensures data hasn't been tampered with.

**Refs**: MITRE ATLAS AML.T0020, NIST AI RMF MAP 1.5, ISO/IEC 23894 Annex B, Google SAIF Data Security

---

### Rule: Protect Sensitive Training Data

**Level**: `strict`

**When**: Training data contains PII, proprietary information, or sensitive content.

**Do**:
```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

class DataPrivacyHandler:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    def scan_and_redact_pii(self, text: str) -> str:
        """Detect and redact PII from training text."""
        results = self.analyzer.analyze(
            text=text,
            entities=["PERSON", "EMAIL", "PHONE_NUMBER", "CREDIT_CARD", "SSN"],
            language='en'
        )
        return self.anonymizer.anonymize(text=text, analyzer_results=results).text

    def apply_differential_privacy(self, dataset, epsilon=1.0):
        """Add differential privacy noise to dataset."""
        from diffprivlib.models import GaussianNB
        # Use DP-aware algorithms for sensitive data
        return dp_preprocessor.transform(dataset, epsilon=epsilon)

# Encrypt data at rest
from cryptography.fernet import Fernet

def encrypt_dataset(data: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data)
```

**Don't**:
```python
# VULNERABLE: Training on raw PII
model.fit(customer_data_with_ssn)

# VULNERABLE: No access controls on training data
training_data = open('/shared/training_data.csv').read()
```

**Why**: Training data can leak through model memorization (AML.T0024 - Exfiltration via ML Inference API). Models may regurgitate sensitive data from training sets.

**Refs**: MITRE ATLAS AML.T0024, NIST AI RMF MANAGE 2.2, ISO/IEC 23894 A.8 Privacy, GDPR Art. 25

---

## Model Security

### Rule: Secure Model Artifacts

**Level**: `strict`

**When**: Storing, deploying, or distributing trained models.

**Do**:
```python
import hashlib
import json
from cryptography.hazmat.primitives import serialization

class SecureModelManager:
    def save_model(self, model, path: str, metadata: dict):
        """Save model with integrity metadata."""
        # Serialize model
        model_bytes = self._serialize_model(model)

        # Generate integrity hash
        sha256 = hashlib.sha256(model_bytes).hexdigest()

        # Sign the hash
        signature = self._sign_hash(sha256)

        # Save model and metadata
        with open(path, 'wb') as f:
            f.write(model_bytes)

        metadata_path = f"{path}.meta"
        with open(metadata_path, 'w') as f:
            json.dump({
                'sha256': sha256,
                'signature': signature,
                'created_at': datetime.utcnow().isoformat(),
                'framework': metadata.get('framework'),
                'version': metadata.get('version')
            }, f)

    def load_model(self, path: str):
        """Load model with integrity verification."""
        metadata_path = f"{path}.meta"

        with open(metadata_path) as f:
            metadata = json.load(f)

        with open(path, 'rb') as f:
            model_bytes = f.read()

        # Verify integrity
        actual_hash = hashlib.sha256(model_bytes).hexdigest()
        if actual_hash != metadata['sha256']:
            raise ModelIntegrityError("Model hash mismatch - possible tampering")

        # Verify signature
        if not self._verify_signature(metadata['sha256'], metadata['signature']):
            raise ModelIntegrityError("Invalid model signature")

        return self._deserialize_model(model_bytes)
```

**Don't**:
```python
# VULNERABLE: No integrity verification
model = torch.load('model.pt')  # Could be tampered

# VULNERABLE: Storing models without access control
model.save('/public/models/production.pkl')
```

**Why**: Model theft (AML.T0000) and tampering can compromise IP and introduce backdoors. Integrity verification detects unauthorized modifications.

**Refs**: MITRE ATLAS AML.T0000, NIST AI RMF MANAGE 2.3, Google SAIF Model Security

---

### Rule: Implement Model Access Controls

**Level**: `strict`

**When**: Exposing models via APIs or allowing model inference.

**Do**:
```python
from functools import wraps
import time

class ModelAPIProtection:
    def __init__(self):
        self.rate_limiter = RateLimiter(requests_per_minute=60)
        self.query_logger = QueryLogger()

    def protected_inference(self, auth_required=True, rate_limit=True):
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # Authentication
                if auth_required:
                    user = self.authenticate_request()
                    if not user:
                        raise AuthenticationError("Invalid credentials")

                # Rate limiting
                if rate_limit and not self.rate_limiter.allow(user.id):
                    raise RateLimitError("Rate limit exceeded")

                # Log query for monitoring
                self.query_logger.log(
                    user_id=user.id,
                    input_hash=hash(str(kwargs.get('input'))),
                    timestamp=time.time()
                )

                # Execute inference
                result = f(*args, **kwargs)

                # Limit output precision to prevent extraction
                if hasattr(result, 'probabilities'):
                    result.probabilities = self._round_probabilities(
                        result.probabilities, decimals=2
                    )

                return result
            return wrapper
        return decorator

    def _round_probabilities(self, probs, decimals=2):
        """Reduce precision to hinder model extraction attacks."""
        return [round(p, decimals) for p in probs]

@model_api.route('/predict', methods=['POST'])
@protection.protected_inference(auth_required=True, rate_limit=True)
def predict(input_data):
    return model.predict(input_data)
```

**Don't**:
```python
# VULNERABLE: Unauthenticated model access
@app.route('/predict', methods=['POST'])
def predict():
    return model.predict(request.json)

# VULNERABLE: Full probability distribution enables extraction
def predict(x):
    return model.predict_proba(x).tolist()  # All probabilities
```

**Why**: Unrestricted API access enables model extraction attacks (AML.T0040) where attackers reconstruct the model through queries.

**Refs**: MITRE ATLAS AML.T0040, AML.T0024, NIST AI RMF MANAGE 1.3, Google SAIF Application Security

---

## Inference Security

### Rule: Validate and Sanitize Model Inputs

**Level**: `strict`

**When**: Receiving inputs for model inference from users or external systems.

**Do**:
```python
import numpy as np
from pydantic import BaseModel, validator

class ImageInput(BaseModel):
    image_data: bytes
    format: str

    @validator('image_data')
    def validate_image(cls, v):
        # Size limits
        if len(v) > 10 * 1024 * 1024:  # 10MB max
            raise ValueError("Image too large")

        # Format validation
        if not v[:8] in [b'\x89PNG', b'\xff\xd8\xff']:  # PNG/JPEG magic
            raise ValueError("Invalid image format")

        return v

class InferenceValidator:
    def __init__(self, input_spec):
        self.input_spec = input_spec

    def validate(self, input_data):
        """Validate input against expected schema and bounds."""
        # Type checking
        if not isinstance(input_data, np.ndarray):
            input_data = np.array(input_data)

        # Shape validation
        if input_data.shape != self.input_spec['shape']:
            raise ValidationError(f"Expected shape {self.input_spec['shape']}")

        # Range validation
        if input_data.min() < self.input_spec['min_value']:
            raise ValidationError("Input below minimum value")
        if input_data.max() > self.input_spec['max_value']:
            raise ValidationError("Input above maximum value")

        # Anomaly detection for adversarial inputs
        if self._detect_adversarial(input_data):
            raise AdversarialInputError("Potential adversarial input detected")

        return input_data

    def _detect_adversarial(self, input_data):
        """Basic adversarial detection heuristics."""
        # Check for unusual patterns
        gradient_magnitude = np.abs(np.gradient(input_data)).max()
        if gradient_magnitude > self.input_spec.get('max_gradient', 10):
            return True
        return False
```

**Don't**:
```python
# VULNERABLE: No input validation
@app.route('/classify', methods=['POST'])
def classify():
    image = request.files['image'].read()
    return model.predict(preprocess(image))

# VULNERABLE: Accepting arbitrary numpy arrays
def predict(data):
    return model(np.array(data))  # No bounds checking
```

**Why**: Adversarial inputs (AML.T0043 - Craft Adversarial Data) can manipulate model behavior. Input validation catches malformed or malicious inputs.

**Refs**: MITRE ATLAS AML.T0043, NIST AI RMF MEASURE 2.6, ISO/IEC 23894 A.9 Robustness

---

### Rule: Detect and Handle Adversarial Inputs

**Level**: `warning`

**When**: Model outputs will drive automated decisions or security-relevant actions.

**Do**:
```python
import numpy as np

class AdversarialDefense:
    def __init__(self, model, detector):
        self.model = model
        self.detector = detector

    def secure_predict(self, input_data):
        """Prediction with adversarial detection."""
        # Detect adversarial perturbations
        is_adversarial, confidence = self.detector.detect(input_data)

        if is_adversarial and confidence > 0.8:
            # Log and alert
            security_logger.warning(
                "Adversarial input detected",
                extra={'confidence': confidence, 'input_hash': hash(input_data.tobytes())}
            )
            raise AdversarialInputError("Input rejected as adversarial")

        # Apply input transformations to reduce adversarial effectiveness
        cleaned_input = self._apply_defenses(input_data)

        # Get prediction with confidence
        prediction = self.model.predict(cleaned_input)
        pred_confidence = self.model.predict_proba(cleaned_input).max()

        # Flag low-confidence predictions
        if pred_confidence < 0.6:
            return {
                'prediction': prediction,
                'confidence': pred_confidence,
                'warning': 'Low confidence - manual review recommended'
            }

        return {'prediction': prediction, 'confidence': pred_confidence}

    def _apply_defenses(self, input_data):
        """Apply defensive transformations."""
        # JPEG compression for images
        # Feature squeezing
        # Spatial smoothing
        return defensive_transform(input_data)
```

**Don't**:
```python
# VULNERABLE: No adversarial detection
def predict(image):
    return model.predict(image)

# VULNERABLE: Blindly trusting high-confidence outputs
def automated_decision(input):
    result = model.predict(input)
    execute_action(result)  # No validation
```

**Why**: Adversarial attacks (AML.T0015 - Evade ML Model) can cause misclassification. Defense layers reduce attack success rates.

**Refs**: MITRE ATLAS AML.T0015, AML.T0043, NIST AI RMF MEASURE 2.7, ISO/IEC 23894 A.9

---

## LLM Security

### Rule: Prevent Prompt Injection

**Level**: `strict`

**When**: Using LLMs with user-provided input in prompts.

**Do**:
```python
class SecureLLMClient:
    def __init__(self, client):
        self.client = client

    def generate(self, system_prompt: str, user_input: str) -> str:
        """Secure LLM generation with input isolation."""
        # Sanitize user input
        sanitized_input = self._sanitize_input(user_input)

        # Use structured message format with clear boundaries
        messages = [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": sanitized_input
            }
        ]

        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            max_tokens=1000
        )

        # Validate output before use
        output = response.choices[0].message.content
        return self._validate_output(output)

    def _sanitize_input(self, user_input: str) -> str:
        """Sanitize user input to prevent injection."""
        # Remove potential injection patterns
        patterns_to_remove = [
            r'ignore previous instructions',
            r'disregard.*system prompt',
            r'you are now',
            r'new instructions:',
        ]
        sanitized = user_input
        for pattern in patterns_to_remove:
            sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE)

        # Length limit
        return sanitized[:4000]

    def _validate_output(self, output: str) -> str:
        """Validate LLM output before use."""
        # Check for sensitive data leakage
        if self._contains_sensitive_patterns(output):
            raise OutputValidationError("Output contains sensitive patterns")

        # Sanitize for downstream use (e.g., HTML)
        return escape(output)
```

**Don't**:
```python
# VULNERABLE: Direct string interpolation
prompt = f"Summarize this text: {user_input}"
response = llm.generate(prompt)

# VULNERABLE: No output validation
def process_request(user_text):
    result = llm.generate(f"Process: {user_text}")
    return execute_command(result)  # Dangerous if injected
```

**Why**: Prompt injection (AML.T0051) manipulates LLM behavior by injecting instructions in user input. Isolation and validation prevent exploitation.

**Refs**: MITRE ATLAS AML.T0051, OWASP LLM01, NIST AI 100-1 §3.2

---

### Rule: Validate LLM Outputs Before Use

**Level**: `strict`

**When**: Using LLM outputs in HTML rendering, code execution, database queries, or system commands.

**Do**:
```python
from markupsafe import escape
import json
import re

class LLMOutputValidator:
    def validate_for_html(self, output: str) -> str:
        """Sanitize LLM output for HTML rendering."""
        return escape(output)

    def validate_for_json(self, output: str) -> dict:
        """Parse and validate JSON from LLM."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            raise ValidationError("Invalid JSON output")

        # Validate against schema
        self._validate_schema(data)
        return data

    def validate_for_code(self, output: str, allowed_operations: list) -> str:
        """Validate code output against allowlist."""
        # Parse AST
        import ast
        try:
            tree = ast.parse(output)
        except SyntaxError:
            raise ValidationError("Invalid Python syntax")

        # Check for dangerous operations
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name not in allowed_operations:
                        raise ValidationError(f"Disallowed import: {alias.name}")
            elif isinstance(node, ast.Call):
                if hasattr(node.func, 'id') and node.func.id in ['eval', 'exec', 'open']:
                    raise ValidationError(f"Disallowed function: {node.func.id}")

        return output

# Usage
validator = LLMOutputValidator()

@app.route('/generate-summary')
def generate_summary():
    summary = llm.generate(prompt)
    safe_html = validator.validate_for_html(summary)
    return render_template('summary.html', content=safe_html)
```

**Don't**:
```python
# VULNERABLE: Direct HTML rendering
@app.route('/summary')
def summary():
    output = llm.generate(prompt)
    return f"<div>{output}</div>"  # XSS if output contains HTML/JS

# VULNERABLE: Executing LLM-generated code
def run_analysis():
    code = llm.generate("Write Python code to analyze data")
    exec(code)  # Arbitrary code execution
```

**Why**: LLMs can be manipulated to generate malicious content. Output validation prevents XSS, injection, and code execution attacks.

**Refs**: OWASP LLM02, OWASP A03:2025, NIST AI 100-1 §3.2

---

## Infrastructure Security

### Rule: Isolate ML Inference Environments

**Level**: `warning`

**When**: Deploying models to production inference systems.

**Do**:
```yaml
# Kubernetes deployment with security context
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-inference
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: inference
        image: ml-inference:v1
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            memory: "4Gi"
            cpu: "2"
            nvidia.com/gpu: "1"
          requests:
            memory: "2Gi"
            cpu: "1"
        volumeMounts:
        - name: model
          mountPath: /models
          readOnly: true
```

```python
# Network isolation for model serving
from flask import Flask
app = Flask(__name__)

# Bind only to internal network
if __name__ == '__main__':
    app.run(host='10.0.0.1', port=8080)  # Internal IP only

# Require authentication for model endpoints
@app.before_request
def require_internal_auth():
    if not verify_internal_token(request.headers.get('X-Internal-Token')):
        abort(401)
```

**Don't**:
```python
# VULNERABLE: Running as root
# Dockerfile
USER root

# VULNERABLE: No resource limits
# Can be exploited for DoS

# VULNERABLE: Exposing model endpoint publicly
app.run(host='0.0.0.0', port=80)
```

**Why**: Isolated environments limit the blast radius of compromises. Resource limits prevent DoS attacks through expensive inference requests.

**Refs**: Google SAIF Infrastructure Security, NIST AI RMF MANAGE 1.1, ISO/IEC 23894 A.11 Security

---

## Monitoring & Logging

### Rule: Monitor for ML-Specific Attacks

**Level**: `warning`

**When**: Operating ML systems in production.

**Do**:
```python
import time
from collections import defaultdict

class MLSecurityMonitor:
    def __init__(self):
        self.query_patterns = defaultdict(list)
        self.alert_threshold = 100

    def log_inference(self, user_id: str, input_data, output, latency: float):
        """Log inference with security-relevant metadata."""
        log_entry = {
            'timestamp': time.time(),
            'user_id': user_id,
            'input_hash': hash(input_data.tobytes()),
            'input_norm': float(np.linalg.norm(input_data)),
            'output_confidence': float(output['confidence']),
            'latency_ms': latency * 1000
        }

        # Track query patterns per user
        self.query_patterns[user_id].append(log_entry)

        # Detect extraction attacks (many similar queries)
        if len(self.query_patterns[user_id]) > self.alert_threshold:
            if self._detect_extraction_pattern(user_id):
                self._alert_extraction_attack(user_id)

        security_logger.info(json.dumps(log_entry))

    def _detect_extraction_pattern(self, user_id: str) -> bool:
        """Detect model extraction attack patterns."""
        queries = self.query_patterns[user_id]

        # Check for systematic input exploration
        recent = queries[-100:]

        # Clustering of input hashes (similar inputs)
        # High query volume in short time
        # Boundary probing patterns

        return self._analyze_patterns(recent)

    def _alert_extraction_attack(self, user_id: str):
        """Alert on potential model extraction."""
        security_logger.critical(
            f"Potential model extraction attack detected",
            extra={'user_id': user_id, 'query_count': len(self.query_patterns[user_id])}
        )
        # Trigger automated response
        self._block_user(user_id)
```

**Don't**:
```python
# VULNERABLE: No logging
@app.route('/predict')
def predict():
    return model.predict(request.json)

# VULNERABLE: Logging without security analysis
logger.info(f"Prediction made")  # No user, no patterns
```

**Why**: ML attacks like model extraction and adversarial inputs require specialized monitoring. Standard security logs miss these patterns.

**Refs**: MITRE ATLAS AML.T0040, NIST AI RMF MEASURE 1.1, Google SAIF Detection and Response

---

## Quick Reference

| Rule | Level | MITRE ATLAS | Primary Standard |
|------|-------|-------------|------------------|
| Validate Training Data | strict | AML.T0020 | NIST AI RMF MAP 1.5 |
| Protect Sensitive Data | strict | AML.T0024 | ISO/IEC 23894 A.8 |
| Secure Model Artifacts | strict | AML.T0000 | Google SAIF Model |
| Model Access Controls | strict | AML.T0040 | NIST AI RMF MANAGE 1.3 |
| Validate Model Inputs | strict | AML.T0043 | ISO/IEC 23894 A.9 |
| Adversarial Detection | warning | AML.T0015 | NIST AI RMF MEASURE 2.7 |
| Prevent Prompt Injection | strict | AML.T0051 | OWASP LLM01 |
| Validate LLM Outputs | strict | - | OWASP LLM02 |
| Isolate Inference | warning | - | Google SAIF Infrastructure |
| ML Attack Monitoring | warning | AML.T0040 | NIST AI RMF MEASURE 1.1 |

---

## Version History

- **v1.0.0** - Initial release based on NIST AI RMF, ISO/IEC 23894, MITRE ATLAS, Google SAIF
