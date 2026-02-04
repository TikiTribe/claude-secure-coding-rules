# Hugging Face Transformers Security Rules

Security rules for Hugging Face Transformers development in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Model Loading Security

### Rule: Disable Remote Code Execution

**Level**: `strict`

**When**: Loading models from Hugging Face Hub.

**Do**:
```python
from transformers import AutoModel, AutoTokenizer

# Safe: Disable remote code execution
model = AutoModel.from_pretrained(
    "bert-base-uncased",
    trust_remote_code=False  # CRITICAL: Never trust remote code
)

tokenizer = AutoTokenizer.from_pretrained(
    "bert-base-uncased",
    trust_remote_code=False
)

# Safe: Use safetensors format (no pickle)
model = AutoModel.from_pretrained(
    "model-name",
    trust_remote_code=False,
    use_safetensors=True  # Safe serialization format
)

# Safe: Load from verified organization
TRUSTED_ORGS = ["google", "facebook", "microsoft", "openai", "meta-llama"]

def load_verified_model(model_id: str):
    org = model_id.split("/")[0] if "/" in model_id else None
    if org and org not in TRUSTED_ORGS:
        raise ValueError(f"Untrusted organization: {org}")

    return AutoModel.from_pretrained(
        model_id,
        trust_remote_code=False,
        use_safetensors=True
    )
```

**Don't**:
```python
# VULNERABLE: Remote code execution enabled
model = AutoModel.from_pretrained(
    user_provided_model,
    trust_remote_code=True  # Executes arbitrary Python!
)

# VULNERABLE: Loading pickle files (RCE risk)
import torch
model = torch.load("model.pt")  # Can execute code

# VULNERABLE: Unverified model source
model = AutoModel.from_pretrained(random_github_model)
```

**Why**: `trust_remote_code=True` allows model creators to execute arbitrary Python code on your system. Pickle files can also contain malicious code.

**Refs**: OWASP LLM05, MITRE ATLAS AML.T0010, CWE-502

---

### Rule: Verify Model Integrity

**Level**: `strict`

**When**: Loading models for production use.

**Do**:
```python
from huggingface_hub import hf_hub_download, model_info
import hashlib

# Safe: Verify model metadata
def verify_model(model_id: str, revision: str = "main"):
    info = model_info(model_id, revision=revision)

    # Check for security advisories
    if hasattr(info, 'security_status'):
        if info.security_status == "unsafe":
            raise ValueError(f"Model {model_id} has security issues")

    # Verify organization
    if info.author not in TRUSTED_AUTHORS:
        print(f"Warning: Unverified author {info.author}")

    return info

# Safe: Pin to specific revision
model = AutoModel.from_pretrained(
    "bert-base-uncased",
    revision="a265f773"  # Specific commit hash
)

# Safe: Verify file checksum
def download_verified(model_id: str, filename: str, expected_hash: str):
    path = hf_hub_download(model_id, filename)

    with open(path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    if actual_hash != expected_hash:
        raise ValueError("Model file integrity check failed")

    return path
```

**Don't**:
```python
# VULNERABLE: Always use latest (could be compromised)
model = AutoModel.from_pretrained("model-name")  # No revision pinned

# VULNERABLE: No integrity verification
model_path = hf_hub_download(model_id, "model.bin")
model = torch.load(model_path)  # Could be tampered

# VULNERABLE: User-provided model ID
model = AutoModel.from_pretrained(user_input)  # Supply chain attack
```

**Why**: Without verification, attackers can replace models with poisoned versions that produce malicious outputs or leak data.

**Refs**: OWASP LLM05, MITRE ATLAS AML.T0020, CWE-494

---

## Tokenizer Security

### Rule: Validate Tokenizer Inputs

**Level**: `strict`

**When**: Processing user input with tokenizers.

**Do**:
```python
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

# Safe: Limit input length
def safe_tokenize(text: str, max_length: int = 512):
    # Validate input
    if not isinstance(text, str):
        raise ValueError("Input must be string")

    # Limit input size before tokenization
    text = text[:max_length * 4]  # Rough char limit

    tokens = tokenizer(
        text,
        max_length=max_length,
        truncation=True,
        padding="max_length",
        return_tensors="pt"
    )

    return tokens

# Safe: Handle special tokens carefully
def tokenize_user_input(user_text: str):
    # Remove potential special token injections
    cleaned = user_text.replace("[CLS]", "").replace("[SEP]", "")
    cleaned = cleaned.replace("<s>", "").replace("</s>", "")

    return tokenizer(
        cleaned,
        add_special_tokens=True,  # Tokenizer adds them properly
        max_length=512,
        truncation=True
    )
```

**Don't**:
```python
# VULNERABLE: No length limits
tokens = tokenizer(user_input)  # Could be huge

# VULNERABLE: Direct concatenation with special tokens
text = f"[CLS] {user_input} [SEP]"  # User can inject tokens
tokens = tokenizer(text, add_special_tokens=False)

# VULNERABLE: No truncation
tokens = tokenizer(text, truncation=False)  # Memory exhaustion
```

**Why**: Malicious inputs can exploit tokenizer behavior for DoS attacks or inject special tokens to manipulate model behavior.

**Refs**: OWASP LLM04, CWE-400, CWE-20

---

## Inference Security

### Rule: Validate Model Outputs

**Level**: `strict`

**When**: Using model outputs in applications.

**Do**:
```python
import torch
from transformers import pipeline

# Safe: Validate generation outputs
def safe_generate(model, tokenizer, prompt: str, max_tokens: int = 100):
    inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            pad_token_id=tokenizer.eos_token_id,
            # Safety controls
            num_return_sequences=1,
            early_stopping=True
        )

    text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    # Validate output
    if len(text) > max_tokens * 10:
        text = text[:max_tokens * 10]

    return text

# Safe: Classification with confidence filtering
def safe_classify(text: str, classifier, threshold: float = 0.8):
    result = classifier(text[:1000])

    # Only return high-confidence results
    if result[0]["score"] < threshold:
        return {"label": "uncertain", "score": result[0]["score"]}

    return result[0]
```

**Don't**:
```python
# VULNERABLE: No output limits
outputs = model.generate(
    inputs,
    max_new_tokens=10000  # Huge output, resource exhaustion
)

# VULNERABLE: Direct use without validation
result = model.generate(inputs)
exec(tokenizer.decode(result[0]))  # Never execute output

# VULNERABLE: Exposing raw logits
logits = model(**inputs).logits
return {"logits": logits.tolist()}  # Information leakage
```

**Why**: Uncontrolled generation can exhaust resources, and raw model outputs may leak training data or enable adversarial attacks.

**Refs**: OWASP LLM04, MITRE ATLAS AML.T0024, CWE-200

---

## Fine-tuning Security

### Rule: Secure Training Data and Process

**Level**: `strict`

**When**: Fine-tuning models on custom data.

**Do**:
```python
from transformers import Trainer, TrainingArguments
from datasets import load_dataset

# Safe: Validate training data
def validate_training_data(dataset):
    for example in dataset:
        # Check for data poisoning patterns
        text = example.get("text", "")
        if len(text) > 10000:
            raise ValueError("Example too long")
        if contains_injection_patterns(text):
            raise ValueError("Suspicious content in training data")

    return dataset

# Safe: Secure training configuration
training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=8,
    save_strategy="epoch",
    logging_dir="./logs",
    # Security settings
    report_to=[],  # Don't send data to external services
    push_to_hub=False,  # Don't auto-push
    load_best_model_at_end=True,
    # Resource limits
    max_steps=10000,
    eval_steps=500
)

# Safe: Checkpoint verification
def save_secure_checkpoint(model, path: str):
    # Use safetensors format
    model.save_pretrained(
        path,
        safe_serialization=True  # Saves as safetensors
    )

    # Generate checksum
    import hashlib
    for file in Path(path).glob("*.safetensors"):
        hash_val = hashlib.sha256(file.read_bytes()).hexdigest()
        (file.parent / f"{file.name}.sha256").write_text(hash_val)
```

**Don't**:
```python
# VULNERABLE: Unvalidated training data
dataset = load_dataset("unknown_source/dataset")
trainer.train()  # Could be poisoned

# VULNERABLE: Auto-push to hub
training_args = TrainingArguments(
    push_to_hub=True,
    hub_token="hf_1234567890abcdef"  # Exposed token
)

# VULNERABLE: Pickle serialization
model.save_pretrained(path)  # Default may use pickle
torch.save(model.state_dict(), "model.pt")  # Pickle format
```

**Why**: Poisoned training data can create backdoors in models. Insecure serialization enables supply chain attacks.

**Refs**: MITRE ATLAS AML.T0020, OWASP LLM05, CWE-502

---

## API Security

### Rule: Secure Hugging Face Hub Authentication

**Level**: `strict`

**When**: Interacting with Hugging Face Hub.

**Do**:
```python
import os
from huggingface_hub import login, HfApi

# Safe: Token from environment
token = os.environ.get("HF_TOKEN")
if not token:
    raise ValueError("HF_TOKEN not configured")

login(token=token, add_to_git_credential=False)

# Safe: Scoped tokens for different operations
READ_TOKEN = os.environ.get("HF_READ_TOKEN")  # Read-only
WRITE_TOKEN = os.environ.get("HF_WRITE_TOKEN")  # Write access

def download_model(model_id: str):
    return AutoModel.from_pretrained(
        model_id,
        token=READ_TOKEN  # Use read-only token
    )

def upload_model(model, repo_id: str):
    model.push_to_hub(
        repo_id,
        token=WRITE_TOKEN,
        private=True  # Keep models private by default
    )
```

**Don't**:
```python
# VULNERABLE: Hardcoded token
login(token="hf_AbCdEfGhIjKlMnOp")

# VULNERABLE: Token in code
model.push_to_hub("my-model", token="hf_1234567890abcdef")

# VULNERABLE: Add token to git credentials
login(token=token, add_to_git_credential=True)  # Persists token

# VULNERABLE: Public upload of sensitive model
model.push_to_hub(repo_id, private=False)  # Publicly accessible
```

**Why**: Exposed tokens allow unauthorized access to private models and enable malicious uploads to your account.

**Refs**: CWE-798, CWE-532, OWASP A07:2025

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Disable remote code execution | strict | OWASP LLM05, CWE-502 |
| Verify model integrity | strict | OWASP LLM05, CWE-494 |
| Validate tokenizer inputs | strict | OWASP LLM04, CWE-400 |
| Validate model outputs | strict | OWASP LLM04, CWE-200 |
| Secure training process | strict | AML.T0020, CWE-502 |
| Secure Hub authentication | strict | CWE-798, CWE-532 |

---

## Version History

- **v1.0.0** - Initial Hugging Face Transformers security rules
