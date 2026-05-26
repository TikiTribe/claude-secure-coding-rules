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

# Safe: Use safetensors format (no pickle); pin to a verified SHA
model = AutoModel.from_pretrained(
    "model-name",
    revision="a265f773",   # Pin to a known-good commit SHA
    trust_remote_code=False,
    use_safetensors=True   # Avoids pickle deserialization
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
# In PyTorch 2.0+ use weights_only=True as a partial mitigation,
# but prefer safetensors-format models instead of torch.load() entirely.
import torch
model = torch.load("model.pt")  # Can execute code

# VULNERABLE: Unverified model source, no revision pin
model = AutoModel.from_pretrained(random_github_model)
```

**Why**: `trust_remote_code=True` allows model creators to execute arbitrary Python code on your system. Pickle files can also contain malicious code. Unpinned revision= allows a supply-chain attacker to swap the model after you reviewed it.

**Refs**: OWASP LLM03:2025 (Supply Chain Vulnerabilities), MITRE ATLAS AML.T0011, CWE-502

---

### Rule: Verify Model Integrity

**Level**: `strict`

**When**: Loading models for production use.

**Do**:
```python
from huggingface_hub import hf_hub_download, model_info
import hashlib

TRUSTED_AUTHORS = {"google", "facebook", "microsoft", "openai", "meta-llama"}

# Safe: Verify model metadata using actual ModelInfo fields.
# HF Hub does not expose a single security_status signal; use tags,
# gated/private status, and revision SHA pinning as the composite check.
def verify_model(model_id: str, expected_sha: str):
    info = model_info(model_id, revision=expected_sha)

    # Reject disabled repositories
    if getattr(info, "disabled", False):
        raise ValueError(f"Model {model_id} is disabled on Hub")

    # Warn on unverified authors
    if info.author not in TRUSTED_AUTHORS:
        # Gated models require Hub approval; still prefer allowlist + tag review
        if not getattr(info, "gated", False):
            raise ValueError(f"Untrusted and ungated author: {info.author}")

    # Inspect community-applied tags for known safety flags
    bad_tags = {"malicious", "unsafe", "flagged"}
    if info.tags and bad_tags.intersection(set(info.tags)):
        raise ValueError(f"Model {model_id} carries a safety-concern tag")

    return info

# Safe: Pin to a verified SHA so the artifact cannot be swapped after review
model = AutoModel.from_pretrained(
    "bert-base-uncased",
    revision="a265f773",        # Specific commit SHA
    trust_remote_code=False,
    use_safetensors=True
)

# Safe: Verify file checksum for downloaded artifacts
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
# VULNERABLE: Always use latest (could be compromised after you reviewed it)
model = AutoModel.from_pretrained("model-name")  # No revision pinned

# VULNERABLE: Dead guard -- ModelInfo has no security_status attribute;
# hasattr() always returns False and the check never executes
info = model_info(model_id)
if hasattr(info, "security_status"):          # Never True
    if info.security_status == "unsafe":      # Dead code
        raise ValueError("unsafe")

# VULNERABLE: No integrity verification
model_path = hf_hub_download(model_id, "model.bin")
model = torch.load(model_path)  # Could be tampered

# VULNERABLE: User-provided model ID without allowlist
model = AutoModel.from_pretrained(user_input)  # Supply chain attack
```

**Why**: Without SHA pinning, attackers can replace a model with a poisoned version after your initial review. `info.security_status` does not exist in any released version of `huggingface_hub`; relying on it creates a false sense of protection. Use `info.disabled`, `info.gated`, and `info.tags` as the available safety signals.

**Refs**: OWASP LLM03:2025 (Supply Chain Vulnerabilities), MITRE ATLAS AML.T0020, CWE-494

---

## Tokenizer Security

### Rule: Validate Tokenizer Inputs

**Level**: `strict`

**When**: Processing user input with tokenizers.

**Do**:
```python
from transformers import AutoTokenizer

# Pin revision to verified SHA; tokenizer.json from untrusted sources
# can alter vocabulary and special-token handling in non-obvious ways.
tokenizer = AutoTokenizer.from_pretrained(
    "bert-base-uncased",
    revision="a265f773",
    trust_remote_code=False
)

# Safe: Limit input length
def safe_tokenize(text: str, max_length: int = 512):
    # Validate input
    if not isinstance(text, str):
        raise ValueError("Input must be string")

    # Limit input size before tokenization (rough char limit prevents
    # adversarial tokenization that produces far more tokens than chars)
    text = text[:max_length * 4]

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

**Why**: Malicious inputs can exploit tokenizer behavior for DoS attacks (unbounded consumption) or inject special tokens to manipulate model behavior. An untrusted `tokenizer.json` can redefine the vocabulary and attack surface independently of `trust_remote_code`.

**Refs**: OWASP LLM10:2025 (Unbounded Consumption), CWE-400, CWE-20

---

## Inference Security

### Rule: Validate Model Outputs

**Level**: `strict`

**When**: Using model outputs in applications.

**Do**:
```python
import torch
from transformers import pipeline, AutoModel, AutoTokenizer

# Safe: pipeline() also requires trust_remote_code=False and a pinned revision
safe_pipe = pipeline(
    "text-generation",
    model="gpt2",
    revision="e7da7f2",
    trust_remote_code=False
)

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

    # Validate output length
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

# VULNERABLE: pipeline() with trust_remote_code enabled
pipe = pipeline("text-generation", model=user_model, trust_remote_code=True)
```

**Why**: Uncontrolled generation exhausts resources. Raw logits can leak training data distribution. Executing model output is remote code execution. `pipeline()` accepts the same `trust_remote_code` parameter as `from_pretrained` and must be restricted.

**Refs**: OWASP LLM05:2025 (Improper Output Handling), OWASP LLM10:2025 (Unbounded Consumption), MITRE ATLAS AML.T0024, CWE-200

---

## Fine-tuning Security

### Rule: Secure Training Data and Process

**Level**: `strict`

**When**: Fine-tuning models on custom data.

**Do**:
```python
from transformers import Trainer, TrainingArguments
from datasets import load_dataset
from pathlib import Path

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

# Safe: Checkpoint with guaranteed safetensors format.
# safe_serialization=True is explicit and version-independent;
# in transformers >= 4.37 the default already prefers safetensors
# when the safetensors package is installed, but explicit is better.
def save_secure_checkpoint(model, path: str):
    model.save_pretrained(
        path,
        safe_serialization=True  # Guarantees safetensors regardless of environment
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

# VULNERABLE: Omitting safe_serialization; pickle .pt files are RCE vectors
torch.save(model.state_dict(), "model.pt")  # Pickle format
```

**Why**: Poisoned training data creates backdoors. Insecure serialization enables supply-chain attacks. `torch.load()` without `weights_only=True` (PyTorch 2.0+) executes arbitrary code; prefer safetensors-format checkpoints via `safe_serialization=True`.

**Refs**: MITRE ATLAS AML.T0020, OWASP LLM03:2025 (Supply Chain Vulnerabilities), CWE-502

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
| Disable remote code execution | strict | OWASP LLM03:2025, CWE-502 |
| Verify model integrity | strict | OWASP LLM03:2025, CWE-494 |
| Validate tokenizer inputs | strict | OWASP LLM10:2025, CWE-400 |
| Validate model outputs | strict | OWASP LLM05:2025, CWE-200 |
| Secure training process | strict | AML.T0020, CWE-502 |
| Secure Hub authentication | strict | CWE-798, CWE-532 |

---

## Coverage Notes

- `weights_only=True` (`torch.load`, PyTorch 2.0+): partial mitigation noted in Don't examples; safetensors is the recommended path.
- `pipeline()`: covered in Inference Security rule; requires `trust_remote_code=False` and a pinned `revision=`.
- `tokenizer.json` attack surface: addressed in Tokenizer Security rule; an untrusted tokenizer file is a distinct risk from `trust_remote_code`.
- PEFT/LoRA adapter security (adapter weight leakage, injection poisoning): not covered in v2.0; deferred to v2.1.

---

## Version History

- **v2.0.0** - Remapped OWASP LLM refs to 2025 taxonomy; replaced dead `info.security_status` guard with real ModelInfo fields; added `revision=` SHA pinning throughout; corrected AML.T0010 to AML.T0011; updated `save_pretrained` comment for transformers >= 4.37; added `pipeline()` and `tokenizer.json` coverage notes
- **v1.0.0** - Initial Hugging Face Transformers security rules
