# Rust Security Rules

Security rules for Rust development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Memory Safety

### Rule: Avoid Unsafe Code Unless Necessary

**Level**: `strict`

**When**: Considering use of unsafe blocks.

**Do**:
```rust
// Safe alternatives exist for most use cases
use std::ptr::NonNull;

// Use safe abstractions
fn get_element(slice: &[i32], index: usize) -> Option<&i32> {
    slice.get(index)
}

// If unsafe is needed, document why and minimize scope
/// # Safety
/// Caller must ensure ptr is valid and properly aligned
unsafe fn read_value(ptr: *const i32) -> i32 {
    // Minimal unsafe block
    *ptr
}
```

**Don't**:
```rust
// VULNERABLE: Unnecessary unsafe
fn get_element(slice: &[i32], index: usize) -> i32 {
    unsafe { *slice.get_unchecked(index) }
}

// VULNERABLE: Large unsafe blocks
unsafe {
    // ... hundreds of lines
}
```

**Why**: Unsafe bypasses Rust's memory safety guarantees, enabling buffer overflows and use-after-free.

**Refs**: CWE-119, CWE-416

---

### Rule: Validate Slice and Array Indices

**Level**: `strict`

**When**: Accessing elements by index.

**Do**:
```rust
fn process_item(items: &[String], index: usize) -> Result<&str, Error> {
    items
        .get(index)
        .map(|s| s.as_str())
        .ok_or(Error::IndexOutOfBounds)
}

// Or use pattern matching
if let Some(item) = items.get(index) {
    process(item);
}
```

**Don't**:
```rust
// VULNERABLE: Panics on out-of-bounds
fn process_item(items: &[String], index: usize) -> &str {
    &items[index]
}
```

**Why**: Out-of-bounds access causes panics, which can be DoS in servers.

**Refs**: CWE-129

---

## Input Validation

### Rule: Validate External Input

**Level**: `strict`

**When**: Processing user input or external data.

**Do**:
```rust
use validator::Validate;

#[derive(Validate)]
struct UserInput {
    #[validate(email)]
    email: String,
    #[validate(length(min = 8, max = 128))]
    password: String,
}

fn create_user(input: UserInput) -> Result<User, ValidationError> {
    input.validate()?;
    // Process validated input
    Ok(User::new(input.email, input.password))
}
```

**Don't**:
```rust
// VULNERABLE: No validation
fn create_user(email: String, password: String) -> User {
    User::new(email, password)
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## SQL Security

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```rust
use sqlx::query;

async fn get_user(pool: &PgPool, email: &str) -> Result<User, Error> {
    sqlx::query_as!(
        User,
        "SELECT id, email, name FROM users WHERE email = $1",
        email
    )
    .fetch_one(pool)
    .await
}

// With diesel
use diesel::prelude::*;

fn get_user(conn: &mut PgConnection, user_email: &str) -> QueryResult<User> {
    users::table
        .filter(users::email.eq(user_email))
        .first(conn)
}
```

**Don't**:
```rust
// VULNERABLE: SQL injection
async fn get_user(pool: &PgPool, email: &str) -> Result<User, Error> {
    let query = format!("SELECT * FROM users WHERE email = '{}'", email);
    sqlx::query_as(&query).fetch_one(pool).await
}
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Cryptography

### Rule: Use Secure Random Numbers

**Level**: `strict`

**When**: Generating tokens, keys, or security-sensitive values.

**Do**:
```rust
use rand::{rngs::OsRng, RngCore};
use base64::{Engine, engine::general_purpose::URL_SAFE};

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE.encode(bytes)
}

// For UUIDs
use uuid::Uuid;
let id = Uuid::new_v4();
```

**Don't**:
```rust
use rand::rngs::SmallRng;
use rand::SeedableRng;

// VULNERABLE: Predictable seed
fn generate_token() -> u64 {
    let mut rng = SmallRng::seed_from_u64(42);
    rng.next_u64()
}
```

**Why**: Predictable random numbers allow attackers to guess tokens and session IDs.

**Refs**: CWE-330, CWE-338

---

### Rule: Use Established Crypto Libraries

**Level**: `strict`

**When**: Implementing cryptographic operations.

**Do**:
```rust
// Password hashing with argon2
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;

fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).ok();
    parsed_hash
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}
```

**Don't**:
```rust
use sha2::{Sha256, Digest};

// VULNERABLE: Fast hash, no salt
fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

**Why**: Rolling your own crypto or using weak hashes leads to broken authentication.

**Refs**: CWE-916, CWE-327

---

## Error Handling

### Rule: Don't Expose Internal Errors

**Level**: `warning`

**When**: Returning errors to clients.

**Do**:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("User not found")]
    NotFound,
    #[error("Invalid input")]
    Validation(String),
    #[error("Internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            AppError::Validation(_) => (StatusCode::BAD_REQUEST, "Invalid input"),
            AppError::Internal(e) => {
                tracing::error!("Internal error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        };
        (status, message).into_response()
    }
}
```

**Don't**:
```rust
// VULNERABLE: Exposes internal details
async fn handler() -> Result<Json<User>, String> {
    get_user().map_err(|e| e.to_string())  // Leaks DB errors
}
```

**Why**: Internal errors reveal database structure, file paths, and system details.

**Refs**: CWE-209, OWASP A05:2025

---

## Command Execution

### Rule: Avoid Shell Commands with User Input

**Level**: `strict`

**When**: Executing external commands.

**Do**:
```rust
use std::process::Command;

fn list_files(dir: &str) -> Result<String, Error> {
    // Validate input
    if dir.contains("..") {
        return Err(Error::InvalidPath);
    }

    let output = Command::new("ls")
        .arg("-la")
        .arg(dir)  // Passed as argument, not shell
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

**Don't**:
```rust
// VULNERABLE: Command injection
fn list_files(dir: &str) -> Result<String, Error> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ls -la {}", dir))
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

**Why**: Shell metacharacters allow executing arbitrary commands.

**Refs**: CWE-78, OWASP A03:2025

---

## Serialization

### Rule: Validate Deserialized Data

**Level**: `strict`

**When**: Deserializing external data.

**Do**:
```rust
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
struct UserRequest {
    #[validate(email)]
    email: String,
    #[validate(range(min = 0, max = 150))]
    age: u8,
}

async fn create_user(Json(input): Json<UserRequest>) -> Result<Json<User>, Error> {
    input.validate()?;  // Validate after deserialization
    // Process
}
```

**Don't**:
```rust
// VULNERABLE: No validation after deserialization
async fn create_user(Json(input): Json<UserRequest>) -> Json<User> {
    // Directly use untrusted data
}
```

**Why**: Serde only checks types, not business rules. Additional validation is required.

**Refs**: CWE-20, CWE-502

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Minimize unsafe | strict | CWE-119 |
| Bounds checking | strict | CWE-129 |
| Input validation | strict | CWE-20 |
| Parameterized queries | strict | CWE-89 |
| Secure randomness | strict | CWE-330 |
| Proper crypto | strict | CWE-916 |
| Safe error handling | warning | CWE-209 |
| No shell injection | strict | CWE-78 |
| Validate deserialized data | strict | CWE-502 |

---

## Version History

- **v1.0.0** - Initial Rust security rules
