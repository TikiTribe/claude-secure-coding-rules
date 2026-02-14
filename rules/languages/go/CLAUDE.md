# Go Security Rules

Security rules for Go development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Input Validation

### Rule: Validate and Sanitize User Input

**Level**: `strict`

**When**: Processing user-provided data.

**Do**:
```go
import (
    "regexp"
    "unicode/utf8"
)

func validateUsername(username string) error {
    if !utf8.ValidString(username) {
        return errors.New("invalid UTF-8")
    }

    if len(username) < 3 || len(username) > 50 {
        return errors.New("username must be 3-50 characters")
    }

    matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
    if !matched {
        return errors.New("invalid characters in username")
    }

    return nil
}
```

**Don't**:
```go
func createUser(username string) {
    // VULNERABLE: No validation
    db.Exec("INSERT INTO users (name) VALUES (?)", username)
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## SQL Security

### Rule: Use Parameterized Queries in Go database/sql

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```go
import "database/sql"

func getUser(db *sql.DB, email string) (*User, error) {
    var user User
    err := db.QueryRow(
        "SELECT id, email, name FROM users WHERE email = $1",
        email,
    ).Scan(&user.ID, &user.Email, &user.Name)

    return &user, err
}

// With sqlx
func getUsers(db *sqlx.DB, status string) ([]User, error) {
    var users []User
    err := db.Select(&users,
        "SELECT * FROM users WHERE status = ?",
        status,
    )
    return users, err
}
```

**Don't**:
```go
// VULNERABLE: SQL injection
query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
rows, err := db.Query(query)

// VULNERABLE: String concatenation
db.Query("SELECT * FROM users WHERE id = " + userID)
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Command Execution

### Rule: Avoid Shell Commands with User Input

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```go
import "os/exec"

func listFiles(dir string) ([]byte, error) {
    // Validate input
    if strings.Contains(dir, "..") {
        return nil, errors.New("invalid directory")
    }

    // Use exec.Command with arguments (no shell)
    cmd := exec.Command("ls", "-la", dir)
    return cmd.Output()
}

// If shell is needed, validate strictly
func runScript(name string) error {
    if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(name) {
        return errors.New("invalid script name")
    }
    return exec.Command("bash", "-c", "./scripts/"+name+".sh").Run()
}
```

**Don't**:
```go
// VULNERABLE: Command injection
cmd := exec.Command("bash", "-c", "ls "+userInput)

// VULNERABLE: Shell metacharacters
exec.Command("sh", "-c", fmt.Sprintf("grep %s file.txt", pattern))
```

**Why**: Shell metacharacters (;, |, &&) allow executing arbitrary commands.

**Refs**: CWE-78, OWASP A03:2025

---

## File Operations

### Rule: Prevent Path Traversal

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```go
import (
    "path/filepath"
    "strings"
)

const uploadsDir = "/app/uploads"

func safeReadFile(filename string) ([]byte, error) {
    // Clean and resolve path
    cleanPath := filepath.Clean(filename)
    absPath := filepath.Join(uploadsDir, cleanPath)

    // Ensure path is within uploads directory
    if !strings.HasPrefix(absPath, uploadsDir+string(filepath.Separator)) {
        return nil, errors.New("path traversal detected")
    }

    return os.ReadFile(absPath)
}
```

**Don't**:
```go
// VULNERABLE: Path traversal
func readFile(filename string) ([]byte, error) {
    return os.ReadFile(filepath.Join("/uploads", filename))
}
```

**Why**: Path traversal (../) allows reading sensitive files like /etc/passwd.

**Refs**: CWE-22, OWASP A01:2025

---

## Cryptography

### Rule: Use Secure Random Numbers

**Level**: `strict`

**When**: Generating tokens, keys, or security-sensitive values.

**Do**:
```go
import (
    "crypto/rand"
    "encoding/base64"
)

func generateToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

func generateSecureID() (string, error) {
    uuid := make([]byte, 16)
    if _, err := rand.Read(uuid); err != nil {
        return "", err
    }
    return fmt.Sprintf("%x", uuid), nil
}
```

**Don't**:
```go
import "math/rand"

// VULNERABLE: Predictable random
func generateToken() string {
    rand.Seed(time.Now().UnixNano())
    return fmt.Sprintf("%d", rand.Int())
}
```

**Why**: math/rand is predictable. Attackers can guess tokens and session IDs.

**Refs**: CWE-330, CWE-338

---

### Rule: Hash Passwords with bcrypt

**Level**: `strict`

**When**: Storing user passwords.

**Do**:
```go
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword(
        []byte(password),
        bcrypt.DefaultCost,
    )
    return string(bytes), err
}

func checkPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

**Don't**:
```go
import "crypto/sha256"

// VULNERABLE: Fast hash, no salt
func hashPassword(password string) string {
    hash := sha256.Sum256([]byte(password))
    return fmt.Sprintf("%x", hash)
}
```

**Why**: Fast hashes without salt are vulnerable to rainbow tables and GPU cracking.

**Refs**: CWE-916, OWASP A02:2025

---

## HTTP Security

### Rule: Set Timeouts on HTTP Clients

**Level**: `warning`

**When**: Making HTTP requests.

**Do**:
```go
import (
    "net/http"
    "time"
)

var httpClient = &http.Client{
    Timeout: 10 * time.Second,
    Transport: &http.Transport{
        TLSHandshakeTimeout:   5 * time.Second,
        ResponseHeaderTimeout: 5 * time.Second,
        IdleConnTimeout:       90 * time.Second,
    },
}

func fetchData(url string) (*http.Response, error) {
    return httpClient.Get(url)
}
```

**Don't**:
```go
// VULNERABLE: No timeout (can hang forever)
resp, err := http.Get(url)
```

**Why**: Missing timeouts enable DoS attacks and resource exhaustion.

**Refs**: CWE-400

---

### Rule: Validate TLS Certificates

**Level**: `strict`

**When**: Making HTTPS requests.

**Do**:
```go
// Default client validates certificates
client := &http.Client{}

// Custom TLS config with validation
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}
```

**Don't**:
```go
// VULNERABLE: Disables certificate validation
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,
}
```

**Why**: Disabled certificate validation enables man-in-the-middle attacks.

**Refs**: CWE-295, OWASP A02:2025

---

## Error Handling

### Rule: Don't Expose Internal Errors

**Level**: `warning`

**When**: Returning errors to clients.

**Do**:
```go
func handler(w http.ResponseWriter, r *http.Request) {
    user, err := getUser(r.Context(), userID)
    if err != nil {
        // Log full error internally
        log.Printf("Error getting user %s: %v", userID, err)

        // Return safe message to client
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
}
```

**Don't**:
```go
func handler(w http.ResponseWriter, r *http.Request) {
    user, err := getUser(r.Context(), userID)
    if err != nil {
        // VULNERABLE: Exposes internal details
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}
```

**Why**: Internal errors reveal database structure, file paths, and system details.

**Refs**: CWE-209, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Input validation | strict | CWE-20 |
| Parameterized queries | strict | CWE-89 |
| Safe command execution | strict | CWE-78 |
| Path traversal prevention | strict | CWE-22 |
| Crypto randomness | strict | CWE-330 |
| bcrypt passwords | strict | CWE-916 |
| HTTP timeouts | warning | CWE-400 |
| TLS validation | strict | CWE-295 |
| Safe error handling | warning | CWE-209 |

---

## Version History

- **v1.0.0** - Initial Go security rules
