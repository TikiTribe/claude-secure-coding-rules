# Go Security Rules

Security rules for Go development in Claude Code. Targets Go 1.22+.

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
    "errors"
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
import (
    "errors"
    "os/exec"
    "regexp"
    "strings"
)

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
    "errors"
    "os"
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
    "fmt"
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

### Rule: Wrap and Unwrap Errors with errors.Is / errors.As

**Level**: `warning`

**When**: Comparing, wrapping, or inspecting errors at any call depth.

**Do**:
```go
import (
    "errors"
    "fmt"
)

// Sentinel error defined once
var ErrNotFound = errors.New("record not found")

// Wrap with context while preserving the chain
func fetchRecord(id int) error {
    if id <= 0 {
        return fmt.Errorf("fetchRecord: %w", ErrNotFound)
    }
    return nil
}

// Unwrap correctly — works at any depth in the chain
func handleRecord(id int) {
    err := fetchRecord(id)
    if errors.Is(err, ErrNotFound) {
        // Handle the specific sentinel
        return
    }

    // Inspect the concrete type anywhere in the chain
    var valErr *ValidationError
    if errors.As(err, &valErr) {
        log.Printf("validation failed: field=%s", valErr.Field)
    }
}
```

**Don't**:
```go
// VULNERABLE: == breaks as soon as the error is wrapped
err := fetchRecord(id)
if err == ErrNotFound { // fails when err is wrapped
    return
}

// VULNERABLE: type assertion fails on wrapped errors
if e, ok := err.(*ValidationError); ok { // fails when wrapped
    _ = e
}
```

**Why**: Direct `==` comparison and type assertions ignore the error chain produced by `fmt.Errorf("%w", ...)`. Any caller that wraps the error — a common pattern in layered Go code — makes the comparison silently false. `errors.Is` traverses the full `Unwrap` chain; `errors.As` finds the first matching type at any depth.

**Refs**: CWE-390, OWASP A05:2025

---

## Concurrency

### Rule: Protect Shared State with sync.Mutex; Check for Data Races

**Level**: `strict`

**When**: Sharing mutable state across goroutines or using channels for coordination.

**Do**:
```go
import (
    "sync"
)

// Mutex guards all reads and writes to the shared field
type SafeCounter struct {
    mu    sync.Mutex
    count int
}

func (c *SafeCounter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}

func (c *SafeCounter) Value() int {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.count
}

// Channel-based coordination: send ownership, never share pointers
func producer(ch chan<- []byte) {
    data := make([]byte, 64)
    // populate data ...
    ch <- data // transfer ownership; do not read data after this send
}
```

**Don't**:
```go
// VULNERABLE: Data race — concurrent reads and writes without a lock
type UnsafeCounter struct {
    count int
}

func (c *UnsafeCounter) Increment() {
    c.count++ // race condition
}

// VULNERABLE: Sharing a pointer through a channel without exclusive ownership
func badProducer(shared *[]byte, ch chan<- *[]byte) {
    ch <- shared
    (*shared)[0] = 0 // race: receiver may be reading concurrently
}
```

**Why**: Data races produce undefined behavior: silent corruption, crashes, or exploitable memory states. Go's memory model does not guarantee that unsynchronized reads see any particular write. A race on a map or slice can cause a panic that crashes the whole process.

Run `go test -race ./...` in CI to detect races before they reach production. The race detector adds ~5-10x overhead but is the authoritative tool; `go vet` alone does not find data races.

**Refs**: CWE-362, OWASP A04:2025

---

## Context Propagation

### Rule: Propagate context.Context and Respect Cancellation

**Level**: `warning`

**When**: Writing functions that perform I/O, call downstream services, or run long-lived operations.

**Do**:
```go
import (
    "context"
    "database/sql"
    "errors"
    "net/http"
)

// Accept ctx as the first parameter; pass it through every blocking call
func fetchUser(ctx context.Context, db *sql.DB, id int) (*User, error) {
    var u User
    err := db.QueryRowContext(ctx,
        "SELECT id, name FROM users WHERE id = $1", id,
    ).Scan(&u.ID, &u.Name)
    if err != nil {
        return nil, fmt.Errorf("fetchUser: %w", err)
    }
    return &u, nil
}

// Check ctx.Done() in tight loops or before expensive work
func processItems(ctx context.Context, items []string) error {
    for _, item := range items {
        select {
        case <-ctx.Done():
            // Return the cancellation reason (context.Canceled or
            // context.DeadlineExceeded) so callers can distinguish them
            return fmt.Errorf("processItems: %w", ctx.Err())
        default:
        }
        if err := process(ctx, item); err != nil {
            return err
        }
    }
    return nil
}

// Set deadlines at the entry point; let the context flow from there
func handler(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    user, err := fetchUser(ctx, db, userID)
    if errors.Is(err, context.DeadlineExceeded) {
        http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
        return
    }
    // ...
}
```

**Don't**:
```go
// VULNERABLE: Ignores cancellation — goroutine leaks and resource exhaustion
func fetchUserBad(db *sql.DB, id int) (*User, error) {
    // db.QueryRow has no deadline; runs until the DB responds or the process dies
    row := db.QueryRow("SELECT id, name FROM users WHERE id = $1", id)
    // ...
}

// VULNERABLE: Stores context in a struct — violates the Go context contract
type BadService struct {
    ctx context.Context
}
```

**Why**: A goroutine that ignores `ctx.Done()` keeps running after the caller has given up, holding DB connections, file handles, or locks until the process exits. Leaked goroutines accumulate under load and cause resource exhaustion (CWE-400). Storing a context in a struct hides its lifetime from callers and breaks cancellation propagation across API boundaries.

**Refs**: CWE-400, OWASP A04:2025

---

## Template Security

### Rule: Use html/template, Not text/template, for HTML Output

**Level**: `strict`

**When**: Rendering HTML responses or generating any output that will be interpreted by a browser.

**Do**:
```go
import (
    "html/template"
    "net/http"
)

var tmpl = template.Must(template.New("page").Parse(`
<!DOCTYPE html>
<html>
<body>
  <h1>Hello, {{.Name}}!</h1>
  <p>Your message: {{.Message}}</p>
</body>
</html>
`))

// html/template escapes Name and Message automatically based on context
func renderPage(w http.ResponseWriter, name, message string) {
    data := struct {
        Name    string
        Message string
    }{name, message}

    if err := tmpl.Execute(w, data); err != nil {
        http.Error(w, "render error", http.StatusInternalServerError)
    }
}
```

**Don't**:
```go
import "text/template" // VULNERABLE: No HTML escaping

var tmpl = template.Must(template.New("page").Parse(`
<h1>Hello, {{.Name}}!</h1>
`))

// If Name is `<script>alert(1)</script>`, it renders as-is
func renderPage(w http.ResponseWriter, name string) {
    tmpl.Execute(w, map[string]string{"Name": name})
}
```

**Why**: `text/template` performs no context-aware escaping. An attacker who controls any template variable can inject arbitrary HTML or JavaScript, producing stored or reflected XSS. `html/template` applies context-sensitive escaping automatically: values in HTML element content, attribute values, URL parameters, and JavaScript contexts are each escaped with the correct encoding for that position. The only legitimate use of `text/template` is for non-HTML output (plain text, Markdown, configuration files) where browser interpretation is impossible.

Do not bypass escaping with `template.HTML(userInput)` or `template.JS(userInput)` unless the value was produced by the application itself and its content is fully controlled.

**Refs**: CWE-79, OWASP A03:2025

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
| errors.Is / errors.As | warning | CWE-390 |
| Mutex / data race prevention | strict | CWE-362 |
| Context propagation | warning | CWE-400 |
| html/template for HTML | strict | CWE-79 |

---

## Version History

- **v2.0.0** - Added concurrency, context propagation, template XSS, and error wrapping rules; fixed missing imports in validateUsername and safeReadFile
