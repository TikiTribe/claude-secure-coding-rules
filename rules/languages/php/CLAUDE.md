# PHP Security Rules

Security rules for PHP development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Database Security

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing any database query with user-supplied or external data.

**Do**:
```php
// Safe: PDO with prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND status = ?");
$stmt->execute([$email, $status]);
$user = $stmt->fetch();

// Safe: PDO with named placeholders
$stmt = $pdo->prepare("SELECT * FROM products WHERE size = :size AND category = :category");
$stmt->execute([':size' => $size, ':category' => $category]);

// Safe: MySQLi with prepared statements
$stmt = $mysqli->prepare("SELECT id, name FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();

// Safe: Use minimal database privileges
// Connect with a user that has only SELECT/INSERT/UPDATE on required tables
$pdo = new PDO($dsn, 'app_user', $password); // not root or db owner
```

**Don't**:
```php
// VULNERABLE: Direct string concatenation
$query = "SELECT * FROM users WHERE email = '$email'";
$result = mysqli_query($conn, $query);

// VULNERABLE: sprintf still injectable
$query = sprintf("SELECT * FROM %s WHERE id = %s", $table, $id);

// VULNERABLE: Interpolated variables
$result = $pdo->query("SELECT * FROM products WHERE size = '$size'");
```

**Why**: SQL injection allows attackers to read, modify, or delete database data, and on some servers can escalate to OS-level command execution.

**Refs**: CWE-89, OWASP A05:2025

---

## Filesystem Security

### Rule: Prevent Path Traversal

**Level**: `strict`

**When**: Reading, writing, or deleting files using any user-supplied input.

**Do**:
```php
// Safe: Validate path and return it — does NOT read the file
// (requires PHP 8.0+ for str_starts_with; use substr($fullPath, 0, strlen($resolvedBase)) === $resolvedBase for PHP 7.x)
function safeValidatePath(string $filename, string $baseDir = '/app/data'): string {
    $resolvedBase = realpath($baseDir);
    if ($resolvedBase === false) {
        throw new \RuntimeException('Base directory does not exist.');
    }

    $fullPath = realpath($resolvedBase . DIRECTORY_SEPARATOR . $filename);

    if ($fullPath === false || !str_starts_with($fullPath, $resolvedBase . DIRECTORY_SEPARATOR)) {
        throw new \RuntimeException('Path traversal attempt detected.');
    }

    return $fullPath; // return the validated path, not the file contents
}

// Safe: Whitelist with basename() and regex allowlist
$filename = basename($_POST['filename']);
if (!preg_match('/^[a-zA-Z0-9_-]+\.(csv|txt)$/', $filename)) {
    throw new InvalidArgumentException('Invalid filename.');
}
$path = '/app/uploads/' . $filename;

// Safe: Use random internal names; map them from a database
// Store user_label -> random_internal_name in a table rather than
// ever using user input directly as a filesystem path
```

**Don't**:
```php
// VULNERABLE: Direct concatenation — allows ../../etc/passwd
$filepath = '/home/' . $_POST['username'] . '/' . $_POST['filename'];
unlink($filepath);

// VULNERABLE: basename() alone does not prevent all traversal
$path = '/app/uploads/' . $_POST['file']; // missing realpath check

// VULNERABLE: Accepting absolute paths from user input
$data = file_get_contents($_GET['path']);
```

**Why**: Path traversal uses `../` sequences to escape the intended directory, potentially exposing or deleting sensitive system files like `/etc/passwd`.

**Refs**: CWE-22, OWASP A01:2025

---

### Rule: Handle Null Bytes in File Paths

**Level**: `strict`

**When**: Using user input in any file operation.

**Do**:
```php
// Safe: Reject strings containing null bytes before any file operation
// (requires PHP 8.0+ for str_contains; use strpos($input, "\0") !== false for PHP 7.x)
function sanitizeFilename(string $input): string {
    if (str_contains($input, "\0")) {
        throw new InvalidArgumentException('Null byte detected in filename.');
    }
    return basename($input);
}

// Safe: PHP 5.3.4+ raises a warning, but explicit checks are still best practice
$filename = sanitizeFilename($_GET['file']);
```

**Don't**:
```php
// VULNERABLE: Null byte truncates path in older PHP/OS combinations
// e.g., "../../etc/passwd\0.jpg" is treated as "../../etc/passwd"
$path = '/app/uploads/' . $_GET['file'];
readfile($path);
```

**Why**: Null bytes can terminate strings at the OS level, allowing attackers to bypass extension checks and access arbitrary files.

**Refs**: CWE-158, CWE-22, OWASP A01:2025

---

## Session Security

### Rule: Harden Session Configuration

**Level**: `strict`

**When**: Using PHP sessions in any web application.

**Do**:
```php
// Safe: Configure sessions securely before session_start()
ini_set('session.use_strict_mode', 1);       // Reject uninitialized session IDs
ini_set('session.use_only_cookies', 1);      // No session ID in URL
ini_set('session.use_trans_sid', 0);
ini_set('session.cookie_httponly', 1);       // Block JavaScript access to cookie
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0); // HTTPS only when available
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.sid_length', 32);           // Manual recommends 32 chars minimum
ini_set('session.sid_bits_per_character', 5);
session_start();

// Safe: Regenerate session ID on privilege change (login, logout, role change)
session_regenerate_id(true); // true = delete old session file
```

**Don't**:
```php
// VULNERABLE: Default settings expose session ID in URLs
session_start(); // without hardened ini settings

// VULNERABLE: Never regenerating ID allows session fixation
if ($loginSuccess) {
    $_SESSION['user'] = $userId; // session ID unchanged — fixation risk
}

// VULNERABLE: Predictable session name leaks tech stack
// Default PHPSESSID tells attackers you're running PHP
```

**Why**: Without strict session settings, attackers can fix, steal, or hijack sessions through URL injection, XSS, or network interception.

**Refs**: CWE-384, CWE-614, OWASP A07:2025

---

## Error Reporting

### Rule: Disable Error Display in Production

**Level**: `strict`

**When**: Deploying any PHP application to a production or staging environment.

**Do**:
```php
// Safe: php.ini production settings
// display_errors = Off
// display_startup_errors = Off
// log_errors = On
// error_log = /var/log/php/app_error.log
// expose_php = Off

// Safe: Enforce programmatically as a fallback
if (getenv('APP_ENV') === 'production') {
    error_reporting(E_ALL);       // Capture everything...
    ini_set('display_errors', 0); // ...but never show it to users
    ini_set('log_errors', 1);
}

// Safe: Use a structured error handler that logs internally and shows a generic message
set_error_handler(function (int $errno, string $errstr, string $file, int $line): bool {
    error_log("[$errno] $errstr in $file:$line");
    return true;
});

set_exception_handler(function (Throwable $e): void {
    error_log($e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    http_response_code(500);
    echo 'An unexpected error occurred.';
});
```

**Don't**:
```php
// VULNERABLE: Exposes internal paths, library versions, and variable names
ini_set('display_errors', 1);
error_reporting(E_ALL);

// VULNERABLE: Leaks DB schema and query structure on error
$result = $pdo->query($sql); // PDOException shown to user reveals table names

// VULNERABLE: expose_php = On (default) sends X-Powered-By: PHP/8.x header
// Tells attackers which PHP version to target
```

**Why**: Error messages reveal server paths, database schemas, library versions, and variable names — all useful to an attacker profiling the system.

**Refs**: CWE-209, OWASP A02:2025

---

## User-Submitted Data

### Rule: Validate and Escape All User Input

**Level**: `strict`

**When**: Processing any data from `$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `$_SERVER`, or external APIs.

**Do**:
```php
<?php
// declare(strict_types=1) must be the very first statement in a file, before any other code.
// Place it at the top of every PHP file to prevent silent type coercions.
declare(strict_types=1);
```

```php
// Safe: Use filter_input with strict validation
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
if ($email === false || $email === null) {
    throw new InvalidArgumentException('Invalid email address.');
}

$age = filter_input(INPUT_GET, 'age', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 0, 'max_range' => 150]
]);

// Safe: Whitelist allowed values
$allowedSorts = ['name', 'date', 'price'];
$sort = in_array($_GET['sort'] ?? '', $allowedSorts, true) ? $_GET['sort'] : 'name';

// Safe: Escape output for HTML context
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

**Don't**:
```php
// VULNERABLE: Trusting user input directly
$username = $_POST['username'];
unlink("/home/$username/file.txt");

// VULNERABLE: Using strip_tags() as the sole sanitizer
// It strips HTML/PHP but not JavaScript or SQL payloads
$input = strip_tags($_POST['data']);

// VULNERABLE: Using htmlentities() without specifying charset
echo htmlentities($input); // charset defaults vary by PHP version
```

**Why**: Every value from the browser — including cookies and hidden fields — is attacker-controlled. Unvalidated input is the root cause of injection, XSS, and filesystem attacks.

**Refs**: CWE-20, CWE-79, OWASP A05:2025

---

## Code Execution

### Rule: Avoid Dangerous Functions with User Input

**Level**: `strict`

**When**: Any function that executes code or shell commands is used near user data.

**Do**:
```php
// Safe: Use disable_functions in php.ini to block dangerous functions entirely
// disable_functions = exec,passthru,shell_exec,system,proc_open,popen,eval

// Safe: Use a fixed command map; never pass user input to the shell
$allowedOperations = [
    'count_lines' => fn(string $path) => substr_count(file_get_contents($path), "\n"),
    'word_count'  => fn(string $path) => str_word_count(file_get_contents($path)),
];

$op = $_GET['op'] ?? '';
if (!array_key_exists($op, $allowedOperations)) {
    throw new InvalidArgumentException('Unknown operation.');
}

// Validate the path — safeValidatePath() returns a safe path, not file contents
$safePath = safeValidatePath($_GET['file'] ?? '', '/app/data');

$fn = $allowedOperations[$op];
$result = $fn($safePath);

// Safe: If a shell command is unavoidable, use escapeshellarg() on every argument
$validatedFilename = basename($_GET['file'] ?? '');
$safeArg = escapeshellarg($validatedFilename);
$output = shell_exec("wc -l $safeArg");
```

**Don't**:
```php
// VULNERABLE: Arbitrary code execution
eval($_POST['code']);

// VULNERABLE: Command injection
system('ls ' . $_GET['dir']);
exec("grep {$_POST['pattern']} /var/log/app.log");

// VULNERABLE: Dynamic inclusion of user-controlled paths (RFI/LFI)
include($_GET['page'] . '.php');
require($_POST['module']);
```

**Why**: Functions like `eval()`, `exec()`, and `include` with user-controlled input enable arbitrary code and command execution, potentially resulting in full server compromise.

**Refs**: CWE-94, CWE-78, CWE-98, OWASP A05:2025

---

## Cryptography

### Rule: Use Secure Password Hashing and Randomness

**Level**: `strict`

**When**: Storing passwords or generating tokens, session secrets, or any security-sensitive random values.

**Do**:
```php
// Safe: Password hashing with password_hash() (bcrypt by default)
$hash = password_hash($plaintext, PASSWORD_BCRYPT, ['cost' => 12]);

// Safe: Verification
if (password_verify($plaintext, $hash)) {
    // authenticated
}

// Safe: Upgrade to Argon2id when available
$hash = password_hash($plaintext, PASSWORD_ARGON2ID);

// Safe: Cryptographically secure random bytes for tokens
try {
    $token = bin2hex(random_bytes(32));   // 64-char hex token
    $apiKey = base64_encode(random_bytes(32));
} catch (\Random\RandomException $e) {
    throw new \RuntimeException('Failed to generate secure random bytes.', 0, $e);
}
```

**Don't**:
```php
// VULNERABLE: md5/sha1 are broken for passwords
$hash = md5($password);
$hash = sha1($password . $salt);

// VULNERABLE: Predictable randomness
srand(time());
$token = rand(); // not cryptographically secure

mt_srand(microtime(true));
$sessionId = md5(mt_rand()); // guessable

// VULNERABLE: Storing plaintext passwords
$_SESSION['password'] = $password;
$user->password = $plaintext; // saved to DB
```

**Why**: Weak hashing algorithms and predictable random number generators allow attackers to crack passwords and forge tokens offline.

**Refs**: CWE-327, CWE-328, CWE-330, OWASP A04:2025

---

## Hiding PHP / Configuration Hardening

### Rule: Minimize PHP Exposure

**Level**: `warning`

**When**: Deploying any PHP application.

**Do**:
```ini
; php.ini — production hardening
expose_php = Off                  ; Removes X-Powered-By: PHP header
display_errors = Off
display_startup_errors = Off
allow_url_include = Off           ; Prevents remote file inclusion
allow_url_fopen = Off             ; Disable if not needed for remote streams
open_basedir = /var/www/app       ; Restrict PHP file access to app directory
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,eval,assert
```

```php
// Safe: Restrict include paths to known directories
set_include_path('/var/www/app/includes');

// Safe: Serve all requests through a single entry point (front controller)
// index.php handles routing; all other .php files are outside the web root
// or protected by .htaccess / nginx deny rules
```

**Don't**:
```php
// VULNERABLE: phpinfo() in a web-accessible file
phpinfo(); // exposes full server config, extensions, paths, env vars

// VULNERABLE: Dynamic inclusion from user input
$page = $_GET['page'];
include("pages/$page.php"); // Local file inclusion (LFI) or RFI if allow_url_include=On

// VULNERABLE: Including files from outside the app directory
// with no open_basedir restriction
```

**Why**: Exposing the PHP version, server configuration, and include paths gives attackers a detailed map to exploit known vulnerabilities and craft targeted attacks.

**Refs**: CWE-200, OWASP A02:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| Prevent path traversal | strict | CWE-22 |
| Handle null bytes in paths | strict | CWE-158 |
| Harden session configuration | strict | CWE-384 |
| Disable error display in production | strict | CWE-209 |
| Validate and escape user input | strict | CWE-20 |
| Avoid dangerous functions with user input | strict | CWE-94 |
| Secure password hashing and randomness | strict | CWE-327 |
| Minimize PHP exposure | warning | CWE-200 |

---

## Version History

- **v1.0.0** - Initial PHP security rules, based on [PHP Manual: Security](https://www.php.net/manual/en/security.php)
