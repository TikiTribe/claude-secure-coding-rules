# JavaScript Security Rules

Security rules for JavaScript/Node.js development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Code Execution

### Rule: Never Use eval() with User Input

**Level**: `strict`

**When**: Dynamic code evaluation is considered.

**Do**:
```javascript
// Use JSON.parse for data
const data = JSON.parse(userInput);

// Use Map for dynamic property access
const handlers = new Map([
  ['action1', handleAction1],
  ['action2', handleAction2]
]);
const handler = handlers.get(actionName);

// Use Function constructor with extreme caution (sandboxed only)
```

**Don't**:
```javascript
// VULNERABLE: Arbitrary code execution
eval(userInput);

// VULNERABLE: Same risk
new Function(userInput)();

// VULNERABLE: setTimeout/setInterval with strings
setTimeout(userCode, 1000);
```

**Why**: `eval()` executes arbitrary JavaScript, enabling complete application compromise.

**Refs**: CWE-94, CWE-95, OWASP A03:2025

---

### Rule: Avoid Prototype Pollution

**Level**: `strict`

**When**: Merging objects or setting properties dynamically.

**Do**:
```javascript
// Use Object.create(null) for dictionaries
const safeDict = Object.create(null);

// Validate keys before assignment
function safeSet(obj, key, value) {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    throw new Error('Invalid key');
  }
  obj[key] = value;
}

// Use Map for user-controlled keys
const userPrefs = new Map();
userPrefs.set(userKey, userValue);
```

**Don't**:
```javascript
// VULNERABLE: Prototype pollution
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];  // Can set __proto__
  }
}

// VULNERABLE: Direct bracket notation with user input
obj[userKey] = userValue;
```

**Why**: Prototype pollution can modify Object.prototype, affecting all objects and enabling RCE.

**Refs**: CWE-1321, CVE-2019-10744 (lodash)

---

## DOM Security

### Rule: Sanitize HTML Before Insertion

**Level**: `strict`

**When**: Inserting dynamic content into the DOM.

**Do**:
```javascript
import DOMPurify from 'dompurify';

// Sanitize HTML
const clean = DOMPurify.sanitize(userHtml);
element.innerHTML = clean;

// Use textContent for plain text
element.textContent = userInput;

// Create elements programmatically
const link = document.createElement('a');
link.href = sanitizedUrl;
link.textContent = userText;
```

**Don't**:
```javascript
// VULNERABLE: XSS
element.innerHTML = userInput;

// VULNERABLE: XSS via document.write
document.write(userInput);

// VULNERABLE: XSS in template literals
element.innerHTML = `<div>${userInput}</div>`;
```

**Why**: Direct HTML insertion enables XSS attacks that steal cookies or perform actions as the user.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Validate URLs Before Use

**Level**: `strict`

**When**: Using user-provided URLs in links, redirects, or fetches.

**Do**:
```javascript
function isValidUrl(urlString) {
  try {
    const url = new URL(urlString);
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}

// Safe redirect
if (isValidUrl(redirectUrl) && isSameDomain(redirectUrl)) {
  window.location.href = redirectUrl;
}
```

**Don't**:
```javascript
// VULNERABLE: javascript: URLs execute code
element.href = userUrl;

// VULNERABLE: Open redirect
window.location.href = userProvidedUrl;
```

**Why**: `javascript:` URLs execute code, open redirects enable phishing attacks.

**Refs**: CWE-601, CWE-79

---

## Server-Side (Node.js)

### Rule: Prevent Command Injection

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```javascript
const { execFile } = require('child_process');

// Use execFile with argument array
execFile('grep', [pattern, filename], (error, stdout) => {
  console.log(stdout);
});

// Or spawn with explicit args
const { spawn } = require('child_process');
const ls = spawn('ls', ['-la', directory]);
```

**Don't**:
```javascript
const { exec } = require('child_process');

// VULNERABLE: Command injection
exec(`grep ${userPattern} ${userFile}`);

// VULNERABLE: Shell interpretation
exec('ls ' + userInput);
```

**Why**: Shell metacharacters (;, |, &&) allow executing arbitrary commands.

**Refs**: CWE-78, OWASP A03:2025

---

### Rule: Validate File Paths

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```javascript
const path = require('path');
const fs = require('fs');

const SAFE_DIR = '/app/uploads';

function safeReadFile(filename) {
  const resolved = path.resolve(SAFE_DIR, filename);

  // Ensure path is within safe directory
  if (!resolved.startsWith(SAFE_DIR + path.sep)) {
    throw new Error('Path traversal detected');
  }

  return fs.readFileSync(resolved);
}
```

**Don't**:
```javascript
// VULNERABLE: Path traversal
const filepath = `./uploads/${userFilename}`;
fs.readFileSync(filepath);

// VULNERABLE: No validation
fs.readFileSync(path.join(baseDir, userInput));
```

**Why**: Path traversal (../) allows reading sensitive files like /etc/passwd or .env.

**Refs**: CWE-22, OWASP A01:2025

---

### Rule: Use Secure Dependencies

**Level**: `warning`

**When**: Installing or updating packages.

**Do**:
```bash
# Audit dependencies
npm audit

# Use lockfile
npm ci

# Check for outdated packages
npm outdated

# Use specific versions
npm install package@1.2.3
```

```javascript
// package.json - pin versions
{
  "dependencies": {
    "express": "4.18.2"  // Exact version
  }
}
```

**Don't**:
```json
{
  "dependencies": {
    "express": "*",      // VULNERABLE: Any version
    "lodash": "^4.0.0"   // Risky: May pull vulnerable minor versions
  }
}
```

**Why**: Unpinned dependencies can introduce vulnerabilities through automatic updates.

**Refs**: CWE-1104, OWASP A06:2025

---

## Cryptography

### Rule: Use Crypto Module Correctly

**Level**: `strict`

**When**: Generating random values or encrypting data.

**Do**:
```javascript
const crypto = require('crypto');

// Secure random token
const token = crypto.randomBytes(32).toString('hex');

// Secure UUID
const { randomUUID } = require('crypto');
const id = randomUUID();

// Password hashing
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
```

**Don't**:
```javascript
// VULNERABLE: Predictable
const token = Math.random().toString(36);

// VULNERABLE: Weak hash for passwords
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**Why**: Math.random() is predictable, MD5/SHA1 are too fast for password hashing.

**Refs**: CWE-330, CWE-328

---

## HTTP Security

### Rule: Set Security Headers

**Level**: `warning`

**When**: Configuring Express or other HTTP servers.

**Do**:
```javascript
const helmet = require('helmet');
const express = require('express');
const app = express();

// Use helmet for security headers
app.use(helmet());

// Or set individually
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

**Don't**:
```javascript
// No security headers configured
const app = express();
app.listen(3000);
```

**Why**: Missing headers enable clickjacking, MIME sniffing, and XSS attacks.

**Refs**: OWASP A05:2025

---

### Rule: Configure CORS Properly

**Level**: `strict`

**When**: Enabling Cross-Origin Resource Sharing.

**Do**:
```javascript
const cors = require('cors');

// Specific origins only
app.use(cors({
  origin: ['https://myapp.com', 'https://admin.myapp.com'],
  methods: ['GET', 'POST'],
  credentials: true
}));

// Or validate dynamically
const allowedOrigins = new Set(['https://myapp.com']);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed'));
    }
  }
}));
```

**Don't**:
```javascript
// VULNERABLE: Allows any origin
app.use(cors({ origin: '*', credentials: true }));

// VULNERABLE: Reflects any origin
app.use(cors({ origin: true }));
```

**Why**: Permissive CORS allows malicious sites to make authenticated requests.

**Refs**: CWE-942, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| No eval() | strict | CWE-94 |
| Prototype pollution | strict | CWE-1321 |
| Sanitize HTML | strict | CWE-79 |
| Validate URLs | strict | CWE-601 |
| Command injection | strict | CWE-78 |
| Path traversal | strict | CWE-22 |
| Secure dependencies | warning | CWE-1104 |
| Crypto randomness | strict | CWE-330 |
| Security headers | warning | - |
| CORS configuration | strict | CWE-942 |

---

## Version History

- **v1.0.0** - Initial JavaScript/Node.js security rules
