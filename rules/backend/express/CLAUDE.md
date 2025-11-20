# Express.js Security Rules

Security rules for Express.js development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security

---

## Security Middleware

### Rule: Use Helmet for Security Headers

**Level**: `strict`

**When**: Setting up Express application.

**Do**:
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Enable all security headers
app.use(helmet());

// Or configure individually
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));
```

**Don't**:
```javascript
const app = express();
// VULNERABLE: No security headers
app.listen(3000);
```

**Why**: Missing security headers enable clickjacking, MIME sniffing, and XSS attacks.

**Refs**: OWASP A05:2025

---

### Rule: Configure CORS Properly

**Level**: `strict`

**When**: Enabling cross-origin requests.

**Do**:
```javascript
const cors = require('cors');

const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
```

**Don't**:
```javascript
// VULNERABLE: Allows any origin
app.use(cors());

// VULNERABLE: Wildcard with credentials
app.use(cors({ origin: '*', credentials: true }));
```

**Why**: Permissive CORS allows malicious sites to make authenticated requests.

**Refs**: CWE-942, OWASP A05:2025

---

## Input Validation

### Rule: Validate Request Data

**Level**: `strict`

**When**: Processing user input.

**Do**:
```javascript
const Joi = require('joi');
const express = require('express');

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
  age: Joi.number().integer().min(0).max(150),
});

app.post('/users', async (req, res, next) => {
  try {
    const validated = await userSchema.validateAsync(req.body);
    // Use validated data
    res.json({ email: validated.email });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

**Don't**:
```javascript
app.post('/users', (req, res) => {
  // VULNERABLE: No validation
  const { email, password } = req.body;
  createUser(email, password);
});
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

### Rule: Sanitize Output

**Level**: `strict`

**When**: Rendering user-provided content.

**Do**:
```javascript
const escape = require('escape-html');

app.get('/profile', (req, res) => {
  const safeName = escape(user.name);
  res.send(`<h1>Welcome, ${safeName}</h1>`);
});

// Or use template engine with auto-escaping
app.set('view engine', 'ejs');
// EJS escapes by default with <%= %>
```

**Don't**:
```javascript
app.get('/search', (req, res) => {
  // VULNERABLE: XSS
  res.send(`<p>Results for: ${req.query.q}</p>`);
});
```

**Why**: Unescaped output enables XSS attacks that steal cookies or perform actions as the user.

**Refs**: CWE-79, OWASP A03:2025

---

## Authentication

### Rule: Implement Secure Session Management

**Level**: `strict`

**When**: Managing user sessions.

**Do**:
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const crypto = require('crypto');

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  name: 'sessionId',  // Change default name
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000,  // 30 minutes
  },
}));

// Regenerate session on login
app.post('/login', async (req, res) => {
  if (await authenticate(req.body)) {
    req.session.regenerate((err) => {
      req.session.userId = user.id;
      res.redirect('/dashboard');
    });
  }
});
```

**Don't**:
```javascript
// VULNERABLE: Weak secret, insecure cookies
app.use(session({
  secret: 'keyboard cat',
  cookie: { secure: false },
}));
```

**Why**: Weak session management enables session hijacking and fixation attacks.

**Refs**: CWE-384, OWASP A07:2025

---

### Rule: Implement Rate Limiting

**Level**: `warning`

**When**: Exposing authentication or sensitive endpoints.

**Do**:
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many login attempts',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/login', loginLimiter, async (req, res) => {
  // Rate limited endpoint
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});

app.use('/api/', apiLimiter);
```

**Don't**:
```javascript
// VULNERABLE: No rate limiting
app.post('/login', async (req, res) => {
  // Brute force possible
});
```

**Why**: Missing rate limits enable brute force attacks and DoS.

**Refs**: CWE-307, OWASP A07:2025

---

## Database Security

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```javascript
// With pg (PostgreSQL)
const result = await pool.query(
  'SELECT * FROM users WHERE email = $1',
  [email]
);

// With mysql2
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = ?',
  [email]
);

// With Sequelize ORM
const user = await User.findOne({ where: { email } });
```

**Don't**:
```javascript
// VULNERABLE: SQL injection
const query = `SELECT * FROM users WHERE email = '${email}'`;
const result = await pool.query(query);

// VULNERABLE: String concatenation
connection.query('SELECT * FROM users WHERE id = ' + userId);
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## File Handling

### Rule: Secure File Uploads

**Level**: `strict`

**When**: Accepting file uploads.

**Do**:
```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    // Generate random filename
    const uniqueName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, uniqueName + ext);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.pdf'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  },
});

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.filename });
});
```

**Don't**:
```javascript
// VULNERABLE: No validation
app.post('/upload', upload.single('file'), (req, res) => {
  // Original filename could be malicious
  fs.rename(req.file.path, `uploads/${req.file.originalname}`);
});
```

**Why**: Unrestricted uploads enable path traversal, RCE via web shells, and DoS.

**Refs**: CWE-434, OWASP A04:2025

---

## Error Handling

### Rule: Implement Secure Error Handling

**Level**: `warning`

**When**: Handling errors in production.

**Do**:
```javascript
// Custom error handler
app.use((err, req, res, next) => {
  console.error(err.stack);  // Log internally

  // Don't expose details in production
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message });
  }
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});
```

**Don't**:
```javascript
// VULNERABLE: Exposes stack traces
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});
```

**Why**: Stack traces reveal internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Helmet headers | strict | - |
| CORS configuration | strict | CWE-942 |
| Input validation | strict | CWE-20 |
| Output sanitization | strict | CWE-79 |
| Secure sessions | strict | CWE-384 |
| Rate limiting | warning | CWE-307 |
| Parameterized queries | strict | CWE-89 |
| Secure file uploads | strict | CWE-434 |
| Error handling | warning | CWE-209 |

---

## Version History

- **v1.0.0** - Initial Express.js security rules
