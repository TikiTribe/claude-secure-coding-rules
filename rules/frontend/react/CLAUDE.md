# React Security Rules

Security rules for React development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security

---

## XSS Prevention

### Rule: Never Use dangerouslySetInnerHTML with User Input

**Level**: `strict`

**When**: Rendering dynamic HTML content.

**Do**:
```jsx
import DOMPurify from 'dompurify';

function SafeContent({ html }) {
  // Sanitize before rendering
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// Or use textContent for plain text
function UserMessage({ text }) {
  return <p>{text}</p>;  // React escapes by default
}
```

**Don't**:
```jsx
function UnsafeContent({ userHtml }) {
  // VULNERABLE: XSS
  return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;
}
```

**Why**: Unsanitized HTML enables XSS attacks that steal cookies or perform actions as the user.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Sanitize URLs in href and src

**Level**: `strict`

**When**: Using dynamic URLs in links or resources.

**Do**:
```jsx
function SafeLink({ url, children }) {
  const isValidUrl = (urlString) => {
    try {
      const parsed = new URL(urlString);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  };

  if (!isValidUrl(url)) {
    return <span>{children}</span>;
  }

  return <a href={url}>{children}</a>;
}

// For images
function SafeImage({ src, alt }) {
  const safeSrc = src.startsWith('https://') ? src : '/fallback.png';
  return <img src={safeSrc} alt={alt} />;
}
```

**Don't**:
```jsx
// VULNERABLE: javascript: URLs execute code
function Link({ userUrl }) {
  return <a href={userUrl}>Click here</a>;
}

// VULNERABLE: data: URLs can contain scripts
<img src={userProvidedSrc} />
```

**Why**: `javascript:` and `data:` URLs execute code when clicked or loaded.

**Refs**: CWE-79, CWE-601

---

## State Management

### Rule: Don't Store Sensitive Data in Client State

**Level**: `strict`

**When**: Managing application state.

**Do**:
```jsx
// Store only necessary session info
const [user, setUser] = useState({
  id: null,
  name: null,
  isAuthenticated: false,
});

// Keep tokens in httpOnly cookies (set by server)
// Access protected resources via API calls
```

**Don't**:
```jsx
// VULNERABLE: Accessible via XSS
const [authToken, setAuthToken] = useState(localStorage.getItem('token'));

// VULNERABLE: Sensitive data in state
const [user, setUser] = useState({
  ...userData,
  password: password,  // Never store passwords
  ssn: socialSecurityNumber,
});
```

**Why**: Client-side state is accessible to XSS attacks. Store tokens in httpOnly cookies.

**Refs**: CWE-922, OWASP A02:2025

---

### Rule: Validate Props and State

**Level**: `warning`

**When**: Receiving data from external sources.

**Do**:
```jsx
import PropTypes from 'prop-types';

function UserProfile({ userId, email }) {
  // Validate before use
  if (typeof userId !== 'number' || userId <= 0) {
    return <ErrorMessage>Invalid user</ErrorMessage>;
  }

  return <div>{email}</div>;
}

UserProfile.propTypes = {
  userId: PropTypes.number.isRequired,
  email: PropTypes.string.isRequired,
};

// TypeScript provides compile-time validation
interface UserProfileProps {
  userId: number;
  email: string;
}
```

**Don't**:
```jsx
function UserProfile({ data }) {
  // VULNERABLE: No validation
  return <div>{data.name}</div>;  // Could crash or expose unexpected data
}
```

**Why**: Invalid data can cause crashes, expose unexpected information, or enable attacks.

**Refs**: CWE-20

---

## API Security

### Rule: Include CSRF Tokens in State-Changing Requests

**Level**: `strict`

**When**: Making POST, PUT, DELETE requests.

**Do**:
```jsx
function useApi() {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

  const post = async (url, data) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      credentials: 'include',
      body: JSON.stringify(data),
    });
    return response.json();
  };

  return { post };
}
```

**Don't**:
```jsx
// VULNERABLE: No CSRF protection
async function deleteAccount(userId) {
  await fetch(`/api/users/${userId}`, {
    method: 'DELETE',
  });
}
```

**Why**: Missing CSRF tokens allow attackers to perform actions on behalf of authenticated users.

**Refs**: CWE-352, OWASP A01:2025

---

### Rule: Validate API Responses

**Level**: `warning`

**When**: Processing data from APIs.

**Do**:
```jsx
async function fetchUser(id) {
  const response = await fetch(`/api/users/${id}`);

  if (!response.ok) {
    throw new Error('Failed to fetch user');
  }

  const data = await response.json();

  // Validate response structure
  if (!data.id || !data.email) {
    throw new Error('Invalid user data');
  }

  return {
    id: data.id,
    email: data.email,
    name: data.name ?? 'Unknown',
  };
}
```

**Don't**:
```jsx
async function fetchUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const data = await response.json();
  // VULNERABLE: Assumes data structure without validation
  return data;
}
```

**Why**: Malformed or malicious API responses can crash the app or inject data.

**Refs**: CWE-20

---

## Component Security

### Rule: Avoid Exposing Sensitive Logic in Components

**Level**: `warning`

**When**: Implementing authorization or sensitive features.

**Do**:
```jsx
// Server handles authorization
function AdminPanel() {
  const { data, isLoading } = useQuery('adminData', fetchAdminData);

  // API returns 403 if not authorized
  if (isLoading) return <Loading />;

  return <AdminDashboard data={data} />;
}

// Use for UX only, not security
function ConditionalUI({ user }) {
  return (
    <>
      <PublicContent />
      {user.isAdmin && <AdminLink />}  // UX only
    </>
  );
}
```

**Don't**:
```jsx
// VULNERABLE: Client-side security check
function AdminPanel({ user }) {
  if (!user.isAdmin) {
    return <AccessDenied />;
  }

  // Admin content - still fetched from API without server check
  return <SensitiveData />;
}
```

**Why**: Client-side checks are easily bypassed. Server must enforce authorization.

**Refs**: CWE-602, OWASP A01:2025

---

### Rule: Sanitize Form Inputs

**Level**: `strict`

**When**: Processing form submissions.

**Do**:
```jsx
import { z } from 'zod';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
});

function LoginForm() {
  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);

    try {
      const validated = loginSchema.parse({
        email: formData.get('email'),
        password: formData.get('password'),
      });

      await login(validated);
    } catch (error) {
      setErrors(error.errors);
    }
  };

  return <form onSubmit={handleSubmit}>...</form>;
}
```

**Don't**:
```jsx
function LoginForm() {
  const handleSubmit = (e) => {
    e.preventDefault();
    // VULNERABLE: No validation
    login({
      email: e.target.email.value,
      password: e.target.password.value,
    });
  };
}
```

**Why**: Unvalidated form data can cause errors or enable injection attacks.

**Refs**: CWE-20, OWASP A03:2025

---

## Dependencies

### Rule: Keep Dependencies Updated

**Level**: `warning`

**When**: Managing project dependencies.

**Do**:
```bash
# Regular audit
npm audit

# Fix vulnerabilities
npm audit fix

# Check for updates
npm outdated

# Use exact versions for critical packages
npm install react@18.2.0
```

```json
// package.json - Consider using exact versions
{
  "dependencies": {
    "react": "18.2.0",
    "react-dom": "18.2.0"
  }
}
```

**Don't**:
```json
{
  "dependencies": {
    "some-package": "*"  // VULNERABLE: Any version
  }
}
```

**Why**: Outdated dependencies may contain known vulnerabilities.

**Refs**: CWE-1104, OWASP A06:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| No dangerouslySetInnerHTML | strict | CWE-79 |
| Sanitize URLs | strict | CWE-79 |
| No sensitive client state | strict | CWE-922 |
| Validate props/state | warning | CWE-20 |
| CSRF tokens | strict | CWE-352 |
| Validate API responses | warning | CWE-20 |
| Server-side authorization | warning | CWE-602 |
| Sanitize forms | strict | CWE-20 |
| Update dependencies | warning | CWE-1104 |

---

## Version History

- **v1.0.0** - Initial React security rules
