# Svelte Security Rules

Security rules for Svelte development in Claude Code.

**Version target**: Svelte 4 / SvelteKit 2.x. Svelte 4 component syntax ($:, `export let`,
`on:event` directives) is valid in Svelte 5 with no code changes; see the advisory notes
at the bottom for Svelte 5 rune equivalents. SvelteKit 2.x changed `error()` and
`redirect()` to throw internally — do not add an outer `throw` keyword.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security

---

## XSS Prevention

### Rule: Never Use @html with User Input

**Level**: `strict`

**When**: Rendering dynamic HTML content.

**Do**:
```svelte
<script>
  import DOMPurify from 'dompurify';

  export let userMessage;
  export let rawHtml;

  $: sanitizedHtml = DOMPurify.sanitize(rawHtml);
</script>

<!-- Text interpolation is auto-escaped -->
<p>{userMessage}</p>

<!-- For HTML, sanitize first -->
<div>{@html sanitizedHtml}</div>
```

**Don't**:
```svelte
<!-- VULNERABLE: XSS -->
<div>{@html userProvidedHtml}</div>
```

**Why**: @html renders raw HTML, enabling XSS attacks that steal cookies or perform actions as users.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Validate Dynamic URLs

**Level**: `strict`

**When**: Binding user input to href, src, or other URL attributes.

**Do**:
```svelte
<script>
  export let userUrl = '';

  $: isValidUrl = (() => {
    try {
      const parsed = new URL(userUrl);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  })();

  $: sanitizedUrl = isValidUrl ? userUrl : '#';
</script>

{#if isValidUrl}
  <a href={sanitizedUrl}>Link</a>
{/if}
```

**Don't**:
```svelte
<!-- VULNERABLE: javascript: URLs -->
<a href={userUrl}>Link</a>
```

**Why**: `javascript:` URLs execute code when clicked.

**Refs**: CWE-79, CWE-601

---

## State Management

### Rule: Don't Store Sensitive Data in Stores

**Level**: `strict`

**When**: Using Svelte stores for state management. In Svelte 5, shared mutable state is
idiomatic via `$state` in a `.svelte.js` module; `writable` stores remain valid. The
security principle — no tokens in client-side state — applies equally to both forms.

**Do**:
```javascript
// stores/user.js
import { writable } from 'svelte/store';

export const user = writable({
  id: null,
  email: null,
  name: null,
  isAuthenticated: false
  // Don't store tokens here
});

// auth.js
export async function login(credentials) {
  // Token stored in httpOnly cookie by server
  const response = await fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
    credentials: 'include'
  });

  const data = await response.json();
  user.set({
    id: data.user.id,
    email: data.user.email,
    isAuthenticated: true
  });
}
```

**Don't**:
```javascript
// VULNERABLE: Tokens accessible via XSS
export const auth = writable({
  accessToken: localStorage.getItem('token'),
  refreshToken: localStorage.getItem('refresh')
});
```

**Why**: Client-side state is accessible to XSS attacks. Store tokens in httpOnly cookies.

**Refs**: CWE-922, OWASP A02:2025

---

## Input Validation

### Rule: Validate Form Inputs

**Level**: `strict`

**When**: Processing user form submissions.

**Do**:
```svelte
<script>
  import { z } from 'zod';

  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(8).max(128)
  });

  let form = { email: '', password: '' };
  let errors = {};

  async function handleSubmit() {
    try {
      const validated = schema.parse(form);
      await api.login(validated);
    } catch (error) {
      if (error instanceof z.ZodError) {
        errors = error.flatten().fieldErrors;
      }
    }
  }
</script>

<form on:submit|preventDefault={handleSubmit}>
  <input bind:value={form.email} type="email" required />
  {#if errors.email}
    <span class="error">{errors.email[0]}</span>
  {/if}

  <input bind:value={form.password} type="password" />
  {#if errors.password}
    <span class="error">{errors.password[0]}</span>
  {/if}

  <button type="submit">Login</button>
</form>
```

**Don't**:
```svelte
<script>
  // VULNERABLE: No validation
  async function handleSubmit() {
    await api.login(form);
  }
</script>
```

**Why**: Unvalidated input causes errors and enables injection attacks.

**Refs**: CWE-20, OWASP A03:2025

---

## API Security

### Rule: Include CSRF Tokens

**Level**: `strict`

**When**: Making state-changing API requests.

**Do**:
```javascript
// lib/api.js
async function apiFetch(url, options = {}) {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('csrftoken='))
    ?.split('=')[1];

  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken,
      ...options.headers
    }
  });
}

export const api = {
  post: (url, data) => apiFetch(url, {
    method: 'POST',
    body: JSON.stringify(data)
  }),
  delete: (url) => apiFetch(url, { method: 'DELETE' })
};
```

**Don't**:
```javascript
// VULNERABLE: No CSRF protection
async function deleteAccount(userId) {
  await fetch(`/api/users/${userId}`, {
    method: 'DELETE'
  });
}
```

**Why**: Missing CSRF tokens allow attackers to perform actions on behalf of users. Note:
SvelteKit Form Actions include built-in CSRF protection and do not require manual token
handling. This pattern applies to custom `fetch()` calls against non-SvelteKit backends.

**Refs**: CWE-352, OWASP A01:2025

---

### Rule: Validate API Responses

**Level**: `warning`

**When**: Processing data from APIs.

**Do**:
```javascript
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string()
});

export async function fetchUser(id) {
  const response = await fetch(`/api/users/${id}`);
  const data = await response.json();

  // Validate response structure
  return UserSchema.parse(data);
}
```

**Don't**:
```javascript
// VULNERABLE: Assumes response structure
export async function fetchUser(id) {
  const response = await fetch(`/api/users/${id}`);
  return response.json();  // May not match expected structure
}
```

**Why**: Malformed API responses can crash the app or inject unexpected data.

**Refs**: CWE-20

---

## SvelteKit Security

### Rule: Protect Server Routes

**Level**: `strict`

**When**: Creating API endpoints in SvelteKit.

**Do**:
```javascript
// src/routes/api/admin/+server.js
import { error } from '@sveltejs/kit';

export async function GET({ locals }) {
  // Verify authentication
  if (!locals.user) {
    error(401, 'Authentication required');        // SvelteKit 2.x: no throw
  }

  // Verify authorization
  if (!locals.user.isAdmin) {
    error(403, 'Insufficient permissions');        // SvelteKit 2.x: no throw
  }

  const data = await getAdminData();
  return new Response(JSON.stringify(data));
}
```

**Don't**:
```javascript
// VULNERABLE: No auth check
export async function GET() {
  const data = await getAdminData();
  return new Response(JSON.stringify(data));
}
```

**Why**: Unprotected endpoints expose sensitive data and functionality.

**Refs**: CWE-862, OWASP A01:2025

---

### Rule: Validate Load Function Data

**Level**: `strict`

**When**: Loading data in SvelteKit pages.

**Do**:
```javascript
// src/routes/users/[id]/+page.server.js
import { error } from '@sveltejs/kit';

export async function load({ params, locals }) {
  // Validate parameter
  const id = parseInt(params.id);
  if (isNaN(id) || id <= 0) {
    error(400, 'Invalid user ID');               // SvelteKit 2.x: no throw
  }

  // Check authorization
  if (locals.user?.id !== id && !locals.user?.isAdmin) {
    error(403, 'Cannot access this user');        // SvelteKit 2.x: no throw
  }

  const user = await getUser(id);
  if (!user) {
    error(404, 'User not found');                 // SvelteKit 2.x: no throw
  }

  return { user };
}
```

**Don't**:
```javascript
// VULNERABLE: No validation or auth
export async function load({ params }) {
  return {
    user: await getUser(params.id)
  };
}
```

**Why**: Unvalidated parameters and missing auth checks enable IDOR attacks.

**Refs**: CWE-639, OWASP A01:2025

---

## Environment Variables

### Rule: Don't Expose Secrets to Client

**Level**: `strict`

**When**: Using environment variables.

**Do**:
```bash
# .env — only PUBLIC_ vars are sent to the client
PUBLIC_API_URL=https://api.myapp.com
DATABASE_URL=postgres://...  # Server only
JWT_SECRET=...               # Server only
```

```javascript
// src/routes/+page.svelte
import { PUBLIC_API_URL } from '$env/static/public';

// src/routes/api/+server.js
import { DATABASE_URL } from '$env/static/private';
```

**Don't**:
```javascript
// VULNERABLE: Exposing secrets
import { JWT_SECRET } from '$env/static/private';

// In +page.svelte (client-side)
const secret = JWT_SECRET;  // Build error — SvelteKit enforces the private boundary at
                             // compile time via module resolution, not at runtime
```

**Why**: Secrets exposed to client are visible in browser and can be extracted.

**Refs**: CWE-200, OWASP A02:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| No @html with user input | strict | CWE-79 |
| Validate dynamic URLs | strict | CWE-79 |
| No sensitive store data | strict | CWE-922 |
| Validate form inputs | strict | CWE-20 |
| CSRF tokens | strict | CWE-352 |
| Validate API responses | warning | CWE-20 |
| Protect server routes | strict | CWE-862 |
| Validate load data | strict | CWE-639 |
| No client secrets | strict | CWE-200 |

---

## Svelte 5 Migration Notes

The rules above use Svelte 4 syntax throughout. All examples are valid in Svelte 5 with no
changes. For new Svelte 5 projects, the idiomatic equivalents are:

| Svelte 4 | Svelte 5 |
|---|---|
| `export let prop` | `let { prop } = $props()` |
| `$: derived = expr` | `let derived = $derived(expr)` |
| `$: { sideEffect }` | `$effect(() => { sideEffect })` |
| `on:submit\|preventDefault` | `onsubmit={handler}` (call `e.preventDefault()` inside) |
| `writable` store | `$state` in a `.svelte.js` module |

Security principles (no tokens in client state, sanitize `{@html}` input, validate all
parameters) are identical between versions.

---

## Version History

- **v2.0.0** - SvelteKit 2.x `error()` call sites updated; Svelte 5 advisory notes added
- **v1.0.0** - Initial Svelte security rules
