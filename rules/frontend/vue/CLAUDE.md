# Vue.js Security Rules

Security rules for Vue.js development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security

---

## XSS Prevention

### Rule: Never Use v-html with User Input

**Level**: `strict`

**When**: Rendering dynamic HTML content.

**Do**:
```vue
<template>
  <!-- Text interpolation is auto-escaped -->
  <p>{{ userMessage }}</p>

  <!-- For HTML, sanitize first -->
  <div v-html="sanitizedHtml"></div>
</template>

<script setup>
import DOMPurify from 'dompurify';
import { computed } from 'vue';

const props = defineProps({
  rawHtml: String
});

const sanitizedHtml = computed(() => {
  return DOMPurify.sanitize(props.rawHtml);
});
</script>
```

**Don't**:
```vue
<template>
  <!-- VULNERABLE: XSS -->
  <div v-html="userProvidedHtml"></div>
</template>
```

**Why**: v-html renders raw HTML, enabling XSS attacks that steal cookies or perform actions as users.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Sanitize Dynamic Attribute Values

**Level**: `strict`

**When**: Binding user input to attributes like href, src, style.

**Do**:
```vue
<template>
  <a v-if="isValidUrl" :href="sanitizedUrl">Link</a>
  <img v-if="isValidImageUrl" :src="imageUrl" />
</template>

<script setup>
import { computed } from 'vue';

const props = defineProps({
  url: String,
  imageUrl: String
});

const isValidUrl = computed(() => {
  try {
    const parsed = new URL(props.url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
});

const sanitizedUrl = computed(() => {
  return isValidUrl.value ? props.url : '#';
});

const isValidImageUrl = computed(() => {
  return props.imageUrl?.startsWith('https://cdn.myapp.com/');
});
</script>
```

**Don't**:
```vue
<template>
  <!-- VULNERABLE: javascript: URLs -->
  <a :href="userUrl">Link</a>

  <!-- VULNERABLE: Arbitrary URLs -->
  <img :src="userImageUrl" />
</template>
```

**Why**: `javascript:` URLs execute code, arbitrary image URLs enable SSRF.

**Refs**: CWE-79, CWE-918

---

## State Management

### Rule: Don't Store Sensitive Data in Client State

**Level**: `strict`

**When**: Managing application state with Pinia or Vuex.

**Do**:
```javascript
// stores/user.js
import { defineStore } from 'pinia';

export const useUserStore = defineStore('user', {
  state: () => ({
    id: null,
    email: null,
    name: null,
    isAuthenticated: false,
    // Don't store tokens here
  }),
  actions: {
    async login(credentials) {
      // Token stored in httpOnly cookie by server
      const response = await api.login(credentials);
      this.id = response.user.id;
      this.email = response.user.email;
      this.isAuthenticated = true;
    }
  }
});
```

**Don't**:
```javascript
// VULNERABLE: Tokens accessible via XSS
export const useUserStore = defineStore('user', {
  state: () => ({
    accessToken: localStorage.getItem('token'),
    refreshToken: localStorage.getItem('refresh'),
  }),
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
```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input v-model="form.email" type="email" required />
    <input v-model="form.password" type="password" minlength="8" />
    <span v-if="errors.email">{{ errors.email }}</span>
    <button type="submit">Submit</button>
  </form>
</template>

<script setup>
import { reactive } from 'vue';
import { z } from 'zod';

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
});

const form = reactive({ email: '', password: '' });
const errors = reactive({});

const handleSubmit = async () => {
  try {
    const validated = schema.parse(form);
    await api.login(validated);
  } catch (error) {
    if (error instanceof z.ZodError) {
      error.errors.forEach(e => {
        errors[e.path[0]] = e.message;
      });
    }
  }
};
</script>
```

**Don't**:
```vue
<script setup>
// VULNERABLE: No validation
const handleSubmit = async () => {
  await api.login(form);
};
</script>
```

**Why**: Unvalidated input causes errors and enables injection attacks.

**Refs**: CWE-20, OWASP A03:2025

---

## API Security

### Rule: Include CSRF Tokens in Requests

**Level**: `strict`

**When**: Making state-changing API requests.

**Do**:
```javascript
// plugins/axios.js
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
});

// Include CSRF token from cookie
api.interceptors.request.use(config => {
  const token = document.cookie
    .split('; ')
    .find(row => row.startsWith('csrftoken='))
    ?.split('=')[1];

  if (token) {
    config.headers['X-CSRFToken'] = token;
  }
  return config;
});

export default api;
```

**Don't**:
```javascript
// VULNERABLE: No CSRF protection
const deleteAccount = async (userId) => {
  await fetch(`/api/users/${userId}`, {
    method: 'DELETE',
  });
};
```

**Why**: Missing CSRF tokens allow attackers to perform actions on behalf of users.

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
  name: z.string(),
});

export const fetchUser = async (id) => {
  const response = await api.get(`/users/${id}`);

  // Validate response structure
  const user = UserSchema.parse(response.data);
  return user;
};
```

**Don't**:
```javascript
// VULNERABLE: Assumes response structure
export const fetchUser = async (id) => {
  const response = await api.get(`/users/${id}`);
  return response.data;  // May not match expected structure
};
```

**Why**: Malformed API responses can crash the app or inject unexpected data.

**Refs**: CWE-20

---

## Component Security

### Rule: Don't Trust Client-Side Authorization

**Level**: `warning`

**When**: Implementing protected features.

**Do**:
```vue
<template>
  <!-- UI hint only - server enforces access -->
  <AdminPanel v-if="user.isAdmin" />
</template>

<script setup>
// Component that fetches protected data
const AdminPanel = defineAsyncComponent(async () => {
  // API returns 403 if not authorized
  const data = await api.get('/admin/data');
  // ... render with data
});
</script>
```

**Don't**:
```vue
<template>
  <!-- VULNERABLE: Client-side only check -->
  <div v-if="user.isAdmin">
    <SensitiveData :data="secretData" />
  </div>
</template>

<script setup>
// VULNERABLE: Fetched regardless of client check
const secretData = await api.get('/secret');
</script>
```

**Why**: Client-side checks are easily bypassed. Server must enforce authorization.

**Refs**: CWE-602, OWASP A01:2025

---

## Router Security

### Rule: Implement Navigation Guards

**Level**: `warning`

**When**: Protecting routes.

**Do**:
```javascript
// router/index.js
import { createRouter } from 'vue-router';
import { useUserStore } from '@/stores/user';

const router = createRouter({
  routes: [
    {
      path: '/dashboard',
      component: Dashboard,
      meta: { requiresAuth: true }
    },
    {
      path: '/admin',
      component: Admin,
      meta: { requiresAuth: true, requiresAdmin: true }
    }
  ]
});

router.beforeEach(async (to, from) => {
  const userStore = useUserStore();

  if (to.meta.requiresAuth && !userStore.isAuthenticated) {
    return { path: '/login', query: { redirect: to.fullPath } };
  }

  if (to.meta.requiresAdmin && !userStore.isAdmin) {
    return { path: '/unauthorized' };
  }
});

export default router;
```

**Don't**:
```javascript
// VULNERABLE: No route protection
const router = createRouter({
  routes: [
    { path: '/admin', component: Admin }  // Anyone can access
  ]
});
```

**Why**: Navigation guards provide UX for auth flows, but server must still validate.

**Refs**: CWE-862

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| No v-html with user input | strict | CWE-79 |
| Sanitize dynamic attributes | strict | CWE-79 |
| No sensitive client state | strict | CWE-922 |
| Validate form inputs | strict | CWE-20 |
| CSRF tokens | strict | CWE-352 |
| Validate API responses | warning | CWE-20 |
| Server-side authorization | warning | CWE-602 |
| Navigation guards | warning | CWE-862 |

---

## Version History

- **v1.0.0** - Initial Vue.js security rules
