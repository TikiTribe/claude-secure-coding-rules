# Next.js Security Rules

Security rules for Next.js development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security
- `rules/frontend/react/CLAUDE.md` - React security

---

## Server Components

### Rule: Separate Server and Client Data

**Level**: `strict`

**When**: Using React Server Components (RSC).

**Do**:
```jsx
// app/users/page.tsx (Server Component)
import { db } from '@/lib/db';

async function UsersPage() {
  const users = await db.user.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      // Don't select password_hash
    },
  });

  return <UserList users={users} />;
}

// Only pass safe data to client components
```

**Don't**:
```jsx
// VULNERABLE: Leaking server data to client
async function UsersPage() {
  const users = await db.user.findMany();  // Includes all fields
  return <UserList users={users} />;  // password_hash sent to client
}
```

**Why**: Server-only data can leak to client bundles. Select only needed fields.

**Refs**: CWE-200, OWASP A01:2025

---

### Rule: Mark Server-Only Code

**Level**: `warning`

**When**: Using server-only modules like database clients.

**Do**:
```javascript
// lib/db.ts
import 'server-only';  // Prevents import in client components
import { PrismaClient } from '@prisma/client';

export const db = new PrismaClient();

// lib/auth.ts
import 'server-only';

export async function getServerSession() {
  // Server-only auth logic
}
```

**Don't**:
```javascript
// VULNERABLE: Can be imported anywhere
// lib/db.ts
import { PrismaClient } from '@prisma/client';
export const db = new PrismaClient();
```

**Why**: `server-only` package errors if imported in client components, preventing accidental data exposure.

**Refs**: CWE-200

---

## API Routes

### Rule: Validate API Route Inputs

**Level**: `strict`

**When**: Creating API routes.

**Do**:
```typescript
// app/api/users/route.ts
import { z } from 'zod';
import { NextResponse } from 'next/server';

const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const validated = createUserSchema.parse(body);

    const user = await createUser(validated);
    return NextResponse.json(user, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: 'Validation failed' }, { status: 400 });
    }
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No validation
export async function POST(request: Request) {
  const body = await request.json();
  const user = await createUser(body);
  return NextResponse.json(user);
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

### Rule: Implement Authentication in API Routes

**Level**: `strict`

**When**: Creating protected API endpoints.

**Do**:
```typescript
// app/api/admin/route.ts
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { NextResponse } from 'next/server';

export async function GET() {
  const session = await getServerSession(authOptions);

  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const data = await getAdminData();
  return NextResponse.json(data);
}
```

**Don't**:
```typescript
// VULNERABLE: No authentication
export async function GET() {
  const data = await getAdminData();
  return NextResponse.json(data);
}
```

**Why**: Unprotected API routes allow unauthorized access to sensitive data.

**Refs**: CWE-862, OWASP A01:2025

---

## Server Actions

### Rule: Validate Server Action Inputs

**Level**: `strict`

**When**: Using Server Actions for mutations.

**Do**:
```typescript
// app/actions.ts
'use server';

import { z } from 'zod';
import { getServerSession } from 'next-auth';
import { revalidatePath } from 'next/cache';

const updateProfileSchema = z.object({
  name: z.string().min(1).max(100),
  bio: z.string().max(500).optional(),
});

export async function updateProfile(formData: FormData) {
  const session = await getServerSession();
  if (!session) {
    throw new Error('Unauthorized');
  }

  const validated = updateProfileSchema.parse({
    name: formData.get('name'),
    bio: formData.get('bio'),
  });

  await db.user.update({
    where: { id: session.user.id },
    data: validated,
  });

  revalidatePath('/profile');
}
```

**Don't**:
```typescript
'use server';

// VULNERABLE: No validation or auth
export async function updateProfile(formData: FormData) {
  await db.user.update({
    where: { id: formData.get('userId') },  // User controls ID!
    data: {
      name: formData.get('name'),
      role: formData.get('role'),  // Privilege escalation
    },
  });
}
```

**Why**: Server Actions are public endpoints. Attackers can call them directly with malicious data.

**Refs**: CWE-20, CWE-862, OWASP A01:2025

---

## Environment Variables

### Rule: Protect Server Environment Variables

**Level**: `strict`

**When**: Using environment variables.

**Do**:
```javascript
// next.config.js
module.exports = {
  // Only NEXT_PUBLIC_ vars are exposed to client
  env: {
    // Don't put secrets here
  },
};

// Server-only access
// app/api/route.ts
const apiKey = process.env.API_SECRET_KEY;  // Server only

// Client-safe variables
// components/Analytics.tsx
const trackingId = process.env.NEXT_PUBLIC_ANALYTICS_ID;
```

```env
# .env.local
DATABASE_URL=postgresql://...     # Server only
API_SECRET_KEY=sk_...             # Server only
NEXT_PUBLIC_APP_URL=https://...   # Safe for client
```

**Don't**:
```javascript
// VULNERABLE: Exposing secrets
module.exports = {
  env: {
    API_KEY: process.env.API_KEY,  // Now in client bundle!
  },
};
```

**Why**: Non-NEXT_PUBLIC_ variables should stay server-side. Client bundles are public.

**Refs**: CWE-200, OWASP A02:2025

---

## Middleware

### Rule: Implement Security Middleware

**Level**: `warning`

**When**: Adding cross-cutting security concerns.

**Do**:
```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function middleware(request: NextRequest) {
  // Protected routes
  if (request.nextUrl.pathname.startsWith('/dashboard')) {
    const token = await getToken({ req: request });

    if (!token) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }

  // Security headers
  const response = NextResponse.next();
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  return response;
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/:path*'],
};
```

**Don't**:
```typescript
// No middleware = no centralized security
```

**Why**: Middleware provides centralized authentication and security headers.

**Refs**: OWASP A05:2025

---

## Image Handling

### Rule: Configure Allowed Image Domains

**Level**: `strict`

**When**: Using next/image with external sources.

**Do**:
```javascript
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'cdn.myapp.com',
      },
      {
        protocol: 'https',
        hostname: 'avatars.githubusercontent.com',
      },
    ],
  },
};
```

**Don't**:
```javascript
// VULNERABLE: Allows any domain
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',  // Any domain!
      },
    ],
  },
};
```

**Why**: Unrestricted image domains enable SSRF and hosting of malicious content.

**Refs**: CWE-918, OWASP A10:2025

---

## Redirects

### Rule: Validate Redirect URLs

**Level**: `strict`

**When**: Implementing redirects based on user input.

**Do**:
```typescript
// app/api/callback/route.ts
import { NextResponse } from 'next/server';

const ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/settings'];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const redirectTo = searchParams.get('redirect') || '/dashboard';

  // Validate redirect target
  if (!ALLOWED_REDIRECTS.includes(redirectTo)) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  return NextResponse.redirect(new URL(redirectTo, request.url));
}
```

**Don't**:
```typescript
// VULNERABLE: Open redirect
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const redirectTo = searchParams.get('redirect');

  return NextResponse.redirect(redirectTo);  // Attacker controls URL
}
```

**Why**: Open redirects enable phishing attacks by redirecting to malicious sites.

**Refs**: CWE-601, OWASP A01:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Separate server/client data | strict | CWE-200 |
| Mark server-only code | warning | CWE-200 |
| Validate API inputs | strict | CWE-20 |
| API authentication | strict | CWE-862 |
| Validate Server Actions | strict | CWE-20 |
| Protect env variables | strict | CWE-200 |
| Security middleware | warning | - |
| Restrict image domains | strict | CWE-918 |
| Validate redirects | strict | CWE-601 |

---

## Version History

- **v1.0.0** - Initial Next.js security rules (App Router)
