# TypeScript Security Rules

Security rules for TypeScript development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/javascript/CLAUDE.md` - JavaScript security (all rules apply)

---

## Type Safety

### Rule: Use Strict TypeScript Configuration

**Level**: `warning`

**When**: Configuring TypeScript projects.

**Do**:
```json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true
  }
}
```

**Don't**:
```json
{
  "compilerOptions": {
    "strict": false,
    "noImplicitAny": false
  }
}
```

**Why**: Strict mode catches type errors that could lead to runtime vulnerabilities.

**Refs**: CWE-704

---

### Rule: Validate External Data with Runtime Checks

**Level**: `strict`

**When**: Processing data from APIs, user input, or external sources.

**Do**:
```typescript
import { z } from 'zod';

// Define schema
const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  role: z.enum(['user', 'admin']),
});

type User = z.infer<typeof UserSchema>;

async function fetchUser(id: number): Promise<User> {
  const response = await fetch(`/api/users/${id}`);
  const data = await response.json();

  // Runtime validation
  return UserSchema.parse(data);
}
```

**Don't**:
```typescript
interface User {
  id: number;
  email: string;
}

async function fetchUser(id: number): Promise<User> {
  const response = await fetch(`/api/users/${id}`);
  // VULNERABLE: Type assertion without validation
  return response.json() as User;
}
```

**Why**: TypeScript types are erased at runtime. External data needs runtime validation.

**Refs**: CWE-20, OWASP A03:2025

---

### Rule: Avoid Type Assertions on Untrusted Data

**Level**: `strict`

**When**: Handling data from external sources.

**Do**:
```typescript
function processInput(input: unknown): string {
  if (typeof input === 'string') {
    return input.trim();
  }
  throw new Error('Invalid input type');
}

// With type guards
function isUser(obj: unknown): obj is User {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'id' in obj &&
    typeof (obj as User).id === 'number'
  );
}
```

**Don't**:
```typescript
function processInput(input: unknown): string {
  // VULNERABLE: Assumes type without checking
  return (input as string).trim();
}

// VULNERABLE: Double assertion bypasses type safety
const data = JSON.parse(text) as unknown as SecretData;
```

**Why**: Type assertions bypass TypeScript's type checking, allowing unsafe operations.

**Refs**: CWE-704, CWE-20

---

## API Security

### Rule: Type API Responses Correctly

**Level**: `warning`

**When**: Defining types for API endpoints.

**Do**:
```typescript
// Separate internal and API types
interface UserInternal {
  id: number;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

// API response type (no sensitive fields)
interface UserResponse {
  id: number;
  email: string;
  createdAt: string;
}

function toUserResponse(user: UserInternal): UserResponse {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt.toISOString(),
  };
}
```

**Don't**:
```typescript
// VULNERABLE: Same type for internal and API
interface User {
  id: number;
  email: string;
  passwordHash: string;  // Leaked to API!
}

app.get('/user/:id', (req, res) => {
  const user = getUser(req.params.id);
  res.json(user);  // Sends passwordHash
});
```

**Why**: Separate types prevent accidental exposure of sensitive fields in API responses.

**Refs**: CWE-200, OWASP A01:2025

---

### Rule: Use Branded Types for Sensitive Data

**Level**: `advisory`

**When**: Handling IDs, tokens, or other sensitive values.

**Do**:
```typescript
// Branded types prevent mixing up IDs
type UserId = string & { readonly brand: unique symbol };
type PostId = string & { readonly brand: unique symbol };

function createUserId(id: string): UserId {
  return id as UserId;
}

function getUser(id: UserId): User {
  // Can only accept UserId, not PostId
}

// Prevents this mistake:
// getUser(postId);  // Type error!
```

**Don't**:
```typescript
// All IDs are interchangeable strings
function getUser(id: string): User { }
function getPost(id: string): Post { }

// Easy to mix up
const user = getUser(postId);  // No error, but wrong!
```

**Why**: Branded types prevent accidental misuse of sensitive identifiers.

**Refs**: CWE-704

---

## Null Safety

### Rule: Handle Nullable Values Explicitly

**Level**: `warning`

**When**: Working with potentially undefined values.

**Do**:
```typescript
function getUserEmail(userId: string): string | null {
  const user = users.get(userId);

  // Explicit null check
  if (!user) {
    return null;
  }

  return user.email;
}

// Optional chaining with nullish coalescing
const email = user?.email ?? 'default@example.com';

// Array access with noUncheckedIndexedAccess
const first = items[0];
if (first !== undefined) {
  process(first);
}
```

**Don't**:
```typescript
function getUserEmail(userId: string): string {
  // VULNERABLE: May throw at runtime
  return users.get(userId)!.email;
}

// Non-null assertion on external data
const data = JSON.parse(text)!;
```

**Why**: Non-null assertions (!) can cause runtime crashes with untrusted data.

**Refs**: CWE-476

---

## Enum Safety

### Rule: Use String Enums for External Data

**Level**: `warning`

**When**: Defining enums that interact with external systems.

**Do**:
```typescript
// String enums are safer for serialization
enum UserRole {
  Admin = 'admin',
  User = 'user',
  Guest = 'guest',
}

// Or use const objects
const UserRole = {
  Admin: 'admin',
  User: 'user',
  Guest: 'guest',
} as const;

type UserRole = typeof UserRole[keyof typeof UserRole];
```

**Don't**:
```typescript
// Numeric enums can be bypassed
enum UserRole {
  Admin,  // 0
  User,   // 1
  Guest,  // 2
}

function setRole(role: UserRole) {
  // Attacker can pass any number
}

setRole(999);  // No type error!
```

**Why**: Numeric enums accept any number at runtime, bypassing validation.

**Refs**: CWE-20

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Strict tsconfig | warning | CWE-704 |
| Runtime validation | strict | CWE-20 |
| Avoid type assertions | strict | CWE-704 |
| Separate API types | warning | CWE-200 |
| Branded types | advisory | CWE-704 |
| Null safety | warning | CWE-476 |
| String enums | warning | CWE-20 |

**Note**: All JavaScript security rules also apply to TypeScript.

---

## Version History

- **v1.0.0** - Initial TypeScript security rules
