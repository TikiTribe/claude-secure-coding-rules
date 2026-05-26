# Angular Security Rules

Security rules for Angular development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/typescript/CLAUDE.md` - TypeScript security

---

## XSS Prevention

### Rule: Never Bypass Sanitization

**Level**: `strict`

**When**: Rendering dynamic content.

**Do**:
```typescript
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { SecurityContext } from '@angular/core';

@Component({
  selector: 'app-content',
  template: `
    <!-- Angular auto-escapes interpolated text by default -->
    <p>{{ userMessage }}</p>

    <!-- [innerHTML] sanitizes HTML automatically — no bypass needed -->
    <div [innerHTML]="trustedHtml"></div>

    <!-- Explicit sanitization for content assembled server-side -->
    <div [innerHTML]="explicitlySanitizedHtml"></div>
  `
})
export class ContentComponent {
  // Angular escapes this automatically in {{ }} binding
  userMessage = '<script>alert("xss")</script>';

  // Angular's [innerHTML] binding sanitizes this before rendering
  trustedHtml = '<strong>Bold text</strong>';

  constructor(private sanitizer: DomSanitizer) {}

  get explicitlySanitizedHtml(): string | null {
    // sanitize() keeps safe HTML and strips dangerous tags/attributes
    return this.sanitizer.sanitize(SecurityContext.HTML, this.trustedHtml);
  }
}
```

**Don't**:
```typescript
// VULNERABLE: bypassSecurityTrustHtml disables Angular's sanitizer entirely.
// Passing user input here allows arbitrary XSS.
get userContent(): SafeHtml {
  return this.sanitizer.bypassSecurityTrustHtml(this.userProvidedHtml);
}

// VULNERABLE: Bypass on user-provided URLs enables javascript: execution
get userUrl(): SafeUrl {
  return this.sanitizer.bypassSecurityTrustUrl(this.userInput);
}
```

**Why**: Angular's `[innerHTML]` binding already sanitizes HTML — no `bypassSecurityTrust*`
call is needed for ordinary rendering. Calling `bypassSecurityTrust*` marks content as
trusted and disables the sanitizer, which enables XSS when user input flows through it.
Use `DomSanitizer.sanitize(SecurityContext.HTML, content)` when you need explicit
sanitization with a return value.

**Refs**: CWE-79, OWASP A03:2025

---

### Rule: Validate Dynamic URLs

**Level**: `strict`

**When**: Binding user input to href, src, or other URL attributes.

**Do**:
```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-link',
  // Angular 17+ built-in control flow replaces *ngIf
  template: `
    @if (isValidUrl) {
      <a [href]="sanitizedUrl">Link</a>
    } @else {
      <span>Invalid URL</span>
    }
  `
})
export class LinkComponent {
  userUrl: string = '';

  get isValidUrl(): boolean {
    try {
      const parsed = new URL(this.userUrl);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  get sanitizedUrl(): string {
    return this.isValidUrl ? this.userUrl : '#';
  }
}
```

**Don't**:
```typescript
// VULNERABLE: javascript: URLs execute code when clicked
template: `<a [href]="userUrl">Link</a>`
```

**Why**: `javascript:` URLs execute code when clicked. Always validate the protocol
before binding a user-supplied value to a URL attribute.

**Refs**: CWE-79, CWE-601

---

## Authentication

### Rule: Use HTTP Interceptors for Auth

**Level**: `strict`

**When**: Adding authentication and CSRF tokens to API requests.

**Do**:
```typescript
// Functional interceptor — Angular 15+ recommended form
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { CsrfService } from './csrf.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const csrfService = inject(CsrfService);

  const authReq = req.clone({
    withCredentials: true,          // Send httpOnly auth cookie
    setHeaders: {
      'X-CSRF-Token': csrfService.getToken()
    }
  });
  return next(authReq);
};

// app.config.ts — register via provideHttpClient (Angular 15+)
import { provideHttpClient, withInterceptors } from '@angular/common/http';

export const appConfig = {
  providers: [
    provideHttpClient(withInterceptors([authInterceptor]))
  ]
};
```

**Don't**:
```typescript
// VULNERABLE: Token in localStorage is accessible via XSS
const token = localStorage.getItem('token');
headers.set('Authorization', `Bearer ${token}`);
```

**Why**: Tokens in `localStorage` are accessible to any script on the page, making
them easy XSS targets. `withCredentials: true` lets the browser send an httpOnly
cookie the JavaScript layer cannot read. CSRF tokens added via an interceptor
protect every mutating request without per-call boilerplate.

The class-based `HttpInterceptor` / `HTTP_INTERCEPTORS` token pattern works in
NgModule projects but is the legacy API. Prefer functional interceptors with
`withInterceptors()` for new code.

**Refs**: CWE-922, OWASP A02:2025

---

## Input Validation

### Rule: Validate Form Inputs

**Level**: `strict`

**When**: Processing user form submissions.

**Do**:
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-login',
  // Angular 17+ built-in control flow replaces *ngIf
  template: `
    <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
      <input formControlName="email" type="email">
      @if (loginForm.get('email')?.errors?.['email']) {
        <div>Invalid email</div>
      }
      <input formControlName="password" type="password">
      <button type="submit" [disabled]="loginForm.invalid">Login</button>
    </form>
  `
})
export class LoginComponent {
  loginForm: FormGroup;

  constructor(private fb: FormBuilder) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]]
    });
  }

  onSubmit() {
    if (this.loginForm.valid) {
      this.authService.login(this.loginForm.value);
    }
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No validation — any input reaches the auth service
onSubmit() {
  this.authService.login({
    email: this.emailInput,
    password: this.passwordInput
  });
}
```

**Why**: Unvalidated input causes unexpected errors and enables injection attacks.
Reactive forms with `Validators` reject malformed input before it reaches any
service or API.

**Refs**: CWE-20, OWASP A03:2025

---

## Route Guards

### Rule: Implement Route Guards

**Level**: `warning`

**When**: Protecting routes from unauthorized access.

**Do**:
```typescript
// Functional guard — Angular 15+ recommended form
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }
  return router.createUrlTree(['/login']);
};

// routes
const routes: Routes = [
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [authGuard]
  },
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [authGuard, adminGuard]
  }
];
```

**Don't**:
```typescript
// VULNERABLE: No route protection — any user reaches admin
const routes: Routes = [
  { path: 'admin', component: AdminComponent }
];
```

**Why**: Guards provide a UX-layer barrier for auth flows, but the server must
still validate every request. Client-side guards are not a substitute for
server-side authorization (see OWASP A01:2025 Broken Access Control).

The class-based `CanActivate` interface was deprecated in Angular 15. Use
`CanActivateFn` with `inject()` for new code. The class-based form remains
supported for legacy NgModule projects.

**Refs**: CWE-862, OWASP A01:2025

---

## API Security

### Rule: Validate API Responses

**Level**: `warning`

**When**: Processing data from APIs.

**Do**:
```typescript
// zod is a third-party schema validation library (npm install zod)
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string()
});

@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getUser(id: number): Observable<User> {
    return this.http.get(`/api/users/${id}`).pipe(
      map(response => {
        // Validate response structure at runtime
        return UserSchema.parse(response);
      }),
      catchError(error => {
        if (error instanceof z.ZodError) {
          console.error('Invalid API response', error);
        }
        throw error;
      })
    );
  }
}
```

**Don't**:
```typescript
// VULNERABLE: TypeScript generics are erased at runtime; no validation occurs
getUser(id: number): Observable<User> {
  return this.http.get<User>(`/api/users/${id}`);
}
```

**Why**: Malformed responses can crash the app or inject unexpected data. Runtime
schema validation catches structural mismatches that TypeScript generics cannot.

**Refs**: CWE-20

---

## Content Security

### Rule: Configure Content Security Policy

**Level**: `warning`

**When**: Deploying the application.

**Do**:
```typescript
// In server configuration or meta tag
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               style-src 'self' 'unsafe-inline';
               img-src 'self' https://cdn.myapp.com;">

// Note: style-src 'unsafe-inline' is commonly required for Angular global
// stylesheets. Evaluate nonce-based CSP for component styles when your
// build tooling supports it, to avoid the blanket unsafe-inline allowance.

// angular.json — enable subresource integrity for build output
{
  "projects": {
    "my-app": {
      "architect": {
        "build": {
          "options": {
            "subresourceIntegrity": true
          }
        }
      }
    }
  }
}
```

**Don't**:
```html
<!-- VULNERABLE: Allows any source and enables eval -->
<meta http-equiv="Content-Security-Policy"
      content="default-src *; script-src 'unsafe-eval'">
```

**Why**: CSP prevents XSS by controlling allowed content sources. `unsafe-eval`
allows `eval()` and similar constructs; combined with a wildcard `default-src`,
it removes virtually all XSS protection.

**Refs**: OWASP A05:2025

---

## State Management

### Rule: Don't Store Sensitive Data in Client State

**Level**: `strict`

**When**: Managing application state with NgRx or services.

**Do**:
```typescript
// state/user.reducer.ts
export interface UserState {
  id: number | null;
  email: string | null;
  name: string | null;
  isAuthenticated: boolean;
  // Tokens belong in httpOnly cookies, not client state
}

// auth.service.ts
@Injectable({ providedIn: 'root' })
export class AuthService {
  async login(credentials: Credentials): Promise<void> {
    // Server sets token in an httpOnly cookie; JavaScript cannot read it
    const response = await this.http.post('/api/login', credentials).toPromise();
    this.store.dispatch(loginSuccess({ user: response.user }));
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Tokens in client state are accessible to XSS attacks
export interface UserState {
  accessToken: string;
  refreshToken: string;
}
```

**Why**: Client-side state (NgRx store, services, `localStorage`) is readable by
any JavaScript executing on the page. An XSS payload can exfiltrate tokens stored
there. Keep tokens in httpOnly cookies where script cannot reach them.

**Refs**: CWE-922, CWE-312, OWASP A02:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Never bypass sanitization | strict | CWE-79 |
| Validate dynamic URLs | strict | CWE-79, CWE-601 |
| HTTP interceptors for auth | strict | CWE-922 |
| Validate form inputs | strict | CWE-20 |
| Route guards | warning | CWE-862 |
| Validate API responses | warning | CWE-20 |
| Content Security Policy | warning | - |
| No sensitive client state | strict | CWE-922, CWE-312 |

---

## Version History

- **v2.0.0** - Functional interceptors, functional guards, Angular 17 control flow, sanitization Do/Don't corrected
- **v1.0.0** - Initial Angular security rules
