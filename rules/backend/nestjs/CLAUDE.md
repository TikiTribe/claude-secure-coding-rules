# NestJS Security Rules

Security rules for NestJS development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/languages/typescript/CLAUDE.md` - TypeScript security

---

## Input Validation

### Rule: Use Class-Validator for DTOs

**Level**: `strict`

**When**: Accepting request data.

**Do**:
```typescript
import { IsEmail, IsString, MinLength, MaxLength, IsInt, Min, Max } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password: string;

  @IsInt()
  @Min(0)
  @Max(150)
  @Transform(({ value }) => parseInt(value, 10))
  age: number;
}

// main.ts - Enable global validation
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,           // Strip unknown properties
  forbidNonWhitelisted: true, // Throw on unknown properties
  transform: true,
}));
```

**Don't**:
```typescript
// VULNERABLE: No validation
@Post('users')
createUser(@Body() body: any) {
  return this.userService.create(body);
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## Authentication

### Rule: Implement JWT Guards Properly

**Level**: `strict`

**When**: Protecting routes with JWT authentication.

**Do**:
```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
      algorithms: ['HS256'],
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.userService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}

// Controller
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
export class AdminController {
  @Get('dashboard')
  getDashboard() {
    return this.adminService.getDashboard();
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Hardcoded secret
super({
  secretOrKey: 'hardcoded-secret-key',
});

// VULNERABLE: No expiration check
super({
  ignoreExpiration: true,
});
```

**Why**: Weak JWT configuration allows token forgery and unauthorized access.

**Refs**: CWE-347, OWASP A07:2025

---

## Authorization

### Rule: Implement Role-Based Access Control

**Level**: `strict`

**When**: Protecting resources based on user roles.

**Do**:
```typescript
import { SetMetadata } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}

// Resource ownership check
@Get(':id')
async getDocument(@Param('id') id: string, @Request() req) {
  const document = await this.documentService.findOne(id);

  if (document.ownerId !== req.user.id && !req.user.roles.includes('admin')) {
    throw new ForbiddenException();
  }

  return document;
}
```

**Don't**:
```typescript
// VULNERABLE: No ownership check (IDOR)
@Get(':id')
async getDocument(@Param('id') id: string) {
  return this.documentService.findOne(id);
}
```

**Why**: Missing authorization checks allow users to access others' data.

**Refs**: CWE-862, OWASP A01:2025

---

## Rate Limiting

### Rule: Implement Rate Limiting

**Level**: `warning`

**When**: Protecting endpoints from abuse.

**Do**:
```typescript
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60,
      limit: 10,
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}

// Custom limits per endpoint
@Controller('auth')
export class AuthController {
  @Post('login')
  @Throttle(5, 60)  // 5 requests per minute
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }
}
```

**Don't**:
```typescript
// VULNERABLE: No rate limiting
@Post('login')
login(@Body() dto: LoginDto) {
  return this.authService.login(dto);
}
```

**Why**: Missing rate limits enable brute force attacks and DoS.

**Refs**: CWE-307, OWASP A07:2025

---

## Database Security

### Rule: Use TypeORM Safely

**Level**: `strict`

**When**: Querying databases.

**Do**:
```typescript
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  // Repository methods are safe
  findByEmail(email: string): Promise<User> {
    return this.userRepository.findOne({ where: { email } });
  }

  // QueryBuilder with parameters
  findActive(status: string): Promise<User[]> {
    return this.userRepository
      .createQueryBuilder('user')
      .where('user.status = :status', { status })
      .getMany();
  }
}
```

**Don't**:
```typescript
// VULNERABLE: SQL injection
findByEmail(email: string) {
  return this.userRepository.query(
    `SELECT * FROM users WHERE email = '${email}'`
  );
}
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

## Security Headers

### Rule: Use Helmet for Security Headers

**Level**: `warning`

**When**: Configuring the application.

**Do**:
```typescript
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet());

  // Or configure individually
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
  }));

  await app.listen(3000);
}
```

**Don't**:
```typescript
// No security headers
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
```

**Why**: Missing headers enable clickjacking, MIME sniffing, and XSS attacks.

**Refs**: OWASP A05:2025

---

## CORS Configuration

### Rule: Configure CORS Restrictively

**Level**: `strict`

**When**: Enabling cross-origin requests.

**Do**:
```typescript
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: ['https://myapp.com', 'https://admin.myapp.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  await app.listen(3000);
}
```

**Don't**:
```typescript
// VULNERABLE: Allows any origin
app.enableCors();

// VULNERABLE: Wildcard with credentials
app.enableCors({
  origin: '*',
  credentials: true,
});
```

**Why**: Permissive CORS allows malicious sites to make authenticated requests.

**Refs**: CWE-942, OWASP A05:2025

---

## Error Handling

### Rule: Use Exception Filters

**Level**: `warning`

**When**: Handling errors.

**Do**:
```typescript
import { ExceptionFilter, Catch, ArgumentsHost, HttpException, Logger } from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();

    let status = 500;
    let message = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      message = exception.message;
    } else {
      // Log full error internally
      this.logger.error('Unhandled exception', exception);
    }

    response.status(status).json({
      statusCode: status,
      message,
    });
  }
}
```

**Don't**:
```typescript
// VULNERABLE: Exposes stack traces
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse();
    response.status(500).json({
      message: exception.message,
      stack: exception.stack,  // Leaks internals
    });
  }
}
```

**Why**: Stack traces reveal internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Class-validator DTOs | strict | CWE-20 |
| JWT guards | strict | CWE-347 |
| RBAC authorization | strict | CWE-862 |
| Rate limiting | warning | CWE-307 |
| TypeORM parameters | strict | CWE-89 |
| Helmet headers | warning | - |
| CORS configuration | strict | CWE-942 |
| Exception filters | warning | CWE-209 |

---

## Version History

- **v1.0.0** - Initial NestJS security rules
