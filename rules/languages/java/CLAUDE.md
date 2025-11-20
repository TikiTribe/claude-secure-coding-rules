# Java Security Rules

Security rules for Java development in Claude Code.

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

## Serialization

### Rule: Avoid Unsafe Deserialization

**Level**: `strict`

**When**: Deserializing external data.

**Do**:
```java
// Use JSON instead of Java serialization
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);

// If Java serialization is required, use allowlist
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

// Or use serialization filters (Java 9+)
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
import javax.validation.constraints.*;

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

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| No command injection | strict | CWE-78 |
| Safe deserialization | strict | CWE-502 |
| Strong cryptography | strict | CWE-327 |
| Path traversal prevention | strict | CWE-22 |
| XXE prevention | strict | CWE-611 |
| Safe error handling | warning | CWE-209 |
| Input validation | strict | CWE-20 |

---

## Version History

- **v1.0.0** - Initial Java security rules
