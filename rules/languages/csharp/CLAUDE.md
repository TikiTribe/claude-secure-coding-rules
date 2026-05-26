# C# Security Rules

Security rules for C# development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Injection Prevention

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```csharp
// Entity Framework
var user = await context.Users
    .Where(u => u.Email == email)
    .FirstOrDefaultAsync();

// ADO.NET with parameters
using var command = new SqlCommand(
    "SELECT * FROM Users WHERE Email = @Email", connection);
command.Parameters.AddWithValue("@Email", email);

// Dapper
var user = await connection.QueryFirstOrDefaultAsync<User>(
    "SELECT * FROM Users WHERE Email = @Email",
    new { Email = email });
```

**Don't**:
```csharp
// VULNERABLE: SQL injection
var query = $"SELECT * FROM Users WHERE Email = '{email}'";
var user = await connection.QueryFirstOrDefaultAsync<User>(query);
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

### Rule: Prevent Command Injection

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```csharp
using System.Diagnostics;

public string RunCommand(string filename)
{
    // Validate input
    if (filename.Contains("..") || filename.Contains(";"))
    {
        throw new ArgumentException("Invalid filename");
    }

    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "ls",
            Arguments = filename,  // Passed as argument, not shell
            RedirectStandardOutput = true,
            UseShellExecute = false
        }
    };

    process.Start();
    return process.StandardOutput.ReadToEnd();
}
```

**Don't**:
```csharp
// VULNERABLE: Command injection
Process.Start("cmd.exe", $"/c dir {userInput}");
```

**Why**: Shell metacharacters allow executing arbitrary commands.

**Refs**: CWE-78, OWASP A03:2025

---

## Serialization

### Rule: Avoid Unsafe Deserialization

**Level**: `strict`

**When**: Deserializing external data.

**Do**:
```csharp
using System.Text.Json;

// Use System.Text.Json (secure by default)
var user = JsonSerializer.Deserialize<User>(jsonString);

// Or Newtonsoft with type restrictions
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None  // Disable type handling
};
var user = JsonConvert.DeserializeObject<User>(json, settings);
```

**Don't**:
```csharp
// VULNERABLE: Arbitrary code execution
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);

// VULNERABLE: Type name handling
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(json, settings);
```

**Why**: Unsafe deserialization can execute arbitrary code via gadget chains.

**Refs**: CWE-502, OWASP A08:2025

---

## Cryptography

### Rule: Use Strong Cryptographic Algorithms

**Level**: `strict`

**When**: Encrypting data or hashing passwords.

**Do**:
```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

// Secure random
var token = new byte[32];
RandomNumberGenerator.Fill(token);

// AES-GCM encryption (.NET 8+)
// AesGcm is the correct class; CipherMode.GCM does not exist in System.Security.Cryptography.
var key = new byte[32]; // 256-bit key
RandomNumberGenerator.Fill(key);
using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);
var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // 12 bytes
RandomNumberGenerator.Fill(nonce);
var plaintext = System.Text.Encoding.UTF8.GetBytes("sensitive data");
var ciphertext = new byte[plaintext.Length];
var tag = new byte[16];
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
// Transmit or store: nonce + tag + ciphertext (all three are required for decryption)

// Password hashing with Identity
var hasher = new PasswordHasher<User>();
var hash = hasher.HashPassword(user, password);
var result = hasher.VerifyHashedPassword(user, hash, password);
```

**Don't**:
```csharp
// VULNERABLE: Weak algorithms
using var md5 = MD5.Create();
var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

// VULNERABLE: Predictable random
var random = new Random();
var token = random.Next();
```

**Why**: Weak cryptography allows attackers to decrypt data or crack passwords.

**Refs**: CWE-327, CWE-328, CWE-330

---

## Path Traversal

### Rule: Validate File Paths

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```csharp
public string SafeGetFile(string filename)
{
    var basePath = Path.GetFullPath("/app/uploads");
    var requestedPath = Path.GetFullPath(
        Path.Combine(basePath, filename));

    // Ensure path is within base directory
    if (!requestedPath.StartsWith(basePath))
    {
        throw new SecurityException("Path traversal attempt detected");
    }

    return File.ReadAllText(requestedPath);
}
```

**Don't**:
```csharp
// VULNERABLE: Path traversal
public string GetFile(string filename)
{
    return File.ReadAllText($"/app/uploads/{filename}");
}
```

**Why**: Path traversal allows reading sensitive files outside intended directories.

**Refs**: CWE-22, OWASP A01:2025

---

## XML Processing

### Rule: Prevent XXE Attacks

**Level**: `strict`

**When**: Parsing XML from external sources.

**Do**:
```csharp
using System.Xml;

var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};

using var reader = XmlReader.Create(stream, settings);
var doc = new XmlDocument();
doc.Load(reader);
```

**Don't**:
```csharp
// VULNERABLE: XXE attack
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver();  // Allows external entities
doc.LoadXml(untrustedXml);
```

**Why**: XXE allows reading local files, SSRF, and denial of service.

**Refs**: CWE-611, OWASP A05:2025

---

## Input Validation

### Rule: Validate All External Input

**Level**: `strict`

**When**: Processing user input.

**Do**:
```csharp
using System.ComponentModel.DataAnnotations;

public class UserDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [StringLength(128, MinimumLength = 8)]
    public string Password { get; set; }

    [Range(0, 150)]
    public int? Age { get; set; }
}

[HttpPost("users")]
public IActionResult CreateUser([FromBody] UserDto dto)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }
    // dto is validated
    return Ok(userService.Create(dto));
}
```

**Don't**:
```csharp
// VULNERABLE: No validation
[HttpPost("users")]
public IActionResult CreateUser([FromBody] dynamic dto)
{
    return Ok(userService.Create(dto));
}
```

**Why**: Unvalidated input enables injection attacks and business logic bypass.

**Refs**: CWE-20, OWASP A03:2025

---

## Error Handling

### Rule: Don't Expose Stack Traces

**Level**: `warning`

**When**: Handling exceptions.

**Do**:
```csharp
public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public async ValueTask<bool> TryHandleAsync(
        HttpContext context,
        Exception exception,
        CancellationToken token)
    {
        // Log full details internally
        _logger.LogError(exception, "Unhandled exception");

        // Return safe message to client
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Internal server error"
        }, token);

        return true;
    }
}
```

**Don't**:
```csharp
// VULNERABLE: Exposes stack trace
app.UseDeveloperExceptionPage();  // In production!

// VULNERABLE: Returns exception details
catch (Exception ex)
{
    return StatusCode(500, ex.ToString());
}
```

**Why**: Stack traces reveal internal paths, library versions, and code structure.

**Refs**: CWE-209, OWASP A05:2025

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
| Input validation | strict | CWE-20 |
| Safe error handling | warning | CWE-209 |

---

## Version History

- **v1.0.0** - Initial C# security rules
