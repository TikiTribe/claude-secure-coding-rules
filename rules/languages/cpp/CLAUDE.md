# C++ Security Rules

Security rules for C++ development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Memory Safety

### Rule: Use Smart Pointers

**Level**: `strict`

**When**: Managing dynamic memory.

**Do**:
```cpp
#include <memory>

// Safe: unique_ptr for single ownership
auto data = std::make_unique<DataObject>();

// Safe: shared_ptr for shared ownership
auto config = std::make_shared<Config>();

// Safe: RAII pattern
class FileHandler {
    std::unique_ptr<FILE, decltype(&fclose)> file;
public:
    FileHandler(const char* path)
        : file(fopen(path, "r"), &fclose) {}
};
```

**Don't**:
```cpp
// VULNERABLE: Manual memory management
DataObject* data = new DataObject();
// ... code that might throw or return early
delete data;  // May never be reached

// VULNERABLE: Array new/delete mismatch
int* arr = new int[100];
delete arr;  // Should be delete[]

// VULNERABLE: Use after free
Data* ptr = new Data();
delete ptr;
ptr->process();  // Undefined behavior
```

**Why**: Manual memory management leads to memory leaks, double-free, and use-after-free vulnerabilities that can be exploited for code execution.

**Refs**: CWE-416, CWE-415, CWE-401, OWASP A06:2025

---

### Rule: Prevent Buffer Overflows

**Level**: `strict`

**When**: Working with arrays and buffers.

**Do**:
```cpp
#include <vector>
#include <array>
#include <string>

// Safe: Use std::vector
std::vector<int> numbers(100);
numbers.at(50) = 42;  // Bounds checking

// Safe: Use std::array for fixed size
std::array<char, 256> buffer;

// Safe: Use std::string
std::string name = user_input;

// Safe: Bounds-checked copy
void safe_copy(char* dest, size_t dest_size, const char* src) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}
```

**Don't**:
```cpp
// VULNERABLE: Stack buffer overflow
char buffer[256];
strcpy(buffer, user_input);  // No bounds checking

// VULNERABLE: gets() is always unsafe
char input[100];
gets(input);  // Removed in C11

// VULNERABLE: sprintf overflow
char msg[50];
sprintf(msg, "User: %s", username);  // May overflow

// VULNERABLE: Unchecked array access
int arr[10];
arr[user_index] = value;  // No bounds check
```

**Why**: Buffer overflows allow attackers to overwrite memory, potentially executing arbitrary code or crashing the application.

**Refs**: CWE-120, CWE-121, CWE-122, OWASP A06:2025

---

### Rule: Initialize Variables

**Level**: `warning`

**When**: Declaring variables.

**Do**:
```cpp
// Safe: Initialize at declaration
int count = 0;
std::string name{};
double* ptr = nullptr;

// Safe: Use braced initialization
std::vector<int> data{1, 2, 3};

// Safe: Initialize all struct members
struct Config {
    int timeout = 30;
    bool enabled = false;
    std::string host{};
};
```

**Don't**:
```cpp
// VULNERABLE: Uninitialized variables
int count;
if (condition) count = 10;
use(count);  // May be uninitialized

// VULNERABLE: Uninitialized pointer
char* buffer;
strcpy(buffer, data);  // Undefined behavior

// VULNERABLE: Partial struct initialization
struct Data {
    int x;
    int y;
};
Data d;
d.x = 1;  // d.y is uninitialized
```

**Why**: Uninitialized variables contain garbage data, leading to unpredictable behavior and potential security vulnerabilities.

**Refs**: CWE-457, CWE-908

---

## Input Validation

### Rule: Validate Integer Operations

**Level**: `strict`

**When**: Performing arithmetic with user input.

**Do**:
```cpp
#include <limits>
#include <stdexcept>

// Safe: Check for overflow before operation
int safe_add(int a, int b) {
    if (b > 0 && a > std::numeric_limits<int>::max() - b) {
        throw std::overflow_error("Integer overflow");
    }
    if (b < 0 && a < std::numeric_limits<int>::min() - b) {
        throw std::underflow_error("Integer underflow");
    }
    return a + b;
}

// Safe: Use safe integer library
#include <SafeInt.hpp>
SafeInt<int> safe_value = user_input;
SafeInt<int> result = safe_value * multiplier;

// Safe: Validate array indices
if (index >= 0 && index < static_cast<int>(vec.size())) {
    return vec[index];
}
```

**Don't**:
```cpp
// VULNERABLE: Unchecked arithmetic
int total = count * price;  // May overflow

// VULNERABLE: Signed/unsigned mismatch
size_t len = get_length();
if (len > 0) {
    int index = len - 1;  // Conversion issues
}

// VULNERABLE: Size calculation overflow
size_t size = num_elements * element_size;
char* buffer = new char[size];  // May allocate too little
```

**Why**: Integer overflow can cause buffer overflows, infinite loops, and incorrect security checks.

**Refs**: CWE-190, CWE-191, CWE-681

---

### Rule: Validate Format Strings

**Level**: `strict`

**When**: Using printf-style functions.

**Do**:
```cpp
#include <cstdio>
#include <format>  // C++20

// Safe: Use fixed format strings
printf("%s: %d\n", label, value);

// Safe: C++20 std::format
std::string msg = std::format("User: {}", username);

// Safe: Use iostream
std::cout << "User: " << username << std::endl;

// Safe: If user string must be printed
printf("%s", user_string);  // Not as format string
```

**Don't**:
```cpp
// VULNERABLE: User input as format string
printf(user_input);  // Format string attack

// VULNERABLE: Mismatched format specifiers
printf("%s", integer_value);  // Type confusion

// VULNERABLE: Missing arguments
printf("%s %s %s", str1, str2);  // Missing third argument
```

**Why**: Format string vulnerabilities allow attackers to read memory, crash applications, or execute arbitrary code.

**Refs**: CWE-134, OWASP A03:2025

---

## Secure Coding Patterns

### Rule: Use RAII for Resource Management

**Level**: `warning`

**When**: Managing resources (files, locks, connections).

**Do**:
```cpp
#include <fstream>
#include <mutex>

// Safe: RAII file handling
void process_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("Cannot open file");
    // File automatically closed when function exits
}

// Safe: RAII mutex locking
class ThreadSafe {
    mutable std::mutex mtx;
    int data;
public:
    int get() const {
        std::lock_guard<std::mutex> lock(mtx);
        return data;  // Lock released automatically
    }
};

// Safe: Custom RAII wrapper
class DatabaseConnection {
    Connection* conn;
public:
    DatabaseConnection() : conn(db_connect()) {}
    ~DatabaseConnection() { if (conn) db_close(conn); }
    // Delete copy operations
    DatabaseConnection(const DatabaseConnection&) = delete;
    DatabaseConnection& operator=(const DatabaseConnection&) = delete;
};
```

**Don't**:
```cpp
// VULNERABLE: Manual resource management
FILE* f = fopen("data.txt", "r");
if (!f) return -1;
// ... code that might throw or return
fclose(f);  // May not be reached

// VULNERABLE: Manual lock management
mutex.lock();
// ... code that might throw
mutex.unlock();  // May deadlock
```

**Why**: Manual resource management leads to resource leaks and deadlocks, especially when exceptions or early returns occur.

**Refs**: CWE-404, CWE-772

---

### Rule: Prevent Command Injection

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```cpp
#include <cstdlib>
#include <array>

// Safe: Avoid system() entirely when possible
// Use library functions instead

// Safe: If external command needed, use execv family
#include <unistd.h>
void safe_execute(const std::string& file) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - no shell involved
        execlp("cat", "cat", file.c_str(), nullptr);
        _exit(1);
    }
    // Parent waits
    waitpid(pid, nullptr, 0);
}

// Safe: Strict input validation
bool is_safe_filename(const std::string& name) {
    return std::all_of(name.begin(), name.end(), [](char c) {
        return std::isalnum(c) || c == '.' || c == '_';
    });
}
```

**Don't**:
```cpp
// VULNERABLE: Command injection
std::string cmd = "ls " + user_input;
system(cmd.c_str());

// VULNERABLE: Shell metacharacters
std::string filename = user_input;
system(("cat " + filename).c_str());  // Could be "; rm -rf /"

// VULNERABLE: popen with user input
FILE* pipe = popen(("grep " + pattern).c_str(), "r");
```

**Why**: Command injection allows attackers to execute arbitrary system commands with the application's privileges.

**Refs**: CWE-78, OWASP A03:2025

---

## Cryptography

### Rule: Use Modern Cryptographic Libraries

**Level**: `strict`

**When**: Implementing cryptographic operations.

**Do**:
```cpp
#include <openssl/evp.h>
#include <openssl/rand.h>

// Safe: Use OpenSSL or similar vetted library
unsigned char key[32];
if (RAND_bytes(key, sizeof(key)) != 1) {
    throw std::runtime_error("Failed to generate random bytes");
}

// Safe: Use authenticated encryption (GCM)
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);

// Safe: Constant-time comparison for secrets
#include <openssl/crypto.h>
bool verify(const unsigned char* a, const unsigned char* b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}
```

**Don't**:
```cpp
// VULNERABLE: Custom crypto implementation
int my_encrypt(char* data, const char* key) {
    for (int i = 0; i < strlen(data); i++) {
        data[i] ^= key[i % strlen(key)];  // XOR is not encryption
    }
}

// VULNERABLE: Weak algorithms
#include <openssl/md5.h>
MD5(password, strlen(password), hash);  // MD5 is broken

// VULNERABLE: Timing attack in comparison
bool check_token(const char* a, const char* b) {
    return strcmp(a, b) == 0;  // Short-circuit reveals length
}
```

**Why**: Custom cryptography and weak algorithms provide false security. Timing attacks can leak secrets through execution time differences.

**Refs**: CWE-327, CWE-328, CWE-208

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Use smart pointers | strict | CWE-416 |
| Prevent buffer overflows | strict | CWE-120 |
| Initialize variables | warning | CWE-457 |
| Validate integer operations | strict | CWE-190 |
| Validate format strings | strict | CWE-134 |
| RAII resource management | warning | CWE-404 |
| Prevent command injection | strict | CWE-78 |
| Modern cryptography | strict | CWE-327 |

---

## Version History

- **v1.0.0** - Initial C++ security rules
