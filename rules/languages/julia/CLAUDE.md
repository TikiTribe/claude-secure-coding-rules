# Julia Security Rules

Security rules for Julia development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/_core/ai-security.md` - AI/ML security (critical for Julia scientific computing)

---

## Code Execution

### Rule: Avoid Dangerous Metaprogramming

**Level**: `strict`

**When**: Processing user input or dynamic code.

**Do**:
```julia
# Safe: Use dispatch instead of eval
function process_operation(op::Symbol, data)
    if op == :mean
        return mean(data)
    elseif op == :sum
        return sum(data)
    else
        error("Unknown operation: $op")
    end
end

# Safe: Use multiple dispatch
abstract type Operation end
struct MeanOp <: Operation end
struct SumOp <: Operation end

apply(::MeanOp, data) = mean(data)
apply(::SumOp, data) = sum(data)

# Safe: Parameterized functions
function safe_filter(data, column::Symbol, value)
    filter(row -> getproperty(row, column) == value, data)
end
```

**Don't**:
```julia
# VULNERABLE: Arbitrary code execution
eval(Meta.parse(user_input))

# VULNERABLE: Code injection
@eval $(Meta.parse(user_code))

# VULNERABLE: include from untrusted source
include(user_provided_path)

# VULNERABLE: Dynamic function calls
func_name = Symbol(user_input)
getfield(Main, func_name)(data)
```

**Why**: `eval()` and `Meta.parse()` with user input enable arbitrary code execution, allowing attackers to access data or compromise the system.

**Refs**: CWE-94, CWE-95, OWASP A03:2025

---

### Rule: Secure System Commands

**Level**: `strict`

**When**: Executing shell commands from Julia.

**Do**:
```julia
# Safe: Use Cmd objects with argument separation
filename = "data.txt"
result = read(`wc -l $filename`, String)

# Safe: Validate inputs
function safe_list(directory::String)
    # Validate path
    if !isdir(directory) || contains(directory, "..")
        error("Invalid directory")
    end
    run(`ls -la $directory`)
end

# Safe: Use pipeline with separate arguments
run(pipeline(`grep pattern`, `wc -l`))
```

**Don't**:
```julia
# VULNERABLE: Shell injection
run(`sh -c "ls $user_input"`)

# VULNERABLE: String interpolation in shell
cmd = "grep $pattern $filename"
run(`sh -c $cmd`)

# VULNERABLE: Unsanitized user input
run(`cat $user_filename`)  # Could be "; rm -rf /"
```

**Why**: Shell injection allows attackers to execute arbitrary commands on the system.

**Refs**: CWE-78, OWASP A03:2025

---

## Type Safety

### Rule: Use Type Annotations for Security

**Level**: `warning`

**When**: Defining function interfaces, especially with external input.

**Do**:
```julia
# Safe: Strict type annotations
function process_user_data(
    id::Int,
    name::AbstractString,
    data::Vector{Float64}
)::Dict{String, Any}
    # Type-safe processing
    return Dict("id" => id, "name" => name, "mean" => mean(data))
end

# Safe: Validate before conversion
function safe_parse_int(input::AbstractString)::Int
    stripped = strip(input)
    if !all(c -> isdigit(c) || c == '-', stripped)
        error("Invalid integer format")
    end
    return parse(Int, stripped)
end

# Safe: Use parametric types
struct SecureContainer{T<:Number}
    data::Vector{T}
    checksum::UInt64
end
```

**Don't**:
```julia
# VULNERABLE: No type safety
function process(data)
    # Any type accepted, unexpected behavior possible
    return data[1] + data[2]
end

# VULNERABLE: Unsafe conversion
user_value = parse(Int, user_input)  # May throw on bad input

# VULNERABLE: Any type storage
global_cache = Dict()  # Any keys/values
```

**Why**: Type safety prevents type confusion attacks and ensures data integrity throughout processing pipelines.

**Refs**: CWE-843, CWE-704

---

## Package Security

### Rule: Manage Package Dependencies Securely

**Level**: `warning`

**When**: Installing and using Julia packages.

**Do**:
```julia
# Safe: Use Project.toml and Manifest.toml
# They provide reproducible, version-locked environments

# Safe: Pin specific versions
using Pkg
Pkg.add(name="HTTP", version="1.5.0")

# Safe: Verify packages from official registry
Pkg.Registry.add(RegistrySpec(url="https://github.com/JuliaRegistries/General"))

# Safe: Use package environments
Pkg.activate(".")
Pkg.instantiate()

# Safe: Check for vulnerabilities
# Review package source before adding
```

**Don't**:
```julia
# VULNERABLE: Install from arbitrary URLs
Pkg.add(url=user_provided_url)

# VULNERABLE: No version pinning
Pkg.add("SomePackage")  # Gets latest, may introduce vulnerabilities

# VULNERABLE: Dev from untrusted source
Pkg.develop(url=untrusted_repo)

# VULNERABLE: Ignoring Manifest.toml
# Results in non-reproducible builds
```

**Why**: Malicious packages can execute arbitrary code during installation or runtime, compromising your system and data.

**Refs**: CWE-829, OWASP A06:2025

---

## Data Security

### Rule: Secure Serialization

**Level**: `strict`

**When**: Saving or loading Julia objects.

**Do**:
```julia
using JSON3
using JLD2

# Safe: Use JSON for data interchange
json_data = JSON3.write(data)
data = JSON3.read(json_string, ExpectedType)

# Safe: JLD2 for Julia objects (from trusted sources only)
@save "data.jld2" model results
@load "data.jld2" model results  # Only from trusted sources

# Safe: Validate data structure after loading
function safe_load(path::String)
    data = JSON3.read(read(path, String), Dict{String, Any})
    validate_schema(data)  # Verify expected structure
    return data
end
```

**Don't**:
```julia
using Serialization

# VULNERABLE: Deserialize from untrusted sources
data = deserialize(user_provided_file)

# VULNERABLE: Load JLD2 from unknown sources
@load untrusted_file data  # May execute code

# VULNERABLE: No validation after load
data = JSON3.read(external_input)
process(data)  # Use without validation
```

**Why**: Julia's `Serialization` and JLD2 can execute arbitrary code during deserialization from malicious files.

**Refs**: CWE-502, OWASP A08:2025

---

### Rule: Prevent Data Leakage

**Level**: `warning`

**When**: Handling sensitive data in scientific computing.

**Do**:
```julia
# Safe: Filter sensitive columns
function safe_export(data::DataFrame)
    sensitive_cols = [:ssn, :password, :credit_card]
    safe_cols = setdiff(names(data), sensitive_cols)
    return data[:, safe_cols]
end

# Safe: Aggregate sensitive data
function safe_summary(salaries::Vector{Float64})
    return (
        mean = mean(salaries),
        std = std(salaries),
        n = length(salaries)
    )
    # Don't return individual values
end

# Safe: Limit output
first(large_dataset, 10)
```

**Don't**:
```julia
# VULNERABLE: Logging sensitive data
@info "Processing user" user.ssn user.password

# VULNERABLE: Unfiltered exports
CSV.write("export.csv", all_data)

# VULNERABLE: Printing raw data
println(patient_records)
```

**Why**: Data leakage in outputs, logs, or exports can violate privacy regulations and expose sensitive information.

**Refs**: CWE-532, CWE-200

---

## Web Security

### Rule: Secure HTTP Operations

**Level**: `warning`

**When**: Making HTTP requests or building web services.

**Do**:
```julia
using HTTP

# Safe: Use HTTPS with certificate verification
response = HTTP.get("https://api.example.com/data",
    headers = ["Authorization" => "Bearer $(ENV["API_TOKEN"])"]
)

# Safe: Validate URLs
function safe_fetch(url::String)
    parsed = HTTP.URI(url)
    if parsed.scheme ∉ ["http", "https"]
        error("Invalid URL scheme")
    end
    return HTTP.get(url)
end

# Safe: Timeout and retry configuration
HTTP.get(url, connect_timeout=10, readtimeout=30, retry=true)

# Safe: Use environment variables for secrets
api_key = get(ENV, "API_KEY", "")
isempty(api_key) && error("API_KEY not configured")
```

**Don't**:
```julia
# VULNERABLE: Hardcoded credentials
HTTP.get(url, headers=["Authorization" => "Bearer sk-hardcoded123"])

# VULNERABLE: Disabled SSL verification
HTTP.get(url, require_ssl_verification=false)

# VULNERABLE: Credentials in URL
HTTP.get("https://user:password@api.example.com")
```

**Why**: Hardcoded credentials get committed to version control. Disabled SSL allows man-in-the-middle attacks.

**Refs**: CWE-798, CWE-295

---

## Randomness

### Rule: Use Cryptographic Randomness

**Level**: `strict`

**When**: Generating tokens, keys, or security-sensitive values.

**Do**:
```julia
using Random
using SHA

# Safe: Use cryptographic RNG
crypto_rng = RandomDevice()
token = bytes2hex(rand(crypto_rng, UInt8, 32))

# Safe: Generate secure random string
function secure_token(n::Int=32)
    bytes = rand(RandomDevice(), UInt8, n)
    return bytes2hex(bytes)
end

# Safe: Secure random choice
function secure_choice(items::Vector)
    idx = rand(RandomDevice(), 1:length(items))
    return items[idx]
end
```

**Don't**:
```julia
# VULNERABLE: Predictable random
Random.seed!(12345)  # Never for security
token = randstring(32)

# VULNERABLE: Default RNG is not cryptographic
session_id = rand(UInt64)

# VULNERABLE: Time-based seeding
Random.seed!(round(Int, time()))
```

**Why**: Julia's default Mersenne Twister RNG is predictable. Attackers can guess tokens generated with `rand()`.

**Refs**: CWE-330, CWE-338

---

## File Operations

### Rule: Prevent Path Traversal

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```julia
# Safe: Validate file paths
function safe_read(filename::String, base_dir::String="/app/data")
    # Resolve to absolute path
    full_path = abspath(joinpath(base_dir, filename))

    # Verify within allowed directory
    if !startswith(full_path, abspath(base_dir))
        error("Path traversal attempt detected")
    end

    if !isfile(full_path)
        error("File not found")
    end

    return read(full_path, String)
end
```

**Don't**:
```julia
# VULNERABLE: Direct concatenation
content = read("/data/" * user_filename, String)

# VULNERABLE: No path validation
open(user_path) do f
    read(f)
end

# VULNERABLE: Accepting absolute paths
include(user_provided_script)
```

**Why**: Path traversal attacks use `../` to access files outside intended directories, exposing sensitive system files.

**Refs**: CWE-22, OWASP A01:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Avoid eval/Meta.parse | strict | CWE-94 |
| Secure system commands | strict | CWE-78 |
| Type annotations | warning | CWE-843 |
| Package security | warning | CWE-829 |
| Secure serialization | strict | CWE-502 |
| Prevent data leakage | warning | CWE-200 |
| Secure HTTP | warning | CWE-798 |
| Cryptographic randomness | strict | CWE-330 |
| Path traversal prevention | strict | CWE-22 |

---

## Version History

- **v1.0.0** - Initial Julia security rules
