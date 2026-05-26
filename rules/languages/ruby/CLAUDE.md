# Ruby Security Rules

Security rules for Ruby development in Claude Code. Targets Ruby >= 3.1.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security

---

## Injection Prevention

### Rule: Use Parameterized Queries

**Level**: `strict`

**When**: Executing database queries.

**Do**:
```ruby
# ActiveRecord (safe)
user = User.where(email: email).first
users = User.where("status = ?", status)

# Named placeholders
User.where("email = :email AND status = :status",
           email: email, status: status)

# Raw SQL with parameters
User.find_by_sql(["SELECT * FROM users WHERE email = ?", email])
```

**Don't**:
```ruby
# VULNERABLE: SQL injection
User.where("email = '#{email}'")
User.find_by_sql("SELECT * FROM users WHERE email = '#{email}'")
```

**Why**: SQL injection allows attackers to read, modify, or delete database data.

**Refs**: CWE-89, OWASP A03:2025

---

### Rule: Prevent Command Injection

**Level**: `strict`

**When**: Executing system commands.

**Do**:
```ruby
require 'open3'
require 'shellwords'

# Array form passes arguments directly to the OS; no shell is invoked,
# so no escaping is needed or appropriate.
def list_files(directory)
  raise ArgumentError, "Invalid directory" if directory.include?('..')

  stdout, _status = Open3.capture2('ls', '-la', directory)
  stdout
end

# When array form is unavailable and a single shell-string is unavoidable,
# use Shellwords.escape to quote each argument.
def legacy_shell_command(filename)
  system("cat #{Shellwords.escape(filename)}")
end
```

**Don't**:
```ruby
# VULNERABLE: Command injection via string interpolation
system("ls -la #{user_input}")
`echo #{user_input}`
exec("cat #{filename}")

# WRONG: Shellwords.escape is meaningless in array-form system(); the OS
# receives the escape sequences as literal characters in the argument string.
system('echo', Shellwords.escape(user_input))
```

**Why**: Shell metacharacters allow executing arbitrary commands. The array form of `system()`, `spawn()`, and `Open3` methods bypasses the shell entirely; no escaping is needed or correct for those calls. Reserve `Shellwords.escape` for single-string shell invocations only.

**Refs**: CWE-78, OWASP A03:2025

---

## Metaprogramming Safety

### Rule: Never Pass Untrusted Input to Dynamic Execution Methods

**Level**: `strict`

**When**: Using `eval`, `send`, `public_send`, `class_eval`, `instance_eval`, `define_method`, or `const_get` with any value derived from external input.

**Do**:
```ruby
# Use an explicit allowlist before dispatching dynamically.
ALLOWED_ACTIONS = %w[start stop restart].freeze

def perform_action(action)
  raise ArgumentError, "Unknown action" unless ALLOWED_ACTIONS.include?(action)

  send(action)  # safe: only allowlisted method names reach send
end

# Prefer explicit case/when over dynamic dispatch for small sets.
def format_value(type, value)
  case type
  when "integer" then Integer(value)
  when "float"   then Float(value)
  else raise ArgumentError, "Unsupported type: #{type}"
  end
end
```

**Don't**:
```ruby
# VULNERABLE: RCE via eval with user-controlled string
eval(params[:expression])

# VULNERABLE: Arbitrary method call
send(params[:action])

# VULNERABLE: class_eval executes arbitrary Ruby
String.class_eval(user_input)

# VULNERABLE: instance_eval on a model object
@record.instance_eval(request.body.read)

# VULNERABLE: const_get with unsanitized input enables class instantiation
Object.const_get(params[:class]).new
```

**Why**: Ruby's dynamic dispatch methods execute arbitrary code when given attacker-controlled strings. A single unguarded `eval` or `send` call is a full remote code execution vector. Use allowlists or static dispatch instead.

**Refs**: CWE-94, OWASP A03:2025

---

## ERB Output Encoding

### Rule: Never Mark User Input as HTML-Safe

**Level**: `strict`

**When**: Rendering user-supplied content in ERB templates or Rails helpers.

**Do**:
```ruby
# Rails escapes <%= %> automatically — no action needed for plain output.
# Template:
#   <%= @user.display_name %>   # safe: HTML-escaped by default

# When rendering rich text, use a sanitization library, not html_safe.
require 'rails_html_sanitizer'

def render_bio(raw_bio)
  sanitizer = Rails::Html::SafeListSanitizer.new
  sanitizer.sanitize(raw_bio, tags: %w[p b i em strong], attributes: []).html_safe
  # html_safe is correct here because sanitize() has already stripped all
  # dangerous tags and attributes.
end

# For plain text that must appear inside an HTML attribute, use h() or ERB::Util.html_escape.
safe_attr = ERB::Util.html_escape(user_value)
```

**Don't**:
```ruby
# VULNERABLE: bypasses Rails XSS protection — stored XSS if stored in DB
@user.bio.html_safe

# VULNERABLE: raw() is an alias for html_safe; same risk
raw(@comment.body)

# VULNERABLE: <%== %> is ERB's raw-output tag — equivalent to raw()
# Template:
#   <%== @user.profile %>

# VULNERABLE: ActionView::Helpers::TextHelper#simple_format with html_safe input
simple_format(@post.html_safe)
```

**Why**: Rails escapes `<%= %>` output by default. Calling `html_safe` or `raw()` on user-supplied content marks the string as trusted and disables that escaping, enabling stored XSS. The correct pattern is to sanitize with an allowlist of safe tags and then mark the sanitized result as safe.

**Refs**: CWE-79, OWASP A03:2025

---

## Serialization

### Rule: Avoid Unsafe Deserialization

**Level**: `strict`

**When**: Deserializing external data.

**Do**:
```ruby
require 'json'

# Use JSON for external data
data = JSON.parse(json_string)

# If YAML is needed, use safe_load (Ruby >= 3.1 API)
require 'yaml'
data = YAML.safe_load(yaml_string, permitted_classes: [Symbol, Date])
```

**Don't**:
```ruby
# VULNERABLE: Arbitrary code execution
Marshal.load(untrusted_data)

# VULNERABLE: Unsafe YAML — executes arbitrary Ruby
YAML.load(untrusted_yaml)
```

**Why**: `Marshal` and `YAML.load` can instantiate arbitrary Ruby objects and execute code during deserialization.

**Refs**: CWE-502, OWASP A08:2025

---

## Cryptography

### Rule: Use Strong Cryptographic Algorithms

**Level**: `strict`

**When**: Encrypting data or hashing passwords.

**Do**:
```ruby
require 'securerandom'
require 'bcrypt'
require 'openssl'

# Cryptographically secure random token
token = SecureRandom.hex(32)

# Password hashing — bcrypt is standard-compliant; prefer argon2 gem for new projects
password_hash = BCrypt::Password.create(password, cost: 12)
valid = BCrypt::Password.new(password_hash) == password

# AES-256-GCM authenticated encryption
cipher = OpenSSL::Cipher.new('aes-256-gcm')
cipher.encrypt
key = cipher.random_key
iv  = cipher.random_iv
encrypted = cipher.update(data) + cipher.final
tag = cipher.auth_tag
```

**Don't**:
```ruby
require 'digest'

# VULNERABLE: Weak hash, unsuitable for passwords
hash = Digest::MD5.hexdigest(password)

# VULNERABLE: Predictable random
token = rand(1_000_000)
```

**Why**: Weak or predictable cryptography allows attackers to decrypt data or crack passwords offline.

**Refs**: CWE-327, CWE-328, CWE-330

---

## Path Traversal

### Rule: Validate File Paths

**Level**: `strict`

**When**: Accessing files based on user input.

**Do**:
```ruby
def safe_get_file(filename)
  base_path      = File.expand_path('/app/uploads')
  requested_path = File.expand_path(File.join(base_path, filename))

  unless requested_path.start_with?("#{base_path}/")
    raise SecurityError, "Path traversal attempt detected"
  end

  File.read(requested_path)
end
```

**Don't**:
```ruby
# VULNERABLE: Path traversal
def get_file(filename)
  File.read("/app/uploads/#{filename}")
end
```

**Why**: Without expansion and prefix checks, `../` sequences allow reading arbitrary files on the host.

**Refs**: CWE-22, OWASP A01:2025

---

## Regular Expressions

### Rule: Prevent ReDoS Attacks

**Level**: `warning`

**When**: Using regular expressions with user input.

**Do**:
```ruby
# Anchor with \A and \z; avoid nested quantifiers
EMAIL_PATTERN = /\A[\w.+-]+@[\w.-]+\.[a-z]{2,}\z/i

# Validate length before matching
def valid_email?(input)
  return false if input.length > 255

  require 'timeout'
  Timeout.timeout(1) { input.match?(EMAIL_PATTERN) }
rescue Timeout::Error
  false
end
```

**Don't**:
```ruby
# VULNERABLE: Catastrophic backtracking
pattern = /^(a+)+$/
"aaaaaaaaaaaaaaaaaaaaaaaaaaab".match?(pattern)  # hangs
```

**Why**: Pathological regexes allow attackers to cause denial of service by supplying crafted inputs that trigger exponential backtracking.

**Refs**: CWE-1333, OWASP A05:2025

---

## Error Handling

### Rule: Don't Expose Stack Traces

**Level**: `warning`

**When**: Handling exceptions in web controllers.

**Do**:
```ruby
class ApplicationController < ActionController::Base
  rescue_from StandardError do |exception|
    Rails.logger.error(exception.full_message)
    render json: { error: 'Internal server error' }, status: 500
  end

  rescue_from ActiveRecord::RecordNotFound do
    render json: { error: 'Not found' }, status: 404
  end
end
```

**Don't**:
```ruby
# VULNERABLE: Exposes stack trace and internal paths
rescue_from StandardError do |exception|
  render json: {
    error: exception.message,
    backtrace: exception.backtrace
  }, status: 500
end
```

**Why**: Stack traces reveal gem versions, file paths, and internal structure that attackers use to craft targeted exploits.

**Refs**: CWE-209, OWASP A05:2025

---

## Mass Assignment

### Rule: Use Strong Parameters

**Level**: `strict`

**When**: Accepting model attributes from HTTP requests.

**Do**:
```ruby
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    if @user.save
      render json: @user, status: :created
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :name, :password)
  end
end
```

**Don't**:
```ruby
# VULNERABLE: Mass assignment — attacker can set admin: true
def create
  @user = User.new(params[:user])
  @user.save
end

# VULNERABLE: Permits every attribute
def user_params
  params.require(:user).permit!
end
```

**Why**: Without an explicit allowlist, attackers can set protected attributes such as `admin`, `role`, or `balance` by including them in the request body.

**Refs**: CWE-915, OWASP A01:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Parameterized queries | strict | CWE-89 |
| No command injection | strict | CWE-78 |
| No dynamic eval/send with untrusted input | strict | CWE-94 |
| Safe ERB output encoding | strict | CWE-79 |
| Safe deserialization | strict | CWE-502 |
| Strong cryptography | strict | CWE-327 |
| Path traversal prevention | strict | CWE-22 |
| ReDoS prevention | warning | CWE-1333 |
| Safe error handling | warning | CWE-209 |
| Strong parameters | strict | CWE-915 |

---

## Version History

- **v2.0.0** - Added metaprogramming safety and ERB output encoding rules; fixed Shellwords.escape misuse in command injection Do example; Ruby >= 3.1 baseline
- **v1.0.0** - Initial Ruby security rules
