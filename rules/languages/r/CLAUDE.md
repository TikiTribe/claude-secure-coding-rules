# R Security Rules

Security rules for R development in Claude Code.

## Prerequisites

- `rules/_core/owasp-2025.md` - Core web security
- `rules/_core/ai-security.md` - AI/ML security (critical for R data science)

---

## Code Execution

### Rule: Avoid Dangerous Evaluation

**Level**: `strict`

**When**: Processing user input or external data.

**Do**:
```r
# Safe: Use parameterized functions
filter_data <- function(data, column, value) {
  data[data[[column]] == value, ]
}

# Safe: Use switch for controlled options
operation <- switch(user_choice,
  "mean" = mean,
  "median" = median,
  "sum" = sum,
  stop("Invalid operation")
)
result <- operation(data$column)
```

**Don't**:
```r
# VULNERABLE: Arbitrary code execution
eval(parse(text = user_input))

# VULNERABLE: Code injection via get()
func_name <- user_input
result <- get(func_name)(data)

# VULNERABLE: source() from untrusted location
source(user_provided_url)
```

**Why**: `eval()`, `parse()`, and `get()` with user input enable arbitrary code execution, allowing attackers to access data or compromise the system.

**Refs**: CWE-94, CWE-95, OWASP A03:2025

---

### Rule: Secure System Commands

**Level**: `strict`

**When**: Executing system commands from R.

**Do**:
```r
# Safe: Use processx with argument vector
library(processx)

result <- run(
  command = "ls",
  args = c("-la", safe_directory),
  error_on_status = TRUE
)

# Safe: Validate and escape if system() is required
if (grepl("^[a-zA-Z0-9_/-]+$", filename)) {
  system2("wc", args = c("-l", shQuote(filename)))
}
```

**Don't**:
```r
# VULNERABLE: Command injection
system(paste("cat", user_filename))

# VULNERABLE: Shell expansion
system(sprintf("grep %s %s", pattern, filename))

# VULNERABLE: Unsanitized shell command
shell(user_input)
```

**Why**: Command injection allows attackers to execute arbitrary system commands, potentially compromising the entire server.

**Refs**: CWE-78, OWASP A03:2025

---

## Data Security

### Rule: Prevent Data Leakage in Outputs

**Level**: `warning`

**When**: Generating reports, logs, or outputs.

**Do**:
```r
# Safe: Redact sensitive columns before output
safe_summary <- function(data) {
  # Remove PII columns
  safe_data <- data[, !names(data) %in% c("ssn", "credit_card", "password")]
  summary(safe_data)
}

# Safe: Limit output rows
head(data, n = 10)  # Don't expose entire dataset

# Safe: Aggregate instead of showing raw data
aggregate(salary ~ department, data = employees, FUN = mean)
```

**Don't**:
```r
# VULNERABLE: Exposing raw PII
print(patient_data)

# VULNERABLE: Writing sensitive data to logs
message(paste("Processing user:", user_record$ssn))

# VULNERABLE: Unfiltered data export
write.csv(customer_data, "export.csv")
```

**Why**: Accidental data exposure in outputs, logs, or exports can violate privacy regulations (GDPR, HIPAA) and expose sensitive information.

**Refs**: CWE-532, CWE-200, OWASP A01:2025

---

### Rule: Secure Data Serialization

**Level**: `strict`

**When**: Saving or loading R objects.

**Do**:
```r
# Safe: Use RDS with known safe sources only
saveRDS(model, "model.rds")
model <- readRDS("model.rds")  # Only from trusted sources

# Safe: Use safer formats for data exchange
library(jsonlite)
write_json(data, "data.json")
data <- fromJSON("data.json")

# Safe: Validate before loading
if (file.exists(filepath) && tools::md5sum(filepath) == expected_hash) {
  data <- readRDS(filepath)
}
```

**Don't**:
```r
# VULNERABLE: Loading RDS from untrusted sources
model <- readRDS(user_provided_path)

# VULNERABLE: No validation of serialized objects
data <- unserialize(rawToChar(received_bytes))

# VULNERABLE: Loading .RData from unknown sources
load(downloaded_file)  # Can execute code on load
```

**Why**: R serialization formats (RDS, RData) can contain executable code that runs during deserialization.

**Refs**: CWE-502, OWASP A08:2025

---

## Package Security

### Rule: Verify Package Sources

**Level**: `warning`

**When**: Installing R packages.

**Do**:
```r
# Safe: Install from CRAN with verification
install.packages("dplyr", repos = "https://cran.r-project.org")

# Safe: Pin package versions
if (packageVersion("dplyr") < "1.0.0") {
  install.packages("dplyr")
}

# Safe: Use renv for reproducible environments
library(renv)
renv::init()
renv::snapshot()

# Safe: Verify GitHub packages
remotes::install_github("user/repo@v1.0.0")  # Pin to specific version/tag
```

**Don't**:
```r
# VULNERABLE: Installing from arbitrary URLs
install.packages(user_provided_url, repos = NULL)

# VULNERABLE: Unpinned GitHub installs
devtools::install_github(user_input)

# VULNERABLE: Disabling security checks
install.packages("pkg", repos = NULL, type = "source", INSTALL_opts = "--no-test-load")
```

**Why**: Malicious packages can execute arbitrary code during installation or loading, compromising your system and data.

**Refs**: CWE-829, OWASP A06:2025

---

## Shiny Application Security

### Rule: Validate All Shiny Inputs

**Level**: `strict`

**When**: Building Shiny applications.

**Do**:
```r
library(shiny)

server <- function(input, output, session) {
  # Safe: Validate numeric input
  safe_n <- reactive({
    n <- as.integer(input$n)
    if (is.na(n) || n < 1 || n > 1000) {
      stop("Invalid input: n must be between 1 and 1000")
    }
    n
  })

  # Safe: Whitelist allowed values
  safe_column <- reactive({
    allowed <- c("mpg", "cyl", "disp", "hp")
    if (!input$column %in% allowed) {
      stop("Invalid column selection")
    }
    input$column
  })

  output$plot <- renderPlot({
    hist(mtcars[[safe_column()]], breaks = safe_n())
  })
}
```

**Don't**:
```r
server <- function(input, output, session) {
  # VULNERABLE: Direct use of input in code
  output$result <- renderPrint({
    eval(parse(text = input$code))
  })

  # VULNERABLE: Unsanitized column access
  output$table <- renderTable({
    data[[input$column]]  # Could access unintended columns
  })

  # VULNERABLE: SQL injection via input
  output$data <- renderTable({
    query <- paste0("SELECT * FROM users WHERE name = '", input$name, "'")
    dbGetQuery(con, query)
  })
}
```

**Why**: Shiny inputs come directly from users and must be validated to prevent code injection, data exposure, and SQL injection.

**Refs**: CWE-20, CWE-89, OWASP A03:2025

---

### Rule: Implement Shiny Authentication

**Level**: `strict`

**When**: Deploying Shiny apps with sensitive data.

**Do**:
```r
library(shiny)
library(shinymanager)

# Safe: Use authentication wrapper
ui <- secure_app(
  fluidPage(
    # Your UI here
  )
)

server <- function(input, output, session) {
  # Check authentication
  res_auth <- secure_server(
    check_credentials = check_credentials(
      data.frame(
        user = c("admin"),
        password = c(scrypt::hashPassword("secure_password")),
        stringsAsFactors = FALSE
      )
    )
  )

  # Access user info
  output$user <- renderText({
    reactiveValuesToList(res_auth)$user
  })
}
```

**Don't**:
```r
# VULNERABLE: No authentication on sensitive app
shinyApp(ui, server)

# VULNERABLE: Hardcoded credentials in code
if (input$password == "admin123") {
  # Allow access
}

# VULNERABLE: Client-side only authentication
ui <- fluidPage(
  passwordInput("pass", "Password"),
  conditionalPanel(
    condition = "input.pass == 'secret'",  # Bypassed easily
    tableOutput("sensitive_data")
  )
)
```

**Why**: Unauthenticated Shiny apps expose sensitive data and functionality to anyone who discovers the URL.

**Refs**: CWE-306, OWASP A07:2025

---

## File Operations

### Rule: Prevent Path Traversal

**Level**: `strict`

**When**: Reading or writing files based on user input.

**Do**:
```r
# Safe: Validate file paths
safe_read <- function(filename, base_dir = "/app/data") {
  # Normalize and resolve path
  full_path <- normalizePath(file.path(base_dir, filename), mustWork = FALSE)

  # Verify path is within allowed directory
  if (!startsWith(full_path, normalizePath(base_dir))) {
    stop("Path traversal attempt detected")
  }

  if (!file.exists(full_path)) {
    stop("File not found")
  }

  read.csv(full_path)
}
```

**Don't**:
```r
# VULNERABLE: Direct path concatenation
read.csv(paste0("/data/", user_filename))

# VULNERABLE: No path validation
file.copy(input_path, output_path)

# VULNERABLE: Accepting absolute paths
data <- read.csv(user_provided_path)
```

**Why**: Path traversal attacks use `../` sequences to access files outside intended directories, potentially exposing sensitive system files.

**Refs**: CWE-22, OWASP A01:2025

---

## Database Security

### Rule: Use Parameterized Database Queries

**Level**: `strict`

**When**: Querying databases with user input.

**Do**:
```r
library(DBI)

# Safe: Parameterized query
result <- dbGetQuery(con,
  "SELECT * FROM users WHERE email = ? AND status = ?",
  params = list(email, status)
)

# Safe: Using dbplyr (generates safe SQL)
library(dplyr)
library(dbplyr)

users_db <- tbl(con, "users")
result <- users_db %>%
  filter(email == local(email)) %>%
  collect()

# Safe: Escape identifiers
table_name <- dbQuoteIdentifier(con, user_table)
query <- paste("SELECT * FROM", table_name)
```

**Don't**:
```r
# VULNERABLE: String concatenation
query <- paste0("SELECT * FROM users WHERE email = '", email, "'")
dbGetQuery(con, query)

# VULNERABLE: sprintf injection
query <- sprintf("SELECT * FROM %s WHERE id = %s", table, id)
dbExecute(con, query)
```

**Why**: SQL injection can read, modify, or delete database data, and potentially execute system commands.

**Refs**: CWE-89, OWASP A03:2025

---

## Randomness

### Rule: Use Cryptographic Randomness for Security

**Level**: `strict`

**When**: Generating tokens, keys, or security-sensitive values.

**Do**:
```r
library(openssl)

# Safe: Cryptographic random bytes
token <- base64_encode(rand_bytes(32))
api_key <- paste0(as.character(rand_bytes(32)), collapse = "")

# Safe: Secure random string
secure_token <- function(n = 32) {
  chars <- c(letters, LETTERS, 0:9)
  bytes <- as.integer(rand_bytes(n))
  paste0(chars[(bytes %% length(chars)) + 1], collapse = "")
}
```

**Don't**:
```r
# VULNERABLE: Predictable random
set.seed(123)  # Never for security purposes
token <- paste0(sample(letters, 32, replace = TRUE), collapse = "")

# VULNERABLE: Time-based seeds are predictable
set.seed(as.numeric(Sys.time()))
session_id <- runif(1)

# VULNERABLE: sample() is not cryptographic
api_key <- paste0(sample(c(letters, 0:9), 32, replace = TRUE), collapse = "")
```

**Why**: R's default random number generator is predictable. Attackers can guess tokens and session IDs generated with `sample()` or `runif()`.

**Refs**: CWE-330, CWE-338

---

## API Security

### Rule: Secure HTTP Requests

**Level**: `warning`

**When**: Making HTTP requests to external services.

**Do**:
```r
library(httr2)

# Safe: Use httr2 with proper error handling
response <- request("https://api.example.com/data") %>%
  req_headers(Authorization = paste("Bearer", Sys.getenv("API_TOKEN"))) %>%
  req_timeout(30) %>%
  req_retry(max_tries = 3) %>%
  req_perform()

# Safe: Validate SSL certificates (default)
# Safe: Use environment variables for secrets
api_key <- Sys.getenv("API_KEY")
if (api_key == "") stop("API_KEY not configured")
```

**Don't**:
```r
library(httr)

# VULNERABLE: Hardcoded credentials
GET("https://api.example.com",
    add_headers(Authorization = "Bearer sk-1234567890"))

# VULNERABLE: Disabling SSL verification
GET(url, config(ssl_verifypeer = FALSE))

# VULNERABLE: Credentials in URLs
GET("https://user:password@api.example.com/data")
```

**Why**: Hardcoded credentials get committed to version control. Disabled SSL verification enables man-in-the-middle attacks.

**Refs**: CWE-798, CWE-295, OWASP A07:2025

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Avoid eval/parse | strict | CWE-94 |
| Secure system commands | strict | CWE-78 |
| Prevent data leakage | warning | CWE-200 |
| Secure serialization | strict | CWE-502 |
| Verify package sources | warning | CWE-829 |
| Validate Shiny inputs | strict | CWE-20 |
| Shiny authentication | strict | CWE-306 |
| Prevent path traversal | strict | CWE-22 |
| Parameterized queries | strict | CWE-89 |
| Cryptographic randomness | strict | CWE-330 |
| Secure HTTP requests | warning | CWE-798 |

---

## Version History

- **v1.0.0** - Initial R security rules
