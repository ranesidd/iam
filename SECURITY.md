# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

**Note**: We recommend always using the latest version to ensure you have the most recent security patches.

## Reporting a Vulnerability

We take the security of the IAM library seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please Do Not

- **Do not** open a public GitHub issue for security vulnerabilities
- **Do not** disclose the vulnerability publicly until it has been addressed
- **Do not** exploit the vulnerability in production environments

### How to Report

**Preferred Method**: Open a [GitHub Security Advisory](https://github.com/ranesidd/iam/security/advisories/new)

**Alternative Method**: Email the maintainers directly at [security contact email - replace with actual email]

### What to Include

Please include the following information in your report:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What an attacker could achieve by exploiting this vulnerability
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions are affected
5. **Proof of Concept**: Code snippet or example demonstrating the vulnerability (if applicable)
6. **Suggested Fix**: If you have ideas on how to fix it (optional)
7. **Your Contact Information**: So we can follow up with questions

### Example Report

```
Subject: [SECURITY] SQL Injection vulnerability in OTP validation

Description:
The OTP validation function is vulnerable to SQL injection through the email parameter.

Impact:
An attacker could extract sensitive data from the verification_codes table or potentially
execute arbitrary SQL commands.

Steps to Reproduce:
1. Call Validate() with email = "test@example.com' OR '1'='1"
2. The query is executed without proper escaping

Affected Versions:
All versions prior to 1.2.0

Proof of Concept:
[Code snippet demonstrating the vulnerability]

Suggested Fix:
Use parameterized queries with placeholders instead of string concatenation.
```

## Response Timeline

- **Initial Response**: Within 48 hours of receiving the report
- **Status Update**: Within 7 days with our assessment and planned actions
- **Fix Timeline**: We aim to release a security patch within 30 days for critical vulnerabilities
- **Disclosure**: Coordinated disclosure after patch is released

## Security Best Practices

### For Library Users

#### 1. Environment Variables

**Never commit sensitive credentials to version control:**

```bash
# Bad - DO NOT DO THIS
export GOOGLE_API_KEY="AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
git add .env
git commit -m "Add config"

# Good - Use environment-specific config
# Add .env to .gitignore
echo ".env" >> .gitignore
```

**Use secret management services in production:**
- Google Secret Manager
- AWS Secrets Manager
- Azure Key Vault
- HashiCorp Vault

#### 2. Firebase Service Account Security

**Restrict service account permissions:**
```bash
# Only grant necessary roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:SERVICE_ACCOUNT_EMAIL" \
  --role="roles/identitytoolkit.admin"
```

**Rotate service account keys regularly:**
- Set up automatic key rotation (recommended: every 90 days)
- Never share service account keys
- Use Workload Identity on GKE instead of service account keys when possible

#### 3. Database Security (OTP Package)

**Use separate database users with limited permissions:**

```sql
-- Good - Limited permissions
CREATE USER 'otp_service'@'localhost' IDENTIFIED BY 'secure_password';
GRANT SELECT, INSERT, DELETE ON mydb.verification_codes TO 'otp_service'@'localhost';

-- Bad - Too many permissions
GRANT ALL PRIVILEGES ON *.* TO 'otp_service'@'localhost';
```

**Enable SSL/TLS for database connections:**

```go
db, err := sql.Open("mysql", "user:password@tcp(host:3306)/db?tls=true")
```

#### 4. Token Validation

**Always verify tokens on the server side:**

```go
// Good - Server-side verification
decodedToken, err := iam.VerifyToken(ctx, idToken)
if err != nil {
    return fmt.Errorf("unauthorized: %w", err)
}

// Bad - Trusting client-provided claims
// NEVER trust claims from the client without verification
```

**Check token expiration and revocation:**

```go
// The VerifyToken method automatically checks:
// - Token signature
// - Token expiration
// - Token revocation status
decodedToken, err := iam.VerifyToken(ctx, idToken)
```

#### 5. Custom Claims Security

**Never store sensitive data in custom claims:**

```go
// Bad - Sensitive data exposed in token
claims := map[string]interface{}{
    "ssn": "123-45-6789",           // NEVER DO THIS
    "credit_card": "4111111111111", // NEVER DO THIS
    "password_hash": "...",         // NEVER DO THIS
}

// Good - Non-sensitive authorization metadata
claims := map[string]interface{}{
    "role": "admin",
    "permissions": []string{"read", "write"},
    "subscription_tier": "premium",
}
```

**Remember: Custom claims are visible to the client** - they are included in JWT tokens which can be decoded by anyone.

#### 6. Password Security

**Enforce strong password policies:**

```go
// Implement password validation before account creation
func ValidatePassword(password string) error {
    if len(password) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    // Add additional complexity requirements
    return nil
}
```

**Use password reset links, not password retrieval:**

```go
// Good - Send reset link
resetLink, err := iam.ResetPasswordLink(ctx, email)

// Bad - Never retrieve or store plaintext passwords
```

#### 7. Rate Limiting

**Implement rate limiting for authentication endpoints:**

```go
// Example using a rate limiter
limiter := rate.NewLimiter(rate.Every(time.Minute), 5) // 5 requests per minute

func handleSignIn(w http.ResponseWriter, r *http.Request) {
    if !limiter.Allow() {
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
    // Process sign-in
}
```

#### 8. Input Validation

**Always validate and sanitize inputs:**

```go
// Validate email format
func ValidateEmail(email string) error {
    if !regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`).MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}

// Validate tenant ID format
func ValidateTenantID(tenantID string) error {
    if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(tenantID) {
        return errors.New("invalid tenant ID format")
    }
    return nil
}
```

### For Contributors

#### Code Review Security Checklist

Before submitting a PR, ensure:

- [ ] No secrets, API keys, or credentials in code or commits
- [ ] All database queries use parameterized queries (no SQL injection)
- [ ] Input validation is performed on all user-provided data
- [ ] Error messages don't leak sensitive information
- [ ] Authentication/authorization checks are in place
- [ ] Dependencies are up to date and have no known vulnerabilities
- [ ] Tests cover security-critical code paths

#### Dependency Security

**Check for vulnerable dependencies:**

```bash
# Check for known vulnerabilities
go list -json -m all | nancy sleuth

# Or use GitHub's Dependabot (enabled by default)
```

**Keep dependencies updated:**

```bash
go get -u ./...
go mod tidy
```

## Known Security Considerations

### 1. Token Storage

**Client-side token storage** is the responsibility of the application using this library:

- Store tokens securely (httpOnly cookies, secure storage)
- Never store tokens in localStorage for sensitive applications
- Implement token refresh before expiration
- Clear tokens on logout

### 2. Multi-Tenancy Isolation

When using multi-tenancy features:

- Tenant IDs must be validated and sanitized
- Never trust client-provided tenant IDs for authorization decisions
- Always verify tenant context matches the authenticated user
- Implement proper tenant-level access controls in your application

### 3. OTP Security

The OTP package has security considerations:

- OTP codes are 6 characters (uppercase letters and numbers)
- Codes expire based on configured duration
- Old codes are deleted on new generation (one active code per email)
- Codes are deleted after successful validation
- **Rate limiting must be implemented by the application** to prevent brute force attacks

### 4. Firebase Authentication Limits

Be aware of Firebase quotas and limits:

- Custom claims limited to 1000 bytes
- Rate limits on authentication operations
- See [Firebase quotas documentation](https://firebase.google.com/docs/auth/limits)

## Security Updates

Security updates will be released as:

1. **Patch releases** (e.g., 1.2.3 → 1.2.4) for minor security issues
2. **Minor releases** (e.g., 1.2.0 → 1.3.0) for security improvements
3. **GitHub Security Advisories** for critical vulnerabilities

Subscribe to repository releases and security advisories to stay informed.

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Firebase Security Best Practices](https://firebase.google.com/docs/rules/security-best-practices)
- [Go Security Guidelines](https://go.dev/security/)
- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)

## Acknowledgments

We appreciate the security research community and will acknowledge reporters in our security advisories (unless they prefer to remain anonymous).

---

**Last Updated**: 2025-11-08
