# IAM Library

A unified Go library for Identity and Access Management (IAM) operations that provides simplified and abstracted interfaces on top of various cloud providers' IAM services.

## Overview

This library aims to provide a consistent, easy-to-use interface for common IAM operations across different cloud providers including GCP, AWS, Auth0, and others. By abstracting provider-specific implementations, developers can write IAM code once and easily switch between providers or support multiple providers simultaneously.

**Current Status**: Only Google Cloud Platform (Firebase Authentication) is currently supported. Support for additional providers is planned for future releases.

## Features

### Core IAM Operations
- **Account Management**: Create, read, update, and delete user accounts
- **Authentication**: Sign in/out operations with secure token management
- **Password Management**: Password updates and reset link generation
- **Account Verification**: Email-based account existence checks
- **Token Operations**: ID token verification, token refresh, and refresh token revocation
- **Multi-Tenancy Support**: Optional tenant isolation for all IAM operations (Google Identity Platform)
- **Tenant Management**: Create and delete Identity Platform tenants programmatically

### OTP (One-Time Password)
- **Provider-Independent**: Standalone OTP package that works with any IAM provider
- **Database Persistence**: Store and validate OTPs with configurable expiration
- **Flexible Expiration**: Set custom expiration times for OTP codes

### Google Firebase Features
- **Firebase Integration**: Full Firebase Admin SDK integration
- **Secure Authentication**: Uses Firebase Authentication REST API for sign-in operations

## Installation

```bash
go get github.com/ranesidd/iam
```

## Quick Start

### Basic Setup (Google Firebase)

```go
package main

import (
    "context"
    "log"
    
    "github.com/ranesidd/iam/google_iam"
)

func main() {
    // Initialize Google IAM client
    iam, err := googleiam.New()
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    
    // Create a new account
    request := googleiam.CreateAccountRequest{
        Email:       "user@example.com",
        Password:    "securepassword",
        DisplayName: "John Doe",
    }
    
    account, err := iam.CreateAccount(ctx, request)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Created account: %s", account.Account.Email)
}
```

### Token Refresh

Refresh an expired ID token using the refresh token:

```go
package main

import (
    "context"
    "log"

    "github.com/ranesidd/iam/google_iam"
)

func main() {
    iam, err := googleiam.New()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Sign in to get tokens
    signInResponse, err := iam.SignIn(ctx, "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }

    // Use the ID token for authenticated requests...
    // Later, when the token expires (after 1 hour), refresh it:

    refreshResponse, err := iam.RefreshToken(ctx, signInResponse.RefreshToken)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("New ID Token: %s", refreshResponse.IDToken)
    log.Printf("New Refresh Token: %s", refreshResponse.RefreshToken)
    log.Printf("User UUID: %s", refreshResponse.UUID)
    log.Printf("Token expires in: %s seconds", refreshResponse.ExpiresIn)
}
```

**Note**: The tenant context (if any) is automatically preserved from the original sign-in - the refresh token already contains tenant information.

### Multi-Tenancy Support (Google Identity Platform)

All IAM operations support optional tenant isolation through Identity Platform's multi-tenancy feature:

```go
package main

import (
    "context"
    "log"

    "github.com/ranesidd/iam/google_iam"
)

func main() {
    iam, err := googleiam.New()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    tenantID := "tenant-id-123"

    // Create account in a specific tenant
    request := googleiam.CreateAccountRequest{
        Email:       "user@example.com",
        Password:    "securepassword",
        DisplayName: "John Doe",
        TenantID:    &tenantID, // Optional: specify tenant ID
    }
    account, err := iam.CreateAccount(ctx, request)
    if err != nil {
        log.Fatal(err)
    }

    // Sign in to a tenant
    response, err := iam.SignIn(ctx, "user@example.com", "password", tenantID)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Signed in: %s", response.Email)

    // All methods support optional tenantID parameter
    user, err := iam.GetAccount(ctx, account.Account.UUID, tenantID)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("User: %s", user.Email)
}
```

**Backward Compatible**: All tenant parameters are optional. Omitting them uses the default project-level authentication.

### Tenant Management

Create and manage Identity Platform tenants programmatically:

```go
package main

import (
    "context"
    "log"

    "github.com/ranesidd/iam/google_iam"
)

func main() {
    iam, err := googleiam.New()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    allowPasswordSignUp := true
    enableEmailLink := false

    // Create a new tenant
    tenantReq := googleiam.CreateTenantRequest{
        DisplayName:           "My Application Tenant",
        AllowPasswordSignUp:   &allowPasswordSignUp,
        EnableEmailLinkSignIn: &enableEmailLink,
    }
    tenant, err := iam.CreateTenant(ctx, tenantReq)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Created tenant: %s (ID: %s)", tenant.DisplayName, tenant.ID)

    // Delete a tenant
    err = iam.DeleteTenant(ctx, tenant.ID)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("Tenant deleted successfully")
}
```

### Unified Interface (Provider-Agnostic)

```go
package main

import (
    "context"
    "database/sql"
    "log"

    "github.com/ranesidd/iam"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // Initialize database (optional, for OTP support)
    db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/database")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Initialize with unified interface
    // Automatically selects provider based on PROVIDER_GCP env var
    iamClient, err := iam.NewWithDatabase(db)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Use the same IAM operations regardless of provider
    // The interface abstracts provider-specific implementations
    log.Printf("IAM client initialized: %+v", iamClient)
}
```

### OTP (One-Time Password)

```go
package main

import (
    "context"
    "database/sql"
    "log"

    "github.com/ranesidd/iam/otp"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    // Initialize database connection
    db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/database")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create OTP service (no IAM provider needed!)
    otpService := otp.New(db)

    ctx := context.Background()

    // Generate OTP with 24 hour expiration
    otpPayload, err := otpService.Generate(ctx, "user@example.com", 24)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Generated OTP: %s (expires: %v)", otpPayload.Code, otpPayload.ExpiresAt)

    // Validate OTP
    err = otpService.Validate(ctx, "user@example.com", otpPayload.Code)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("OTP validated successfully!")
}
```

## Configuration

### Environment Variables

**For Unified IAM Interface:**

```bash
export PROVIDER_GCP=true  # Enable Google Cloud Platform provider
```

**For Google Firebase provider:**

```bash
export GOOGLE_PROJECT_ID="your-firebase-project-id"
export GOOGLE_API_KEY="your-firebase-api-key"

# Credentials via ADC (for local development):
gcloud auth application-default login --impersonate-service-account=<service-account>@PROJECT-ID.iam.gserviceaccount.com
```

**Required IAM Roles:**
- The service account must have the **"Identity Toolkit Admin"** (`roles/identitytoolkit.admin`) role
- Your login account must have the **"Service Account Token Creator"** (`roles/iam.serviceAccountTokenCreator`) role to impersonate the service account

**Note**: When running on Google Cloud (App Engine, Cloud Run, Cloud Functions, GKE), ADC automatically uses the environment's default service account - no additional configuration needed.

**For Multi-Tenancy (Google Identity Platform):**

Multi-tenancy requires upgrading to Firebase Authentication with Identity Platform (GCP paid tier). No additional environment variables needed - tenant IDs are passed per operation or managed via `CreateTenant()` / `DeleteTenant()` methods.

**For OTP functionality:**

No environment variables required! The OTP package is standalone and only requires a database connection.

### Database Setup (for OTP functionality)

Create the following table for OTP support:

```sql
CREATE TABLE verification_codes (
    email VARCHAR(255) PRIMARY KEY,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
```

## API Reference

### Google IAM Operations

**Account Management**
```go
AccountExists(ctx context.Context, email string, tenantID ...string) (bool, error)
CreateAccount(ctx context.Context, account CreateAccountRequest) (*CreateAccountResponse, error)
GetAccount(ctx context.Context, accountUID string, tenantID ...string) (*Account, error)
UpdateAccount(ctx context.Context, accountUID string, account UpdateAccountRequest, tenantID ...string) (*UpdateAccountResponse, error)
DeleteAccount(ctx context.Context, accountUID string, tenantID ...string) error
```

**Authentication**
```go
SignIn(ctx context.Context, email, password string, tenantID ...string) (*SignInResponse, error)
SignOut(ctx context.Context, accountUUID string, tenantID ...string) error
RefreshToken(ctx context.Context, refreshToken string) (*RefreshTokenResponse, error)
VerifyToken(ctx context.Context, token string, tenantID ...string) (*DecodedToken, error)
Initiate(ctx context.Context, email string, tenantID ...string) error
```

**Token Verification Response Types:**

The `VerifyToken` method returns a `DecodedToken` containing the verified token's claims and Firebase-specific metadata:

```go
type DecodedToken struct {
    AuthTime int64                  `json:"auth_time"`  // Unix timestamp when user authenticated
    Issuer   string                 `json:"iss"`        // Token issuer (Firebase project URL)
    Audience string                 `json:"aud"`        // Token audience (Firebase project ID)
    Expires  int64                  `json:"exp"`        // Unix timestamp when token expires
    IssuedAt int64                  `json:"iat"`        // Unix timestamp when token was issued
    Subject  string                 `json:"sub"`        // User ID (same as UUID)
    UUID     string                 `json:"uuid"`       // User's unique identifier
    Claims   map[string]interface{} `json:"-"`          // Additional custom claims
    Firebase FirebaseInfo           `json:"firebase"`   // Firebase-specific information
}

type FirebaseInfo struct {
    SignInProvider string                 `json:"sign_in_provider"` // Authentication method (e.g., "password", "google.com")
    Tenant         string                 `json:"tenant"`           // Tenant ID (empty for non-tenant accounts)
    Identities     map[string]interface{} `json:"identities"`       // User identity information (email, phone, etc.)
}
```

Example usage:

```go
// Verify and decode an ID token
decodedToken, err := iam.VerifyToken(ctx, idToken)
if err != nil {
    log.Fatal(err)
}

log.Printf("User ID: %s", decodedToken.UUID)
log.Printf("Sign-in method: %s", decodedToken.Firebase.SignInProvider)
log.Printf("Tenant ID: %s", decodedToken.Firebase.Tenant) // Empty for non-tenant accounts
log.Printf("Identities: %+v", decodedToken.Firebase.Identities)
```

**Password Operations**
```go
UpdateAccountPassword(ctx context.Context, accountUID string, request UpdatePasswordRequest) (*SignInResponse, error)
ResetPasswordLink(ctx context.Context, email string, tenantID ...string) (*string, error)
```

**Tenant Management**
```go
CreateTenant(ctx context.Context, request CreateTenantRequest) (*TenantInfo, error)
DeleteTenant(ctx context.Context, tenantID string) error
```

**Notes:**
- All `tenantID` parameters are optional (variadic) - omit for default project-level authentication
- `CreateAccountRequest`, `UpdatePasswordRequest`, and `SignInRequest` include optional `TenantID *string` field
- Multi-tenancy requires Firebase Authentication with Identity Platform (paid tier)

### OTP Package (`github.com/ranesidd/iam/otp`)

```go
// Initialize OTP service
New(db *sql.DB) *OTP

// Generate OTP with custom expiration (in hours)
Generate(ctx context.Context, email string, expirationHours int) (*OTPPayload, error)

// Validate OTP code
Validate(ctx context.Context, email, code string) error

// OTPPayload type
type OTPPayload struct {
    Email     string
    Code      string
    ExpiresAt time.Time
}
```

## Error Handling

The library uses structured error handling with custom error types (located in `github.com/ranesidd/iam/common`):

```go
// Located in github.com/ranesidd/iam/common
type IAMError struct {
    Message string    `json:"message"`
    Code    ErrorCode `json:"error_code"`
}

const (
    AlreadyExists ErrorCode = iota + 100000
    NotFound
)
```

## Supported Providers

- ✅ **Google Cloud Platform** (Firebase Authentication)
- 🔄 **AWS Cognito** (Planned)
- 🔄 **Auth0** (Planned)
- 🔄 **Azure AD** (Planned)

## Development

### Running Tests

**Unit Tests**

```bash
go test ./...
```

**Integration Tests**

Integration tests require Firebase credentials and use the `integration` build tag.

**Required Environment Variables:**
```bash
export GOOGLE_PROJECT_ID="your-firebase-project-id"
export GOOGLE_API_KEY="your-firebase-api-key"
```

**Required Authentication (Application Default Credentials):**
```bash
gcloud auth application-default login --impersonate-service-account=<service-account>@PROJECT-ID.iam.gserviceaccount.com
```

**Required IAM Roles:**
- Service account: **"Identity Toolkit Admin"** (`roles/identitytoolkit.admin`)
- Your login account: **"Service Account Token Creator"** (`roles/iam.serviceAccountTokenCreator`)

**Run Integration Tests:**
```bash
# Run all integration tests
go test -tags=integration ./google_iam -v

# Run a specific integration test
go test -tags=integration ./google_iam -v -run TestAccountLifecycle

# Run all tests (unit + integration)
go test -tags=integration ./...
```

**Note**: Integration tests will be skipped if environment variables are not set. Multi-tenancy tests require Firebase Authentication with Identity Platform (paid tier).

### Building

```bash
go build ./...
```

### Dependencies

- Go 1.23+
- Firebase Admin SDK
- Google Cloud APIs

## Contributing

This project is currently in early development. Contributions are welcome, especially for adding support for additional IAM providers.

## License

See [LICENSE](LICENSE) file for details.