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
- **Token Operations**: ID token verification and refresh token revocation

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
export GOOGLE_SDK_CONFIG='{"type":"service_account","project_id":"your-project",...}'
export GOOGLE_API_KEY="your-firebase-api-key"
```

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

```go
// Account management
AccountExists(ctx context.Context, email string) (bool, error)
CreateAccount(ctx context.Context, account CreateAccountRequest) (*CreateAccountResponse, error)
GetAccount(ctx context.Context, accountUID string) (*Account, error)
UpdateAccount(ctx context.Context, accountUID string, account UpdateAccountRequest) (*UpdateAccountResponse, error)
DeleteAccount(ctx context.Context, accountUID string) error

// Authentication
SignIn(ctx context.Context, email, password string) (*SignInResponse, error)
SignOut(ctx context.Context, accountUUID string) error
VerifyToken(ctx context.Context, token string) error

// Password operations
UpdateAccountPassword(ctx context.Context, accountUID string, request UpdatePasswordRequest) (*SignInResponse, error)
ResetPasswordLink(ctx context.Context, email string) (*string, error)
```

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

```bash
go test ./...
```

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