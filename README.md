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

### Google Firebase Features
- **OTP Support**: Generate and validate one-time passwords with database persistence
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

### With OTP Support

```go
// Initialize with database for OTP functionality
db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/database")
if err != nil {
    log.Fatal(err)
}

iam, err := googleiam.NewWithOTP(db)
if err != nil {
    log.Fatal(err)
}

// Generate OTP
otp, err := iam.GenerateOTP(ctx, "user@example.com")
if err != nil {
    log.Fatal(err)
}

// Validate OTP
err = iam.ValidateOTP(ctx, "user@example.com", otp.Code)
if err != nil {
    log.Fatal(err)
}
```

## Configuration

### Environment Variables

For Google Firebase provider:

```bash
export GOOGLE_SDK_CONFIG='{"type":"service_account","project_id":"your-project",...}'
export GOOGLE_API_KEY="your-firebase-api-key"
```

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

### Core Operations

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

// OTP operations (requires database)
GenerateOTP(ctx context.Context, email string) (*OTP, error)
ValidateOTP(ctx context.Context, email, code string) error
```

## Error Handling

The library uses structured error handling with custom error types:

```go
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