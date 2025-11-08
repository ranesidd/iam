# Contributing to IAM Library

Thank you for your interest in contributing to the IAM library! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Adding New Features](#adding-new-features)
- [Project Structure](#project-structure)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

- Go 1.23 or higher
- Git
- A GitHub account
- For integration tests: Firebase project with proper credentials

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/iam.git
   cd iam
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ranesidd/iam.git
   ```

## Development Setup

### Install Dependencies

```bash
go mod download
go mod verify
```

### Environment Variables for Testing

For integration tests, set up the following environment variables:

```bash
# Required for Google IAM integration tests
export GOOGLE_PROJECT_ID="your-firebase-project-id"
export GOOGLE_API_KEY="your-firebase-api-key"

# Authentication (choose one):
# Option 1: Service account file
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Option 2: Application Default Credentials (ADC)
gcloud auth application-default login --impersonate-service-account=<service-account>@PROJECT-ID.iam.gserviceaccount.com
```

**Required IAM Roles:**
- Service account: `roles/identitytoolkit.admin` (Identity Toolkit Admin)
- Your account: `roles/iam.serviceAccountTokenCreator` (Service Account Token Creator)

### Verify Setup

Run the tests to ensure everything is set up correctly:

```bash
# Run unit tests
go test ./...

# Run integration tests (requires Firebase credentials)
go test -tags=integration ./google_iam -v
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/ranesidd/iam/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Go version and OS
   - Relevant code snippets or error messages

### Suggesting Enhancements

1. Check existing [Issues](https://github.com/ranesidd/iam/issues) for similar suggestions
2. Create a new issue with:
   - Clear, descriptive title
   - Detailed description of the enhancement
   - Use cases and benefits
   - Possible implementation approach (optional)

### Contributing Code

1. **Find an issue** to work on, or create one
2. **Comment on the issue** to let others know you're working on it
3. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** following the coding standards
5. **Write tests** for your changes
6. **Run tests** to ensure everything passes
7. **Commit your changes** following commit guidelines
8. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
9. **Create a Pull Request** from your fork to the main repository

## Coding Standards

### Go Style Guide

- Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` to format your code
- Run `go vet` to catch common mistakes
- Use meaningful variable and function names

### Code Organization

- Keep functions focused and single-purpose
- Group related functionality together
- Use interfaces for abstraction (e.g., `userManagementClient`)
- Maintain backward compatibility whenever possible

### Documentation

- Add comments for all exported functions, types, and constants
- Use complete sentences in comments
- Include examples for complex functionality
- Update README.md and CLAUDE.md for new features

### Error Handling

- Return errors, don't panic
- Use `fmt.Errorf` with `%w` for error wrapping
- Provide clear, actionable error messages
- Use custom error types when appropriate (e.g., `common.IAMError`)

### Example Code Style

```go
// Good
func (c *GoogleIAM) SetCustomUserClaims(ctx context.Context, accountUID string, claims map[string]interface{}, tenantID ...string) error {
    var tid *string
    if len(tenantID) > 0 {
        tid = &tenantID[0]
    }

    // Validate claims size (Firebase limit is 1000 bytes)
    if len(claims) > 0 {
        claimsJSON, err := json.Marshal(claims)
        if err != nil {
            return fmt.Errorf("invalid claims format: %w", err)
        }
        if len(claimsJSON) > 1000 {
            return fmt.Errorf("custom claims exceed 1000 byte limit (size: %d bytes)", len(claimsJSON))
        }
    }

    client, err := c.getAuthClient(ctx, tid)
    if err != nil {
        return err
    }

    return client.SetCustomUserClaims(ctx, accountUID, claims)
}
```

## Testing Guidelines

### Unit Tests

- Write unit tests for all new functionality
- Use table-driven tests for multiple test cases
- Use `testify/assert` and `testify/require` for assertions
- Mock external dependencies (use `sqlmock` for database tests)

### Integration Tests

- Add integration tests for Firebase-related functionality
- Use build tag `//go:build integration`
- Clean up resources in `t.Cleanup()` functions
- Test both success and failure scenarios

### Test Coverage

- Aim for at least 80% test coverage
- Focus on testing business logic and edge cases
- Don't test third-party libraries

### Example Test Structure

```go
func TestFeatureName(t *testing.T) {
    tests := []struct {
        name        string
        input       InputType
        setupMock   func(mock sqlmock.Sqlmock)
        expectError bool
        errorMsg    string
    }{
        {
            name:  "successful case",
            input: validInput,
            setupMock: func(mock sqlmock.Sqlmock) {
                // Set up mock expectations
            },
            expectError: false,
        },
        {
            name:  "error case",
            input: invalidInput,
            setupMock: func(mock sqlmock.Sqlmock) {
                // Set up error expectations
            },
            expectError: true,
            errorMsg:    "expected error message",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Running Tests

```bash
# Run all unit tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./google_iam -v

# Run integration tests
go test -tags=integration ./google_iam -v

# Run specific test
go test -tags=integration ./google_iam -v -run TestSetCustomUserClaims
```

## Commit Guidelines

### Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(google_iam): add custom claims management support

- Add SetCustomUserClaims method with 1000 byte validation
- Update Account type to include CustomClaims field
- Add integration tests for custom claims operations

Closes #42
```

```
fix(otp): use database-agnostic DELETE-then-INSERT for code updates

Replace MySQL-specific ON DUPLICATE KEY UPDATE with standard
DELETE-then-INSERT approach for better database compatibility.

Fixes #38
```

```
docs(readme): add custom claims usage examples

Add comprehensive examples showing how to set, update, and remove
custom claims with both single-tenant and multi-tenant setups.
```

### Best Practices

- Keep commits atomic (one logical change per commit)
- Write clear, descriptive commit messages
- Reference issue numbers when applicable
- Sign commits if possible (`git commit -s`)

## Pull Request Process

### Before Submitting

1. **Update your branch** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests** and ensure they pass:
   ```bash
   go test ./...
   go test -tags=integration ./google_iam -v
   ```

3. **Check code formatting**:
   ```bash
   gofmt -w .
   go vet ./...
   ```

4. **Update documentation** if needed:
   - README.md for user-facing changes
   - CLAUDE.md for architectural changes
   - Code comments for API changes

### Pull Request Template

When creating a pull request, include:

**Description:**
- What changes does this PR introduce?
- Why are these changes needed?

**Related Issues:**
- Closes #XX
- Fixes #YY

**Type of Change:**
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

**Testing:**
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass locally

**Checklist:**
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced

### Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, a maintainer will merge your PR
4. Your contribution will be included in the next release

### After Merge

- Delete your feature branch (both locally and on GitHub)
- Update your local main branch:
  ```bash
  git checkout main
  git pull upstream main
  ```

## Adding New Features

### New IAM Providers

To add support for a new IAM provider (e.g., AWS Cognito, Auth0):

1. Create a new package: `<provider>_iam/`
2. Implement the core IAM interface
3. Add setup/initialization logic
4. Define provider-specific types
5. Write comprehensive tests
6. Update documentation

### New Authentication Methods

1. Add method to the appropriate IAM implementation
2. Update interface if needed
3. Add request/response types
4. Implement with multi-tenancy support (if applicable)
5. Add validation and error handling
6. Write unit and integration tests
7. Update documentation with examples

### Database Support

When adding new database-specific functionality:

1. Use Squirrel query builder for database-agnostic queries
2. Support multiple placeholder formats (?, $1, etc.)
3. Add tests with `sqlmock`
4. Document required schema changes
5. Test with multiple database engines if possible

## Project Structure

```
iam/
├── common/              # Shared utilities and types
│   ├── error.go        # Custom error types
│   └── util.go         # HTTP and helper utilities
├── google_iam/         # Firebase Authentication implementation
│   ├── setup.go        # Client initialization
│   ├── iam.go          # Core operations
│   ├── types.go        # Request/response types
│   ├── setup_test.go   # Setup tests
│   └── iam_integration_test.go  # Integration tests
├── otp/                # Standalone OTP package
│   ├── otp.go          # OTP generation/validation
│   ├── types.go        # OTP types
│   └── otp_test.go     # OTP tests
├── init.go             # Root package initialization
├── go.mod              # Go module definition
├── README.md           # User documentation
├── CLAUDE.md           # AI assistant documentation
├── CONTRIBUTING.md     # This file
└── CODE_OF_CONDUCT.md  # Code of conduct
```

## Questions?

If you have questions about contributing:

1. Check existing [Issues](https://github.com/ranesidd/iam/issues) and [Pull Requests](https://github.com/ranesidd/iam/pulls)
2. Create a new issue with the `question` label
3. Reach out to maintainers

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to the IAM library! Your contributions help make authentication simpler and more accessible for everyone.
