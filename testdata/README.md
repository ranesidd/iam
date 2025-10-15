# Integration Test Setup

This directory contains setup instructions and resources for running integration tests for the IAM library.

## Prerequisites

### 1. Google Cloud Project Setup

You need a Google Cloud project with Firebase Authentication enabled:

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project or select an existing one
3. Enable Firebase Authentication
4. For multi-tenancy tests, upgrade to **Firebase Authentication with Identity Platform** (requires GCP billing)

### 2. Enable Required APIs

In the [Google Cloud Console](https://console.cloud.google.com/), enable:
- Firebase Authentication API
- Identity Toolkit API
- Identity Platform API (for multi-tenancy)

### 3. Authentication Setup

Set up Application Default Credentials (ADC) using one of these methods:

#### Option A: Service Account (Recommended for CI/CD)

1. Go to [Google Cloud Console](https://console.cloud.google.com/) > IAM & Admin > Service Accounts
2. Create a service account with the following roles:
   - Firebase Authentication Admin
   - Identity Platform Admin (for multi-tenancy tests)
3. Create and download a JSON key file
4. Set the environment variable:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/serviceAccount.json"
   ```

#### Option B: gcloud CLI (Recommended for Local Development)

```bash
gcloud auth application-default login
```

#### Option C: Running on Google Cloud

When running on Google Cloud services (App Engine, Cloud Run, Cloud Functions, GKE), ADC automatically uses the environment's default service account. No additional configuration needed.

### 4. Get API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/) > APIs & Services > Credentials
2. Create an API key or use an existing one
3. (Optional) Restrict the API key to Firebase Authentication APIs for security

## Environment Variables

Set these environment variables before running integration tests:

```bash
# Required for all tests
export GOOGLE_PROJECT_ID="your-firebase-project-id"
export GOOGLE_API_KEY="your-firebase-api-key"

# ADC setup (choose one method from Prerequisites section 3)
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/serviceAccount.json"
# OR run: gcloud auth application-default login
```

### Finding Your Values

- **GOOGLE_PROJECT_ID**: Found in Firebase Console > Project Settings > General > Project ID
- **GOOGLE_API_KEY**: Found in Google Cloud Console > APIs & Services > Credentials

## Running Integration Tests

Integration tests are marked with the `integration` build tag and are skipped during normal test runs.

### Run All Integration Tests

```bash
go test -v -tags=integration ./google_iam
```

### Run Specific Test Functions

```bash
# Run only account lifecycle tests
go test -v -tags=integration -run TestAccountLifecycle ./google_iam

# Run only multi-tenancy tests
go test -v -tags=integration -run TestMultiTenancy ./google_iam

# Run only tenant management tests
go test -v -tags=integration -run TestTenantManagement ./google_iam
```

### Run with Timeout

Integration tests may take longer than unit tests:

```bash
go test -v -tags=integration -timeout 10m ./google_iam
```

## Test Categories

### Account Management Tests
- `TestAccountLifecycle`: Full CRUD operations for user accounts
- `TestCreateAccountWithOptionalFields`: Account creation with phone and photo URL
- `TestAccountExists`: Email existence checks

### Authentication Tests
- `TestSignInFlow`: Sign-in with valid/invalid credentials
- `TestTokenVerification`: ID token validation
- `TestSignOut`: Refresh token revocation

### Password Management Tests
- `TestUpdatePassword`: Password change flow
- `TestUpdatePasswordFailures`: Invalid password update scenarios
- `TestResetPasswordLink`: Password reset link generation
- `TestInitiate`: Account initiation for new emails

### Multi-Tenancy Tests

**Note**: These tests require Firebase Authentication with Identity Platform (paid tier).

- `TestTenantManagement`: Create and delete tenants
- `TestMultiTenancyAccountIsolation`: Verify user isolation across tenants
- `TestSignInWithTenant`: Tenant-specific authentication
- `TestTenantAwareOperations`: All IAM operations with tenant context
- `TestUpdatePasswordWithTenant`: Password updates in tenant context
- `TestSignOutWithTenant`: Sign out with tenant isolation
- `TestInitiateWithTenant`: Account initiation within tenants

## Test Data Cleanup

All integration tests use automatic cleanup:

- **User Accounts**: Automatically deleted via `t.Cleanup()` after each test
- **Tenants**: Automatically deleted via `t.Cleanup()` after each test
- **Unique Identifiers**: Each test generates unique emails and display names using UUIDs

No manual cleanup required.

## Common Issues

### Issue: Tests Skip with "GOOGLE_PROJECT_ID not set"

**Solution**: Ensure environment variables are set in your current shell session:
```bash
echo $GOOGLE_PROJECT_ID
echo $GOOGLE_API_KEY
```

### Issue: "Could not find default credentials"

**Solution**: Set up ADC using one of the methods in Prerequisites section 3.

### Issue: Multi-tenancy tests fail with "PERMISSION_DENIED"

**Solution**:
1. Verify you've upgraded to Firebase Authentication with Identity Platform
2. Ensure your service account has "Identity Platform Admin" role
3. Check that Identity Platform API is enabled in Google Cloud Console

### Issue: "API key not valid"

**Solution**:
1. Verify the API key is correct
2. Check that the API key is enabled in Google Cloud Console
3. If restricted, ensure Firebase Authentication API is allowed

### Issue: Tests timeout

**Solution**: Increase timeout when running tests:
```bash
go test -v -tags=integration -timeout 15m ./google_iam
```

## Security Best Practices

1. **Never commit credentials**: Keep API keys and service account files out of version control
2. **Use restricted API keys**: Limit API keys to specific APIs and referrers when possible
3. **Rotate credentials**: Regularly rotate API keys and service account keys
4. **Use IAM roles**: In production, use fine-grained IAM roles for service accounts
5. **Separate environments**: Use different Firebase projects for development, staging, and production

## Cost Considerations

### Free Tier
- Firebase Authentication Free Tier includes:
  - 10,000 monthly active users (MAUs)
  - 50,000 phone authentications per month
  - Sufficient for integration testing

### Identity Platform (Multi-Tenancy)
- Requires GCP billing
- Pricing: ~$0.0055 per MAU after free tier
- Free tier: 50,000 MAUs per month
- Integration tests typically create/delete users quickly, minimal cost impact

For current pricing, see: https://cloud.google.com/identity-platform/pricing

## Continuous Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.23'

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_CREDENTIALS }}

      - name: Run integration tests
        env:
          GOOGLE_PROJECT_ID: ${{ secrets.GOOGLE_PROJECT_ID }}
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
        run: go test -v -tags=integration -timeout 10m ./google_iam
```

### Required GitHub Secrets
- `GCP_CREDENTIALS`: Service account JSON key (base64 encoded or raw JSON)
- `GOOGLE_PROJECT_ID`: Firebase project ID
- `GOOGLE_API_KEY`: Firebase API key

## Support

For issues or questions:
1. Check the main [README.md](../README.md) for library documentation
2. Review [CLAUDE.md](../CLAUDE.md) for architecture details
3. Consult [Firebase Authentication documentation](https://firebase.google.com/docs/auth)
4. Consult [Identity Platform documentation](https://cloud.google.com/identity-platform/docs)
