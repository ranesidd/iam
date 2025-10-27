//go:build integration
// +build integration

package googleiam_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	googleiam "github.com/ranesidd/iam/google_iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers

// setupIntegrationTest initializes a Google IAM client with real credentials
func setupIntegrationTest(t *testing.T) *googleiam.GoogleIAM {
	t.Helper()

	// Check for required environment variables
	if os.Getenv("GOOGLE_PROJECT_ID") == "" {
		t.Skip("GOOGLE_PROJECT_ID not set - skipping integration test")
	}
	if os.Getenv("GOOGLE_API_KEY") == "" {
		t.Skip("GOOGLE_API_KEY not set - skipping integration test")
	}

	client, err := googleiam.New()
	require.NoError(t, err, "Failed to initialize Google IAM client")

	return client
}

// generateTestEmail creates a unique email address for testing
func generateTestEmail() string {
	return fmt.Sprintf("test-%s@example.com", uuid.New().String()[:8])
}

// generateTestDisplayName creates a unique display name for testing
func generateTestDisplayName() string {
	return fmt.Sprintf("Test User %s", uuid.New().String()[:8])
}

// cleanupTestUser deletes a test user, ignoring errors if user doesn't exist
func cleanupTestUser(t *testing.T, client *googleiam.GoogleIAM, uid string, tenantID ...string) {
	t.Helper()
	ctx := context.Background()

	if len(tenantID) > 0 {
		_ = client.DeleteAccount(ctx, uid, tenantID[0])
	} else {
		_ = client.DeleteAccount(ctx, uid)
	}
}

// cleanupTestTenant deletes a test tenant, ignoring errors if tenant doesn't exist
func cleanupTestTenant(t *testing.T, client *googleiam.GoogleIAM, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_ = client.DeleteTenant(ctx, tenantID)
}

// createTestTenant creates a tenant for testing with cleanup
func createTestTenant(t *testing.T, client *googleiam.GoogleIAM) *googleiam.TenantInfo {
	t.Helper()
	ctx := context.Background()

	allowPasswordSignUp := true
	req := googleiam.CreateTenantRequest{
		DisplayName:         fmt.Sprintf("test-%s", uuid.New().String()[:8]),
		AllowPasswordSignUp: &allowPasswordSignUp,
	}

	tenant, err := client.CreateTenant(ctx, req)
	require.NoError(t, err, "Failed to create test tenant")

	t.Cleanup(func() {
		cleanupTestTenant(t, client, tenant.ID)
	})

	return tenant
}

// Account Management Integration Tests

func TestAccountLifecycle(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// 1. Create Account
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err, "Failed to create account")
	require.NotNil(t, createResp)
	assert.Equal(t, email, createResp.Account.Email)
	assert.Equal(t, displayName, createResp.Account.DisplayName)
	assert.NotEmpty(t, createResp.Account.UUID)

	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	// 2. AccountExists - should return true
	exists, err := client.AccountExists(ctx, email)
	require.NoError(t, err)
	assert.True(t, exists, "Account should exist")

	// 3. GetAccount
	account, err := client.GetAccount(ctx, accountUID)
	require.NoError(t, err)
	assert.Equal(t, email, account.Email)
	assert.Equal(t, displayName, account.DisplayName)

	// 4. UpdateAccount
	newDisplayName := "Updated " + displayName
	updateReq := googleiam.UpdateAccountRequest{
		DisplayName: newDisplayName,
	}

	updateResp, err := client.UpdateAccount(ctx, accountUID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, newDisplayName, updateResp.Account.DisplayName)

	// 5. DeleteAccount
	err = client.DeleteAccount(ctx, accountUID)
	require.NoError(t, err)

	// 6. AccountExists - should return false after deletion
	exists, err = client.AccountExists(ctx, email)
	require.NoError(t, err)
	assert.False(t, exists, "Account should not exist after deletion")
}

func TestCreateAccountWithOptionalFields(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()
	phone := "+15555550100"
	photoURL := "https://example.com/photo.jpg"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		Phone:       &phone,
		PhotoURL:    &photoURL,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, createResp)

	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	assert.Equal(t, email, createResp.Account.Email)
	assert.NotNil(t, createResp.Account.Phone)
	assert.Equal(t, phone, *createResp.Account.Phone)
	assert.NotNil(t, createResp.Account.PhotoURL)
	assert.Equal(t, photoURL, *createResp.Account.PhotoURL)
}

func TestAccountExists(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	t.Run("returns true for existing account", func(t *testing.T) {
		email := generateTestEmail()
		createReq := googleiam.CreateAccountRequest{
			Email:       email,
			Password:    "testPassword123!",
			DisplayName: generateTestDisplayName(),
		}

		createResp, err := client.CreateAccount(ctx, createReq)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanupTestUser(t, client, createResp.Account.UUID)
		})

		exists, err := client.AccountExists(ctx, email)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent account", func(t *testing.T) {
		email := generateTestEmail()
		exists, err := client.AccountExists(ctx, email)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// Authentication Integration Tests

func TestSignInFlow(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create test account
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	t.Run("sign in with correct credentials", func(t *testing.T) {
		signInResp, err := client.SignIn(ctx, email, password)
		require.NoError(t, err)
		assert.NotEmpty(t, signInResp.IDToken)
		assert.NotEmpty(t, signInResp.RefreshToken)
		assert.Equal(t, email, signInResp.Email)
		assert.Equal(t, displayName, signInResp.DisplayName)
	})

	t.Run("sign in with wrong password", func(t *testing.T) {
		_, err := client.SignIn(ctx, email, "wrongPassword")
		assert.Error(t, err)
	})

	t.Run("sign in with non-existent email", func(t *testing.T) {
		_, err := client.SignIn(ctx, generateTestEmail(), password)
		assert.Error(t, err)
	})
}

func TestTokenVerification(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	// Sign in to get token
	signInResp, err := client.SignIn(ctx, email, password)
	require.NoError(t, err)

	t.Run("verify valid token", func(t *testing.T) {
		decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken)
		assert.NoError(t, err)
		assert.NotNil(t, decodedToken)
		assert.Equal(t, createResp.Account.UUID, decodedToken.UUID)
		assert.NotEmpty(t, decodedToken.Subject)
		assert.NotEmpty(t, decodedToken.Issuer)
		assert.NotEmpty(t, decodedToken.Audience)
		assert.Greater(t, decodedToken.Expires, int64(0))
		assert.Greater(t, decodedToken.IssuedAt, int64(0))
		assert.Greater(t, decodedToken.AuthTime, int64(0))

		// Verify Firebase info is populated
		assert.NotEmpty(t, decodedToken.Firebase.SignInProvider, "SignInProvider should be populated")
		assert.NotNil(t, decodedToken.Firebase.Identities, "Identities should be populated")
		// Tenant should be empty for non-tenant accounts
		assert.Empty(t, decodedToken.Firebase.Tenant, "Tenant should be empty for non-tenant accounts")
	})

	t.Run("verify invalid token", func(t *testing.T) {
		decodedToken, err := client.VerifyToken(ctx, "invalid-token")
		assert.Error(t, err)
		assert.Nil(t, decodedToken)
	})
}

func TestRefreshToken(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create test account
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	// Sign in to get initial tokens
	signInResp, err := client.SignIn(ctx, email, password)
	require.NoError(t, err)
	assert.NotEmpty(t, signInResp.IDToken)
	assert.NotEmpty(t, signInResp.RefreshToken)

	t.Run("refresh token with valid refresh token", func(t *testing.T) {
		refreshResp, err := client.RefreshToken(ctx, signInResp.RefreshToken)
		require.NoError(t, err)

		// Verify response contains all expected fields
		assert.NotEmpty(t, refreshResp.IDToken, "ID token should not be empty")
		assert.NotEmpty(t, refreshResp.RefreshToken, "Refresh token should not be empty")
		assert.NotEmpty(t, refreshResp.ExpiresIn, "ExpiresIn should not be empty")
		assert.NotEmpty(t, refreshResp.TokenType, "TokenType should not be empty")
		assert.NotEmpty(t, refreshResp.UUID, "UUID should not be empty")
		assert.NotEmpty(t, refreshResp.ProjectID, "ProjectID should not be empty")

		// Verify UUID matches the created account
		assert.Equal(t, createResp.Account.UUID, refreshResp.UUID, "UUID should match the account")

		// Verify the refreshed ID token is valid
		decodedToken, err := client.VerifyToken(ctx, refreshResp.IDToken)
		assert.NoError(t, err, "Refreshed ID token should be valid")
		assert.NotNil(t, decodedToken)
		assert.Equal(t, createResp.Account.UUID, decodedToken.UUID)

		// Verify the new refresh token works
		secondRefreshResp, err := client.RefreshToken(ctx, refreshResp.RefreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, secondRefreshResp.IDToken)
	})

	t.Run("refresh token with invalid refresh token", func(t *testing.T) {
		_, err := client.RefreshToken(ctx, "invalid-refresh-token")
		assert.Error(t, err, "Should fail with invalid refresh token")
	})

	t.Run("refresh token with empty refresh token", func(t *testing.T) {
		_, err := client.RefreshToken(ctx, "")
		assert.Error(t, err, "Should fail with empty refresh token")
		assert.Contains(t, err.Error(), "refresh token is required")
	})
}

func TestSignOut(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	// Sign in to get tokens
	signInResp, err := client.SignIn(ctx, email, password)
	require.NoError(t, err)

	// Verify token works before sign out
	decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken)
	require.NoError(t, err)
	require.NotNil(t, decodedToken)

	// Sign out to revoke refresh tokens
	err = client.SignOut(ctx, createResp.Account.UUID)
	assert.NoError(t, err)

	// Note: ID token may still be valid until expiry, but refresh tokens are revoked
	// This is expected Firebase behavior
}

// Password Management Integration Tests

func TestUpdatePassword(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	oldPassword := "oldPassword123!"
	newPassword := "newPassword456!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    oldPassword,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	// Verify old password works
	_, err = client.SignIn(ctx, email, oldPassword)
	require.NoError(t, err)

	// Update password
	updateReq := googleiam.UpdatePasswordRequest{
		CurrentPassword: oldPassword,
		NewPassword:     newPassword,
	}

	signInResp, err := client.UpdateAccountPassword(ctx, createResp.Account.UUID, updateReq)
	require.NoError(t, err)
	assert.NotEmpty(t, signInResp.IDToken)

	// Sign in with new password should work
	_, err = client.SignIn(ctx, email, newPassword)
	assert.NoError(t, err)

	// Sign in with old password should fail
	_, err = client.SignIn(ctx, email, oldPassword)
	assert.Error(t, err)
}

func TestUpdatePasswordFailures(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	t.Run("wrong current password", func(t *testing.T) {
		updateReq := googleiam.UpdatePasswordRequest{
			CurrentPassword: "wrongPassword",
			NewPassword:     "newPassword123!",
		}

		_, err := client.UpdateAccountPassword(ctx, createResp.Account.UUID, updateReq)
		assert.Error(t, err)
	})
}

func TestResetPasswordLink(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    "testPassword123!",
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID)
	})

	// Get reset password link
	link, err := client.ResetPasswordLink(ctx, email)
	require.NoError(t, err)
	assert.NotNil(t, link)
	assert.NotEmpty(t, *link)
	assert.Contains(t, *link, "http")
}

func TestInitiate(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	t.Run("initiate with new email succeeds", func(t *testing.T) {
		email := generateTestEmail()
		err := client.Initiate(ctx, email)
		assert.NoError(t, err)
	})

	t.Run("initiate with existing email fails", func(t *testing.T) {
		email := generateTestEmail()

		// Create account first
		createReq := googleiam.CreateAccountRequest{
			Email:       email,
			Password:    "testPassword123!",
			DisplayName: generateTestDisplayName(),
		}

		createResp, err := client.CreateAccount(ctx, createReq)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanupTestUser(t, client, createResp.Account.UUID)
		})

		// Try to initiate with same email
		err = client.Initiate(ctx, email)
		assert.Error(t, err)
	})
}

// Multi-Tenancy Integration Tests

func TestTenantManagement(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	t.Run("create and delete tenant", func(t *testing.T) {
		allowPasswordSignUp := true
		enableEmailLink := false

		createReq := googleiam.CreateTenantRequest{
			DisplayName:           fmt.Sprintf("test-%s", uuid.New().String()[:8]),
			AllowPasswordSignUp:   &allowPasswordSignUp,
			EnableEmailLinkSignIn: &enableEmailLink,
		}

		tenant, err := client.CreateTenant(ctx, createReq)
		require.NoError(t, err)
		assert.NotEmpty(t, tenant.ID)
		assert.Equal(t, createReq.DisplayName, tenant.DisplayName)
		assert.True(t, tenant.AllowPasswordSignUp)
		assert.False(t, tenant.EnableEmailLinkSignIn)

		// Delete tenant
		err = client.DeleteTenant(ctx, tenant.ID)
		assert.NoError(t, err)
	})

	t.Run("create tenant with minimal config", func(t *testing.T) {
		createReq := googleiam.CreateTenantRequest{
			DisplayName: fmt.Sprintf("minimal-%s", uuid.New().String()[:8]),
		}

		tenant, err := client.CreateTenant(ctx, createReq)
		require.NoError(t, err)
		assert.NotEmpty(t, tenant.ID)

		t.Cleanup(func() {
			cleanupTestTenant(t, client, tenant.ID)
		})
	})
}

func TestMultiTenancyAccountIsolation(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	// Create two tenants
	tenant1 := createTestTenant(t, client)
	tenant2 := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create account in tenant1
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		TenantID:    &tenant1.ID,
	}

	createResp1, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp1.Account.UUID, tenant1.ID)
	})

	// Create account with same email in tenant2 (should succeed due to isolation)
	createReq.TenantID = &tenant2.ID
	createResp2, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp2.Account.UUID, tenant2.ID)
	})

	// Verify both accounts exist in their respective tenants
	assert.NotEqual(t, createResp1.Account.UUID, createResp2.Account.UUID)
	assert.Equal(t, email, createResp1.Account.Email)
	assert.Equal(t, email, createResp2.Account.Email)
}

func TestSignInWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create account in tenant
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
	})

	t.Run("sign in with correct tenant ID", func(t *testing.T) {
		signInResp, err := client.SignIn(ctx, email, password, tenant.ID)
		require.NoError(t, err)
		assert.NotEmpty(t, signInResp.IDToken)
		assert.NotEmpty(t, signInResp.RefreshToken)
		assert.Equal(t, email, signInResp.Email)
		assert.Equal(t, displayName, signInResp.DisplayName)
	})

	t.Run("sign in without tenant ID fails", func(t *testing.T) {
		_, err := client.SignIn(ctx, email, password)
		assert.Error(t, err)
	})

	t.Run("sign in with wrong tenant ID fails", func(t *testing.T) {
		wrongTenant := createTestTenant(t, client)
		_, err := client.SignIn(ctx, email, password, wrongTenant.ID)
		assert.Error(t, err)
	})
}

func TestTenantAwareOperations(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create account in tenant
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID, tenant.ID)
	})

	t.Run("get account with tenant ID", func(t *testing.T) {
		account, err := client.GetAccount(ctx, accountUID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, email, account.Email)
		assert.Equal(t, displayName, account.DisplayName)
	})

	t.Run("get account without tenant ID fails", func(t *testing.T) {
		_, err := client.GetAccount(ctx, accountUID)
		assert.Error(t, err)
	})

	t.Run("update account with tenant ID", func(t *testing.T) {
		newDisplayName := "Updated " + displayName
		updateReq := googleiam.UpdateAccountRequest{
			DisplayName: newDisplayName,
		}

		updateResp, err := client.UpdateAccount(ctx, accountUID, updateReq, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, newDisplayName, updateResp.Account.DisplayName)
	})

	t.Run("account exists with tenant ID", func(t *testing.T) {
		exists, err := client.AccountExists(ctx, email, tenant.ID)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("account exists without tenant ID returns false", func(t *testing.T) {
		exists, err := client.AccountExists(ctx, email)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("verify token with tenant ID", func(t *testing.T) {
		signInResp, err := client.SignIn(ctx, email, password, tenant.ID)
		require.NoError(t, err)

		decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken, tenant.ID)
		assert.NoError(t, err)
		assert.NotNil(t, decodedToken)
		assert.Equal(t, accountUID, decodedToken.UUID)
		assert.NotEmpty(t, decodedToken.Subject)

		// Verify Firebase info is populated for tenant
		assert.NotEmpty(t, decodedToken.Firebase.SignInProvider, "SignInProvider should be populated")
		assert.NotNil(t, decodedToken.Firebase.Identities, "Identities should be populated")
		assert.Equal(t, tenant.ID, decodedToken.Firebase.Tenant, "Tenant should match the tenant ID used for sign in")
	})

	t.Run("reset password link with tenant ID", func(t *testing.T) {
		link, err := client.ResetPasswordLink(ctx, email, tenant.ID)
		require.NoError(t, err)
		assert.NotNil(t, link)
		assert.NotEmpty(t, *link)
		assert.Contains(t, *link, "http")
	})
}

func TestUpdatePasswordWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	oldPassword := "oldPassword123!"
	newPassword := "newPassword456!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    oldPassword,
		DisplayName: generateTestDisplayName(),
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
	})

	// Verify old password works
	_, err = client.SignIn(ctx, email, oldPassword, tenant.ID)
	require.NoError(t, err)

	// Update password
	updateReq := googleiam.UpdatePasswordRequest{
		CurrentPassword: oldPassword,
		NewPassword:     newPassword,
		TenantID:        &tenant.ID,
	}

	signInResp, err := client.UpdateAccountPassword(ctx, createResp.Account.UUID, updateReq)
	require.NoError(t, err)
	assert.NotEmpty(t, signInResp.IDToken)

	// Sign in with new password should work
	_, err = client.SignIn(ctx, email, newPassword, tenant.ID)
	assert.NoError(t, err)

	// Sign in with old password should fail
	_, err = client.SignIn(ctx, email, oldPassword, tenant.ID)
	assert.Error(t, err)
}

func TestSignOutWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
	})

	// Sign in to get tokens
	signInResp, err := client.SignIn(ctx, email, password, tenant.ID)
	require.NoError(t, err)

	// Verify token works before sign out
	decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken, tenant.ID)
	require.NoError(t, err)
	require.NotNil(t, decodedToken)

	// Sign out to revoke refresh tokens
	err = client.SignOut(ctx, createResp.Account.UUID, tenant.ID)
	assert.NoError(t, err)
}

func TestRefreshTokenWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"
	displayName := generateTestDisplayName()

	// Create account in tenant
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
	})

	// Sign in to tenant to get tokens
	signInResp, err := client.SignIn(ctx, email, password, tenant.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, signInResp.IDToken)
	assert.NotEmpty(t, signInResp.RefreshToken)

	t.Run("refresh token preserves tenant context", func(t *testing.T) {
		// Refresh the token - tenant context is embedded in the refresh token
		refreshResp, err := client.RefreshToken(ctx, signInResp.RefreshToken)
		require.NoError(t, err)

		// Verify response contains all expected fields
		assert.NotEmpty(t, refreshResp.IDToken)
		assert.NotEmpty(t, refreshResp.RefreshToken)
		assert.NotEmpty(t, refreshResp.UUID)

		// Verify the new ID token works with the tenant
		decodedToken, err := client.VerifyToken(ctx, refreshResp.IDToken, tenant.ID)
		assert.NoError(t, err, "Refreshed token should work with original tenant")
		assert.NotNil(t, decodedToken)
		assert.Equal(t, createResp.Account.UUID, decodedToken.UUID)

		// Verify the refreshed token has tenant context (same user UUID)
		assert.Equal(t, createResp.Account.UUID, refreshResp.UUID, "UUID should match the tenant-scoped account")

		// Verify Firebase info includes tenant context
		assert.Equal(t, tenant.ID, decodedToken.Firebase.Tenant, "Tenant should be preserved after refresh")
		assert.NotEmpty(t, decodedToken.Firebase.SignInProvider, "SignInProvider should be populated")
	})

	t.Run("multiple refresh cycles maintain tenant context", func(t *testing.T) {
		currentRefreshToken := signInResp.RefreshToken

		// Perform multiple refresh cycles
		for i := 0; i < 3; i++ {
			refreshResp, err := client.RefreshToken(ctx, currentRefreshToken)
			require.NoError(t, err, "Refresh cycle %d should succeed", i+1)

			// Verify token works with tenant
			decodedToken, err := client.VerifyToken(ctx, refreshResp.IDToken, tenant.ID)
			assert.NoError(t, err, "Token from refresh cycle %d should work with tenant", i+1)
			assert.NotNil(t, decodedToken)
			assert.Equal(t, createResp.Account.UUID, decodedToken.UUID)

			// Verify tenant context is maintained through refresh cycles
			assert.Equal(t, tenant.ID, decodedToken.Firebase.Tenant, "Tenant should be maintained through refresh cycle %d", i+1)

			// Use new refresh token for next iteration
			currentRefreshToken = refreshResp.RefreshToken
		}
	})
}

func TestInitiateWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	t.Run("initiate with new email in tenant succeeds", func(t *testing.T) {
		email := generateTestEmail()
		err := client.Initiate(ctx, email, tenant.ID)
		assert.NoError(t, err)
	})

	t.Run("initiate with existing email in tenant fails", func(t *testing.T) {
		email := generateTestEmail()

		// Create account in tenant first
		createReq := googleiam.CreateAccountRequest{
			Email:       email,
			Password:    "testPassword123!",
			DisplayName: generateTestDisplayName(),
			TenantID:    &tenant.ID,
		}

		createResp, err := client.CreateAccount(ctx, createReq)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
		})

		// Try to initiate with same email in same tenant
		err = client.Initiate(ctx, email, tenant.ID)
		assert.Error(t, err)
	})

	t.Run("initiate with email existing in different tenant succeeds", func(t *testing.T) {
		email := generateTestEmail()
		tenant2 := createTestTenant(t, client)

		// Create account in tenant1
		createReq := googleiam.CreateAccountRequest{
			Email:       email,
			Password:    "testPassword123!",
			DisplayName: generateTestDisplayName(),
			TenantID:    &tenant.ID,
		}

		createResp, err := client.CreateAccount(ctx, createReq)
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanupTestUser(t, client, createResp.Account.UUID, tenant.ID)
		})

		// Initiate with same email in tenant2 should succeed
		err = client.Initiate(ctx, email, tenant2.ID)
		assert.NoError(t, err)
	})
}

// Custom Claims Integration Tests

func TestSetCustomUserClaims(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	// Create test account
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	t.Run("set custom claims on user", func(t *testing.T) {
		claims := map[string]interface{}{
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
			"level":       5,
		}

		err := client.SetCustomUserClaims(ctx, accountUID, claims)
		assert.NoError(t, err)

		// Verify claims appear in GetAccount
		account, err := client.GetAccount(ctx, accountUID)
		require.NoError(t, err)
		assert.NotNil(t, account.CustomClaims)
		assert.Equal(t, "admin", account.CustomClaims["role"])
		assert.Equal(t, float64(5), account.CustomClaims["level"]) // JSON numbers are float64

		// Sign in to get a new token with claims
		signInResp, err := client.SignIn(ctx, email, password)
		require.NoError(t, err)

		// Verify claims appear in the token
		decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken)
		require.NoError(t, err)
		assert.NotNil(t, decodedToken.Claims)
		assert.Equal(t, "admin", decodedToken.Claims["role"])
		assert.Equal(t, float64(5), decodedToken.Claims["level"])
	})
}

func TestUpdateCustomUserClaims(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	// Set initial claims
	initialClaims := map[string]interface{}{
		"role":  "user",
		"level": 1,
	}
	err = client.SetCustomUserClaims(ctx, accountUID, initialClaims)
	require.NoError(t, err)

	// Update claims
	updatedClaims := map[string]interface{}{
		"role":       "admin",
		"level":      10,
		"department": "engineering",
	}
	err = client.SetCustomUserClaims(ctx, accountUID, updatedClaims)
	assert.NoError(t, err)

	// Verify updated claims
	account, err := client.GetAccount(ctx, accountUID)
	require.NoError(t, err)
	assert.Equal(t, "admin", account.CustomClaims["role"])
	assert.Equal(t, float64(10), account.CustomClaims["level"])
	assert.Equal(t, "engineering", account.CustomClaims["department"])
}

func TestRemoveCustomUserClaims(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	password := "testPassword123!"

	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	// Set claims
	claims := map[string]interface{}{
		"role": "admin",
	}
	err = client.SetCustomUserClaims(ctx, accountUID, claims)
	require.NoError(t, err)

	// Remove all claims by passing nil
	err = client.SetCustomUserClaims(ctx, accountUID, nil)
	assert.NoError(t, err)

	// Verify claims are removed
	account, err := client.GetAccount(ctx, accountUID)
	require.NoError(t, err)
	assert.Empty(t, account.CustomClaims)
}

func TestCustomClaimsInGetAccount(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    "testPassword123!",
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	// New account should have no custom claims
	account, err := client.GetAccount(ctx, accountUID)
	require.NoError(t, err)
	assert.Empty(t, account.CustomClaims)

	// Set claims
	claims := map[string]interface{}{
		"subscription": "premium",
		"credits":      100,
	}
	err = client.SetCustomUserClaims(ctx, accountUID, claims)
	require.NoError(t, err)

	// GetAccount should return the claims
	account, err = client.GetAccount(ctx, accountUID)
	require.NoError(t, err)
	assert.NotEmpty(t, account.CustomClaims)
	assert.Equal(t, "premium", account.CustomClaims["subscription"])
	assert.Equal(t, float64(100), account.CustomClaims["credits"])
}

func TestCustomClaimsWithTenant(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	tenant := createTestTenant(t, client)

	email := generateTestEmail()
	password := "testPassword123!"

	// Create account in tenant
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    password,
		DisplayName: generateTestDisplayName(),
		TenantID:    &tenant.ID,
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID, tenant.ID)
	})

	t.Run("set and verify claims in tenant", func(t *testing.T) {
		claims := map[string]interface{}{
			"tenant_role": "tenant_admin",
			"org_id":      "org-123",
		}

		// Set claims with tenant ID
		err := client.SetCustomUserClaims(ctx, accountUID, claims, tenant.ID)
		assert.NoError(t, err)

		// Get account with tenant ID
		account, err := client.GetAccount(ctx, accountUID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, "tenant_admin", account.CustomClaims["tenant_role"])
		assert.Equal(t, "org-123", account.CustomClaims["org_id"])

		// Sign in to tenant and verify claims in token
		signInResp, err := client.SignIn(ctx, email, password, tenant.ID)
		require.NoError(t, err)

		decodedToken, err := client.VerifyToken(ctx, signInResp.IDToken, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, "tenant_admin", decodedToken.Claims["tenant_role"])
		assert.Equal(t, tenant.ID, decodedToken.Firebase.Tenant)
	})
}

func TestCustomClaimsSizeValidation(t *testing.T) {
	client := setupIntegrationTest(t)
	ctx := context.Background()

	email := generateTestEmail()
	createReq := googleiam.CreateAccountRequest{
		Email:       email,
		Password:    "testPassword123!",
		DisplayName: generateTestDisplayName(),
	}

	createResp, err := client.CreateAccount(ctx, createReq)
	require.NoError(t, err)
	accountUID := createResp.Account.UUID
	t.Cleanup(func() {
		cleanupTestUser(t, client, accountUID)
	})

	t.Run("claims exceeding 1000 bytes should fail", func(t *testing.T) {
		// Create claims that exceed 1000 bytes
		largeClaims := map[string]interface{}{
			"large_field": string(make([]byte, 1000)),
		}

		err := client.SetCustomUserClaims(ctx, accountUID, largeClaims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "1000 byte limit")
	})

	t.Run("claims within limit should succeed", func(t *testing.T) {
		// Create claims well under 1000 bytes
		validClaims := map[string]interface{}{
			"role":   "admin",
			"status": "active",
		}

		err := client.SetCustomUserClaims(ctx, accountUID, validClaims)
		assert.NoError(t, err)
	})
}
