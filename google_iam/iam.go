package googleiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"firebase.google.com/go/auth"
	"github.com/google/uuid"

	common "github.com/ranesidd/iam/common"
)

var (
	signInLink       = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s"
	refreshTokenLink = "https://securetoken.googleapis.com/v1/token?key=%s"
)

// userManagementClient interface abstracts *auth.Client and *auth.TenantClient
// Both types implement these methods, allowing us to use them interchangeably
type userManagementClient interface {
	CreateUser(ctx context.Context, user *auth.UserToCreate) (*auth.UserRecord, error)
	GetUser(ctx context.Context, uid string) (*auth.UserRecord, error)
	GetUserByEmail(ctx context.Context, email string) (*auth.UserRecord, error)
	UpdateUser(ctx context.Context, uid string, user *auth.UserToUpdate) (*auth.UserRecord, error)
	DeleteUser(ctx context.Context, uid string) error
	RevokeRefreshTokens(ctx context.Context, uid string) error
	VerifyIDTokenAndCheckRevoked(ctx context.Context, idToken string) (*auth.Token, error)
	PasswordResetLink(ctx context.Context, email string) (string, error)
}

// getAuthClient returns either a tenant-aware client or the default auth client
// Both *auth.Client and *auth.TenantClient satisfy the userManagementClient interface
func (c *GoogleIAM) getAuthClient(ctx context.Context, tenantID *string) (userManagementClient, error) {
	authClient, err := c.app.Auth(ctx)
	if err != nil {
		return nil, err
	}

	if tenantID != nil && !common.IsEmpty(*tenantID) {
		return authClient.TenantManager.AuthForTenant(*tenantID)
	}

	return authClient, nil
}

func (c *GoogleIAM) AccountExists(ctx context.Context, email string, tenantID ...string) (bool, error) {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return false, err
	}

	_, err = client.GetUserByEmail(ctx, email)
	if err != nil {
		if strings.Contains(err.Error(), "cannot find user") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (c *GoogleIAM) CreateAccount(ctx context.Context, account CreateAccountRequest) (*CreateAccountResponse, error) {
	client, err := c.getAuthClient(ctx, account.TenantID)
	if err != nil {
		return nil, err
	}

	accountUID := uuid.New().String()

	params := (&auth.UserToCreate{}).
		UID(accountUID).
		Email(account.Email).
		Password(account.Password).
		DisplayName(account.DisplayName).
		EmailVerified(true).
		Disabled(false)

	if account.Phone != nil {
		params.PhoneNumber(*account.Phone)
	}

	if account.PhotoURL != nil {
		params.PhotoURL(*account.PhotoURL)
	}

	user, err := client.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	newAccount := CreateAccountResponse{
		Account: Account{
			UUID:          user.UID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			EmailVerified: &user.EmailVerified,
			Disabled:      &user.Disabled,
		},
	}

	if !common.IsEmpty(user.PhoneNumber) {
		newAccount.Account.Phone = &user.PhoneNumber
	}

	if !common.IsEmpty(user.PhotoURL) {
		newAccount.Account.PhotoURL = &user.PhotoURL
	}

	// Pass tenantID to SignIn if provided
	var signInResponse *SignInResponse
	if account.TenantID != nil && !common.IsEmpty(*account.TenantID) {
		signInResponse, err = c.SignIn(ctx, account.Email, account.Password, *account.TenantID)
	} else {
		signInResponse, err = c.SignIn(ctx, account.Email, account.Password)
	}
	if err != nil {
		signInErr := errors.New("account created, please sign in")
		return nil, signInErr
	}
	newAccount.SignInResponse = *signInResponse

	return &newAccount, nil
}

func (c *GoogleIAM) GetAccount(ctx context.Context, accountUID string, tenantID ...string) (*Account, error) {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return nil, err
	}

	user, err := client.GetUser(ctx, accountUID)
	if err != nil {
		return nil, err
	}

	account := Account{
		UUID:          user.UID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		EmailVerified: &user.EmailVerified,
		Disabled:      &user.Disabled,
	}

	if !common.IsEmpty(user.PhoneNumber) {
		account.Phone = &user.PhoneNumber
	}

	if !common.IsEmpty(user.PhotoURL) {
		account.PhotoURL = &user.PhotoURL
	}

	return &account, nil
}

func (c *GoogleIAM) UpdateAccount(ctx context.Context, accountUID string, account UpdateAccountRequest, tenantID ...string) (*UpdateAccountResponse, error) {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return nil, err
	}

	params := (&auth.UserToUpdate{}).
		DisplayName(account.DisplayName)

	user, err := client.UpdateUser(ctx, accountUID, params)
	if err != nil {
		return nil, err
	}

	updatedAccount := UpdateAccountResponse{
		Account: Account{
			UUID:          user.UID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			EmailVerified: &user.EmailVerified,
			Disabled:      &user.Disabled,
		},
	}

	if !common.IsEmpty(user.PhoneNumber) {
		updatedAccount.Account.Phone = &user.PhoneNumber
	}

	if !common.IsEmpty(user.PhotoURL) {
		updatedAccount.Account.PhotoURL = &user.PhotoURL
	}

	return &updatedAccount, nil
}

func (c *GoogleIAM) DeleteAccount(ctx context.Context, accountUID string, tenantID ...string) error {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return err
	}

	return client.DeleteUser(ctx, accountUID)
}

func (c *GoogleIAM) UpdateAccountPassword(
	ctx context.Context,
	accountUID string,
	request UpdatePasswordRequest,
) (*SignInResponse, error) {
	client, err := c.getAuthClient(ctx, request.TenantID)
	if err != nil {
		return nil, err
	}

	// Pass tenantID to GetAccount if provided
	var account *Account
	if request.TenantID != nil && !common.IsEmpty(*request.TenantID) {
		account, err = c.GetAccount(ctx, accountUID, *request.TenantID)
	} else {
		account, err = c.GetAccount(ctx, accountUID)
	}
	if err != nil {
		return nil, err
	}

	// Verify current password by signing in
	var signInErr error
	if request.TenantID != nil && !common.IsEmpty(*request.TenantID) {
		_, signInErr = c.SignIn(ctx, account.Email, request.CurrentPassword, *request.TenantID)
	} else {
		_, signInErr = c.SignIn(ctx, account.Email, request.CurrentPassword)
	}
	if signInErr != nil {
		return nil, errors.New("an error occured while updating password")
	}

	params := (&auth.UserToUpdate{}).
		Password(request.NewPassword)

	_, err = client.UpdateUser(ctx, accountUID, params)
	if err != nil {
		return nil, err
	}

	// Sign in with new password
	var signInResponse *SignInResponse
	if request.TenantID != nil && !common.IsEmpty(*request.TenantID) {
		signInResponse, err = c.SignIn(ctx, account.Email, request.NewPassword, *request.TenantID)
	} else {
		signInResponse, err = c.SignIn(ctx, account.Email, request.NewPassword)
	}
	if err != nil {
		return nil, errors.New("password updated, please sign in again")
	}

	return signInResponse, nil
}

func (c *GoogleIAM) ResetPasswordLink(ctx context.Context, email string, tenantID ...string) (*string, error) {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return nil, err
	}

	actionLink, err := client.PasswordResetLink(ctx, email)
	if err != nil {
		return nil, err
	}

	return &actionLink, nil
}

func (c *GoogleIAM) Initiate(ctx context.Context, email string, tenantID ...string) error {
	var err error
	var exists bool

	if len(tenantID) > 0 {
		exists, err = c.AccountExists(ctx, email, tenantID[0])
	} else {
		exists, err = c.AccountExists(ctx, email)
	}
	if err != nil {
		return err
	}

	if exists {
		return common.IAMError{
			Message: "Account already exists",
			Code:    common.AlreadyExists,
		}
	}

	return nil
}

func (c *GoogleIAM) VerifyToken(ctx context.Context, token string, tenantID ...string) error {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return err
	}

	_, err = client.VerifyIDTokenAndCheckRevoked(ctx, token)
	return err
}

func (c *GoogleIAM) SignOut(ctx context.Context, accountUUID string, tenantID ...string) error {
	var tid *string
	if len(tenantID) > 0 {
		tid = &tenantID[0]
	}

	client, err := c.getAuthClient(ctx, tid)
	if err != nil {
		return err
	}

	return client.RevokeRefreshTokens(ctx, accountUUID)
}

func (c *GoogleIAM) SignIn(ctx context.Context, email, password string, tenantID ...string) (*SignInResponse, error) {
	request := SignInRequest{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}

	// Add tenant ID if provided
	if len(tenantID) > 0 && !common.IsEmpty(tenantID[0]) {
		request.TenantID = &tenantID[0]
	}

	marshalledRequest, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var response SignInResponse
	url := fmt.Sprintf(signInLink, c.apiKey)
	err = common.HttpPost(
		ctx,
		url,
		map[string][]string{
			"Content-Type": {string(common.HTTPContentTypeAppJSON)},
		},
		strings.NewReader(string(marshalledRequest)),
		&response)

	return &response, err
}

// RefreshToken exchanges a refresh token for a new ID token and refresh token.
// The tenant context (if any) is already embedded in the refresh token from the original sign-in.
func (c *GoogleIAM) RefreshToken(ctx context.Context, refreshToken string) (*RefreshTokenResponse, error) {
	if common.IsEmpty(refreshToken) {
		return nil, errors.New("refresh token is required")
	}

	request := RefreshTokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	}

	marshalledRequest, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var response RefreshTokenResponse
	url := fmt.Sprintf(refreshTokenLink, c.apiKey)
	err = common.HttpPost(
		ctx,
		url,
		map[string][]string{
			"Content-Type": {string(common.HTTPContentTypeAppJSON)},
		},
		strings.NewReader(string(marshalledRequest)),
		&response)

	return &response, err
}

func (c *GoogleIAM) CreateTenant(ctx context.Context, request CreateTenantRequest) (*TenantInfo, error) {
	if common.IsEmpty(request.DisplayName) {
		return nil, errors.New("display name is required")
	}

	authClient, err := c.app.Auth(ctx)
	if err != nil {
		return nil, err
	}

	// Build tenant configuration using builder pattern
	tenantToCreate := (&auth.TenantToCreate{}).DisplayName(request.DisplayName)

	if request.AllowPasswordSignUp != nil {
		tenantToCreate = tenantToCreate.AllowPasswordSignUp(*request.AllowPasswordSignUp)
	}

	if request.EnableEmailLinkSignIn != nil {
		tenantToCreate = tenantToCreate.EnableEmailLinkSignIn(*request.EnableEmailLinkSignIn)
	}

	// Create tenant
	tenant, err := authClient.TenantManager.CreateTenant(ctx, tenantToCreate)
	if err != nil {
		return nil, err
	}

	// Map to TenantInfo response
	tenantInfo := &TenantInfo{
		ID:                    tenant.ID,
		DisplayName:           tenant.DisplayName,
		AllowPasswordSignUp:   tenant.AllowPasswordSignUp,
		EnableEmailLinkSignIn: tenant.EnableEmailLinkSignIn,
	}

	return tenantInfo, nil
}

func (c *GoogleIAM) DeleteTenant(ctx context.Context, tenantID string) error {
	if common.IsEmpty(tenantID) {
		return errors.New("tenant ID is required")
	}

	authClient, err := c.app.Auth(ctx)
	if err != nil {
		return err
	}

	return authClient.TenantManager.DeleteTenant(ctx, tenantID)
}
