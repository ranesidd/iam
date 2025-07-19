package googleiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"firebase.google.com/go/auth"
	"github.com/google/uuid"

	iam "github.com/ranesidd/iam"
)

var (
	signInLink = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s"
)

func (c *GoogleIAM) AccountExists(ctx context.Context, email string) (bool, error) {
	client, err := c.app.Auth(ctx)
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
	client, err := c.app.Auth(ctx)
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

	if !iam.IsEmpty(user.PhoneNumber) {
		newAccount.Account.Phone = &user.PhoneNumber
	}

	if !iam.IsEmpty(user.PhotoURL) {
		newAccount.Account.PhotoURL = &user.PhotoURL
	}

	signInResponse, err := c.SignIn(ctx, account.Email, account.Password)
	if err != nil {
		signInErr := errors.New("account created, please sign in")
		return nil, signInErr
	}
	newAccount.SignInResponse = *signInResponse

	return &newAccount, nil
}

func (c *GoogleIAM) GetAccount(ctx context.Context, accountUID string) (*Account, error) {
	client, err := c.app.Auth(ctx)
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

	if !iam.IsEmpty(user.PhoneNumber) {
		account.Phone = &user.PhoneNumber
	}

	if !iam.IsEmpty(user.PhotoURL) {
		account.PhotoURL = &user.PhotoURL
	}

	return &account, nil
}

func (c *GoogleIAM) UpdateAccount(ctx context.Context, accountUID string, account UpdateAccountRequest) (*UpdateAccountResponse, error) {
	client, err := c.app.Auth(ctx)
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

	if !iam.IsEmpty(user.PhoneNumber) {
		updatedAccount.Account.Phone = &user.PhoneNumber
	}

	if !iam.IsEmpty(user.PhotoURL) {
		updatedAccount.Account.PhotoURL = &user.PhotoURL
	}

	return &updatedAccount, nil
}

func (c *GoogleIAM) DeleteAccount(ctx context.Context, accountUID string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return err
	}

	err = client.DeleteUser(ctx, accountUID)
	if err != nil {
		return err
	}

	return nil
}

func (c *GoogleIAM) UpdateAccountPassword(
	ctx context.Context,
	accountUID string,
	request UpdatePasswordRequest,
) (*SignInResponse, error) {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return nil, err
	}

	account, err := c.GetAccount(ctx, accountUID)
	if err != nil {
		return nil, err
	}

	if _, err := c.SignIn(ctx, account.Email, request.CurrentPassword); err != nil {
		return nil, errors.New("an error occured while updating password")
	}

	params := (&auth.UserToUpdate{}).
		Password(request.NewPassword)

	_, err = client.UpdateUser(ctx, accountUID, params)
	if err != nil {
		return nil, err
	}

	signInResponse, err := c.SignIn(ctx, account.Email, request.NewPassword)
	if err != nil {
		signInErr := errors.New("password updated, please sign in again")
		return nil, signInErr
	}

	return signInResponse, nil
}

func (c *GoogleIAM) ResetPasswordLink(ctx context.Context, email string) (*string, error) {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return nil, err
	}

	actionLink, err := client.PasswordResetLink(ctx, email)
	if err != nil {
		return nil, err
	}

	return &actionLink, nil
}

func (c *GoogleIAM) Initiate(ctx context.Context, email string) error {
	exists, err := c.AccountExists(ctx, email)
	if err != nil {
		return err
	}

	if exists {
		return iam.IAMError{
			Message: "Account already exists",
			Code:    iam.AlreadyExists,
		}
	}

	return nil
}

func (c *GoogleIAM) VerifyToken(ctx context.Context, token string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return err
	}

	_, err = client.VerifyIDTokenAndCheckRevoked(ctx, token)
	if err != nil {
		return err
	}

	return nil
}

func (c *GoogleIAM) SignOut(ctx context.Context, accountUUID string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return err
	}

	err = client.RevokeRefreshTokens(ctx, accountUUID)
	if err != nil {
		return err
	}

	return nil
}

func (c *GoogleIAM) SignIn(ctx context.Context, email, password string) (*SignInResponse, error) {
	request := SignInRequest{
		Email:             email,
		Password:          password,
		ReturnSecureToken: true,
	}

	marshalledRequest, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var response SignInResponse
	url := fmt.Sprintf(signInLink, c.apiKey)
	err = iam.HttpPost(
		ctx,
		url,
		map[string][]string{
			"Content-Type": {string(iam.HTTPContentTypeAppJSON)},
		},
		strings.NewReader(string(marshalledRequest)),
		&response)

	return &response, err
}
