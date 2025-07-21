package googleiam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"firebase.google.com/go/auth"
	"github.com/google/uuid"

	iam "github.com/ranesidd/iam"

	internal "github.com/ranesidd/iam/internal"
)

var (
	signInLink = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s"
)

func (c *GoogleIAM) AccountExists(ctx context.Context, email string) (bool, error) {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return false, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	_, err = client.GetUserByEmail(ctx, email)
	if err != nil {
		if strings.Contains(err.Error(), "cannot find user") {
			return false, nil
		}

		return false, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	return true, nil
}

func (c *GoogleIAM) CreateAccount(ctx context.Context, account CreateAccountRequest) (*CreateAccountResponse, error) {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	accountUID, err := uuid.NewV7()
	if err != nil {
		return nil, iam.IAMError{
			Message: "could not create unique id",
			Code:    iam.CouldNotGenerateErr,
		}
	}

	params := (&auth.UserToCreate{}).
		UID(accountUID.String()).
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

		if strings.Contains(err.Error(), "EMAIL_EXISTS") {
			return nil, iam.IAMError{
				Message: "account already exists",
				Code:    iam.AlreadyExistsErr,
			}
		}

		if strings.Contains(err.Error(), "password must be a string at least") {
			return nil, iam.IAMError{
				Message: err.Error(),
				Code:    iam.WeakPasswordErr,
			}
		}

		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	newAccount := CreateAccountResponse{
		Account: Account{
			UID:           user.UID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			EmailVerified: &user.EmailVerified,
			Disabled:      &user.Disabled,
		},
	}

	if !internal.IsEmpty(user.PhoneNumber) {
		newAccount.Account.Phone = &user.PhoneNumber
	}

	if !internal.IsEmpty(user.PhotoURL) {
		newAccount.Account.PhotoURL = &user.PhotoURL
	}

	return &newAccount, nil
}

func (c *GoogleIAM) Account(ctx context.Context, accountUID string) (*Account, error) {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	user, err := client.GetUser(ctx, accountUID)
	if err != nil {
		if strings.Contains(err.Error(), "cannot find user from uid") {
			return nil, iam.IAMError{
				Message: "user not found",
				Code:    iam.NotFoundErr,
			}
		}

		return nil, err
	}

	account := Account{
		UID:           user.UID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		EmailVerified: &user.EmailVerified,
		Disabled:      &user.Disabled,
	}

	if !internal.IsEmpty(user.PhoneNumber) {
		account.Phone = &user.PhoneNumber
	}

	if !internal.IsEmpty(user.PhotoURL) {
		account.PhotoURL = &user.PhotoURL
	}

	return &account, nil
}

func (c *GoogleIAM) UpdateAccount(ctx context.Context, accountUID string, account UpdateAccountRequest) (*UpdateAccountResponse, error) {
	if internal.IsEmpty(account.DisplayName) {
		return nil, iam.IAMError{
			Message: "display name cannot be empty",
			Code:    iam.BadRequestErr,
		}
	}

	client, err := c.app.Auth(ctx)
	if err != nil {
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	params := (&auth.UserToUpdate{}).
		DisplayName(account.DisplayName)

	user, err := client.UpdateUser(ctx, accountUID, params)
	if err != nil {
		if strings.Contains(err.Error(), "USER_NOT_FOUND") {
			return nil, iam.IAMError{
				Message: "cannot find user with given UID",
				Code:    iam.NotFoundErr,
			}
		}

		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	updatedAccount := UpdateAccountResponse{
		Account: Account{
			UID:           user.UID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			EmailVerified: &user.EmailVerified,
			Disabled:      &user.Disabled,
		},
	}

	if !internal.IsEmpty(user.PhoneNumber) {
		updatedAccount.Account.Phone = &user.PhoneNumber
	}

	if !internal.IsEmpty(user.PhotoURL) {
		updatedAccount.Account.PhotoURL = &user.PhotoURL
	}

	return &updatedAccount, nil
}

func (c *GoogleIAM) DeleteAccount(ctx context.Context, accountUID string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	err = client.DeleteUser(ctx, accountUID)
	if err != nil {
		if strings.Contains(err.Error(), "USER_NOT_FOUND") {
			return iam.IAMError{
				Message: "cannot find user with given UID",
				Code:    iam.NotFoundErr,
			}
		}

		return iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
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
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	account, err := c.Account(ctx, accountUID)
	if err != nil {
		return nil, err
	}

	if _, err := c.SignIn(ctx, account.Email, request.CurrentPassword); err != nil {
		return nil, iam.IAMError{
			Message: "an error occured while updating the password",
			Code:    iam.BadRequestErr,
		}
	}

	params := (&auth.UserToUpdate{}).
		Password(request.NewPassword)

	_, err = client.UpdateUser(ctx, account.UID, params)
	if err != nil {
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	signInResponse, err := c.SignIn(ctx, account.Email, request.NewPassword)
	if err != nil {
		return nil, iam.IAMError{
			Message: "please sign in again",
			Code:    iam.UnknownErr,
		}
	}

	return signInResponse, nil
}

func (c *GoogleIAM) VerifyAccessToken(ctx context.Context, token string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	_, err = client.VerifyIDTokenAndCheckRevoked(ctx, token)
	if err != nil {
		return iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	return nil
}

func (c *GoogleIAM) SignOut(ctx context.Context, accountUID string) error {
	client, err := c.app.Auth(ctx)
	if err != nil {
		return iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	err = client.RevokeRefreshTokens(ctx, accountUID)
	if err != nil {
		return iam.IAMError{
			Message: "unable to logout",
			Code:    iam.ProviderErr,
		}
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
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.UnknownErr,
		}
	}

	var response SignInResponse
	url := fmt.Sprintf(signInLink, c.apiKey)
	err = internal.HttpPost(
		ctx,
		url,
		map[string][]string{
			"Content-Type": {string(internal.HTTPContentTypeAppJSON)},
		},
		strings.NewReader(string(marshalledRequest)),
		&response)

	if err != nil {
		return nil, iam.IAMError{
			Message: err.Error(),
			Code:    iam.ProviderErr,
		}
	}

	return &response, nil
}
