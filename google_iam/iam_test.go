package googleiam_test

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	firebase "firebase.google.com/go"
	"github.com/joho/godotenv"
	googleiam "github.com/ranesidd/iam/google_iam"
	"github.com/ranesidd/iam/internal"
	"github.com/stretchr/testify/assert"

	iampackage "github.com/ranesidd/iam"
)

func getIAMInstance() *googleiam.GoogleIAM {

	err := godotenv.Load("../.env")
	if err != nil {
		panic(err)
	}

	iam, err := googleiam.New()
	if err != nil {
		panic(err)
	}

	return iam
}

func getFirebaseInternalRef(iam *googleiam.GoogleIAM) *firebase.App {
	if iam == nil {
		return nil
	}

	rv := reflect.ValueOf(iam).Elem().FieldByName("app")
	if !rv.IsValid() || rv.IsNil() {
		return nil
	}

	// Use unsafe to access unexported field
	// Create a new reflect.Value that can be accessed
	unsafeRv := reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()

	// Convert the reflected value back to *firebase.App
	app, ok := unsafeRv.Interface().(*firebase.App)
	if !ok {
		return nil
	}

	return app
}

func TestAccountExists(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
		err      error
	}{
		{
			name:     "Account Exists",
			email:    "sidkool6@gmail.com",
			expected: true,
			err:      nil,
		},
		{
			name:     "Account Doesn't Exist",
			email:    "testemail@gmail.com",
			expected: false,
			err:      nil,
		},
		{
			name:     "Malformed email",
			email:    "testemail",
			expected: false,
			err: iampackage.IAMError{
				Message: "malformed email string: \"testemail\"",
				Code:    iampackage.ProviderErr,
			},
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := instance.AccountExists(context.Background(), test.email)

			assert.Equal(t, test.expected, res)
			assert.Equal(t, test.err, err)
		})
	}
}

func TestCreateAccount(t *testing.T) {
	tests := []struct {
		name     string
		request  googleiam.CreateAccountRequest
		expected *googleiam.CreateAccountResponse
		err      error
		cleanup  bool
	}{
		{
			name: "Valid Account Creation",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Test User",
				Email:       "testcreate@example.com",
				Password:    "testPassword123",
			},
			expected: &googleiam.CreateAccountResponse{
				Account: googleiam.Account{
					DisplayName:   "Test User",
					Email:         "testcreate@example.com",
					EmailVerified: internal.AnyToPtr(true),
					Disabled:      internal.AnyToPtr(false),
				},
			},
			err:     nil,
			cleanup: true,
		},
		{
			name: "Account Creation with Phone",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Test User Phone",
				Email:       "testphone@example.com",
				Password:    "testPassword123",
				Phone:       internal.AnyToPtr("+14254259999"),
			},
			expected: &googleiam.CreateAccountResponse{
				Account: googleiam.Account{
					DisplayName:   "Test User Phone",
					Email:         "testphone@example.com",
					Phone:         internal.AnyToPtr("+14254259999"),
					EmailVerified: internal.AnyToPtr(true),
					Disabled:      internal.AnyToPtr(false),
				},
			},
			err:     nil,
			cleanup: true,
		},
		{
			name: "Account Creation with Photo URL",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Test User Photo",
				Email:       "testphoto@example.com",
				Password:    "testPassword123",
				PhotoURL:    internal.AnyToPtr("https://example.com/photo.jpg"),
			},
			expected: &googleiam.CreateAccountResponse{
				Account: googleiam.Account{
					DisplayName:   "Test User Photo",
					Email:         "testphoto@example.com",
					PhotoURL:      internal.AnyToPtr("https://example.com/photo.jpg"),
					EmailVerified: internal.AnyToPtr(true),
					Disabled:      internal.AnyToPtr(false),
				},
			},
			err:     nil,
			cleanup: true,
		},
		{
			name: "Invalid Email Format",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Test User",
				Email:       "invalid-email",
				Password:    "testPassword123",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "malformed email string: \"invalid-email\"",
				Code:    iampackage.ProviderErr,
			},
		},
		{
			name: "Weak Password",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Test User",
				Email:       "testweak@example.com",
				Password:    "123",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "password must be a string at least 6 characters long",
				Code:    iampackage.WeakPasswordErr,
			},
		},
		{
			name: "Duplicate Email",
			request: googleiam.CreateAccountRequest{
				DisplayName: "Duplicate User",
				Email:       "sidkool6@gmail.com", // This email exists from AccountExists test
				Password:    "testPassword123",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "account already exists",
				Code:    iampackage.AlreadyExistsErr,
			},
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := instance.CreateAccount(context.Background(), test.request)

			if test.expected != nil {
				assert.NotNil(t, res)
				assert.Equal(t, test.expected.Account.DisplayName, res.Account.DisplayName)
				assert.Equal(t, test.expected.Account.Email, res.Account.Email)
				assert.Equal(t, test.expected.Account.EmailVerified, res.Account.EmailVerified)
				assert.Equal(t, test.expected.Account.Disabled, res.Account.Disabled)

				if test.expected.Account.Phone != nil {
					assert.Equal(t, test.expected.Account.Phone, res.Account.Phone)
				}

				if test.expected.Account.PhotoURL != nil {
					assert.Equal(t, test.expected.Account.PhotoURL, res.Account.PhotoURL)
				}

				// UUID should be generated
				assert.NotEmpty(t, res.Account.UID)
			} else {
				assert.Nil(t, res)
			}

			assert.Equal(t, test.err, err)

			if test.cleanup {
				app := getFirebaseInternalRef(instance)
				authClient, _ := app.Auth(context.Background())
				authClient.DeleteUser(context.Background(), res.Account.UID)
			}
		})
	}
}

func TestAccount(t *testing.T) {
	tests := []struct {
		name       string
		accountUID string
		expected   *googleiam.Account
		err        error
	}{
		{
			name:       "Valid Account Retrieval",
			accountUID: "qPrEGMfPojPELUL0QfVx1p0m6RL2",
			expected: &googleiam.Account{
				UID:           "qPrEGMfPojPELUL0QfVx1p0m6RL2",
				Email:         "sidkool6@gmail.com",
				EmailVerified: internal.AnyToPtr(true),
				Disabled:      internal.AnyToPtr(false),
			},
			err: nil,
		},
		{
			name:       "Account Not Found",
			accountUID: "nonexistent-uid-12345",
			expected:   nil,
			err: iampackage.IAMError{
				Message: "user not found",
				Code:    iampackage.NotFoundErr,
			},
		},
		{
			name:       "Empty Account UID",
			accountUID: "",
			expected:   nil,
			err: iampackage.IAMError{
				Message: "user not found",
				Code:    iampackage.NotFoundErr,
			},
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := instance.Account(context.Background(), test.accountUID)

			if test.expected != nil {
				assert.NotNil(t, res)
				assert.Equal(t, test.expected.UID, res.UID)
				assert.Equal(t, test.expected.Email, res.Email)
			} else {
				assert.Nil(t, res)
			}

			assert.Equal(t, test.err, err)
		})
	}
}

func TestUpdateAccount(t *testing.T) {
	tests := []struct {
		name       string
		accountUID string
		request    googleiam.UpdateAccountRequest
		expected   *googleiam.UpdateAccountResponse
		err        error
	}{
		{
			name:       "Valid Account Update",
			accountUID: "qPrEGMfPojPELUL0QfVx1p0m6RL2",
			request: googleiam.UpdateAccountRequest{
				DisplayName: "Updated Display Name",
			},
			expected: &googleiam.UpdateAccountResponse{
				Account: googleiam.Account{
					UID:           "qPrEGMfPojPELUL0QfVx1p0m6RL2",
					Email:         "sidkool6@gmail.com",
					DisplayName:   "Updated Display Name",
					EmailVerified: internal.AnyToPtr(false),
					Disabled:      internal.AnyToPtr(false),
				},
			},
			err: nil,
		},
		{
			name:       "Empty Display Name",
			accountUID: "qPrEGMfPojPELUL0QfVx1p0m6RL2",
			request: googleiam.UpdateAccountRequest{
				DisplayName: "",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "display name cannot be empty",
				Code:    iampackage.BadRequestErr,
			},
		},
		{
			name:       "Account Not Found",
			accountUID: "nonexistent-uid-12345",
			request: googleiam.UpdateAccountRequest{
				DisplayName: "Test Name",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "cannot find user with given UID",
				Code:    iampackage.NotFoundErr,
			},
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := instance.UpdateAccount(context.Background(), test.accountUID, test.request)

			if test.expected != nil {
				assert.NotNil(t, res)
				assert.Equal(t, test.expected.Account.UID, res.Account.UID)
				assert.Equal(t, test.expected.Account.Email, res.Account.Email)
				assert.Equal(t, test.expected.Account.DisplayName, res.Account.DisplayName)
				assert.Equal(t, test.expected.Account.EmailVerified, res.Account.EmailVerified)
				assert.Equal(t, test.expected.Account.Disabled, res.Account.Disabled)
			} else {
				assert.Nil(t, res)
			}

			assert.Equal(t, test.err, err)
		})
	}
}

func TestDeleteAccount(t *testing.T) {
	tests := []struct {
		name       string
		accountUID string
		err        error
		setup      bool
		cleanup    bool
	}{
		{
			name:       "Valid Account Deletion",
			accountUID: "",
			err:        nil,
			setup:      true,
			cleanup:    false,
		},
		{
			name:       "Account Not Found",
			accountUID: "nonexistent-uid-12345",
			err: iampackage.IAMError{
				Message: "cannot find user with given UID",
				Code:    iampackage.NotFoundErr,
			},
			setup:   false,
			cleanup: false,
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testUID := test.accountUID

			if test.setup {
				createReq := googleiam.CreateAccountRequest{
					DisplayName: "Delete Test User",
					Email:       "deletetest@example.com",
					Password:    "testPassword123",
				}
				createRes, createErr := instance.CreateAccount(context.Background(), createReq)
				assert.NoError(t, createErr)
				assert.NotNil(t, createRes)
				testUID = createRes.Account.UID
			}

			err := instance.DeleteAccount(context.Background(), testUID)
			assert.Equal(t, test.err, err)

			if test.cleanup {
				app := getFirebaseInternalRef(instance)
				authClient, _ := app.Auth(context.Background())
				authClient.DeleteUser(context.Background(), testUID)
			}
		})
	}
}

func TestUpdateAccountPassword(t *testing.T) {
	tests := []struct {
		name       string
		accountUID string
		request    googleiam.UpdatePasswordRequest
		expected   *googleiam.SignInResponse
		err        error
		setup      bool
		cleanup    bool
	}{
		{
			name:       "Valid Password Update",
			accountUID: "",
			request: googleiam.UpdatePasswordRequest{
				CurrentPassword: "testPassword123",
				NewPassword:     "newPassword456",
			},
			expected: nil, // We'll check that SignInResponse is returned but not exact values
			err:      nil,
			setup:    true,
			cleanup:  true,
		},
		{
			name:       "Wrong Current Password",
			accountUID: "qPrEGMfPojPELUL0QfVx1p0m6RL2",
			request: googleiam.UpdatePasswordRequest{
				CurrentPassword: "wrongPassword",
				NewPassword:     "newPassword456",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "an error occured while updating the password",
				Code:    iampackage.BadRequestErr,
			},
			setup:   false,
			cleanup: false,
		},
		{
			name:       "Account Not Found",
			accountUID: "nonexistent-uid-12345",
			request: googleiam.UpdatePasswordRequest{
				CurrentPassword: "testPassword123",
				NewPassword:     "newPassword456",
			},
			expected: nil,
			err: iampackage.IAMError{
				Message: "user not found",
				Code:    iampackage.NotFoundErr,
			},
			setup:   false,
			cleanup: false,
		},
	}

	instance := getIAMInstance()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testUID := test.accountUID
			testEmail := ""

			if test.setup {
				createReq := googleiam.CreateAccountRequest{
					DisplayName: "Password Update Test User",
					Email:       "passwordtest@example.com",
					Password:    "testPassword123",
				}
				createRes, createErr := instance.CreateAccount(context.Background(), createReq)
				assert.NoError(t, createErr)
				assert.NotNil(t, createRes)
				testUID = createRes.Account.UID
				testEmail = createRes.Account.Email
			}

			res, err := instance.UpdateAccountPassword(context.Background(), testUID, test.request)

			if test.err == nil {
				assert.NoError(t, err)
				assert.NotNil(t, res)
				assert.NotEmpty(t, res.IDToken)
				assert.NotEmpty(t, res.RefreshToken)
				assert.Equal(t, testEmail, res.Email)
			} else {
				assert.Equal(t, test.err, err)
				assert.Nil(t, res)
			}

			if test.cleanup {
				app := getFirebaseInternalRef(instance)
				authClient, _ := app.Auth(context.Background())
				authClient.DeleteUser(context.Background(), testUID)
			}
		})
	}
}
