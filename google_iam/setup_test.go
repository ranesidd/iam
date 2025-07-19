package googleiam_test

import (
	"errors"
	"os"
	"testing"

	googleiam "github.com/ranesidd/iam/google_iam"
	"github.com/stretchr/testify/assert"
)

const (
	validEnv         = ".env"
	invalidApiKeyEnv = "invalid_api.env"
	invalidSDK       = "invalid_sdk.env"
)

type Env struct {
	googleSDKConfig string
	googleAPIKey    string
}

func TestNew(t *testing.T) {
	table := []struct {
		name        string
		envfile     string
		env         Env
		expectedErr error
	}{
		{
			name:    "Valid Environment",
			envfile: validEnv,
			env: Env{
				googleSDKConfig: "{}",
				googleAPIKey:    "api-key",
			},
			expectedErr: nil,
		},
		{
			name:    "Missing SDK Config",
			envfile: validEnv,
			env: Env{
				googleAPIKey: "api-key",
			},
			expectedErr: errors.New("GOOGLE_SDK_CONFIG not found in environment"),
		},
		{
			name:    "Missing API Key",
			envfile: validEnv,
			env: Env{
				googleSDKConfig: "{}",
			},
			expectedErr: errors.New("GOOGLE_API_KEY not found in environment"),
		},
	}

	for _, test := range table {

		t.Run(test.name, func(t *testing.T) {
			teardown := setupTest(t, test.env)
			defer teardown(t, test.env)

			_, err := googleiam.New()
			assert.Equal(t, err, test.expectedErr)
		})
	}
}

func TestNewWithOTP(t *testing.T) {

}

func setupTest(t *testing.T, env Env) func(t *testing.T, env Env) {

	// Set keys to tmp_* if already set in env
	// overwrite with keys for test
	googAPIKey := os.Getenv("GOOGLE_API_KEY")
	os.Setenv("tmp_GOOGLE_API_KEY", googAPIKey)

	googSDKConfig := os.Getenv("GOOGLE_SDK_CONFIG")
	os.Setenv("tmp_GOOGLE_SDK_CONFIG", googSDKConfig)

	os.Setenv("GOOGLE_API_KEY", env.googleAPIKey)
	os.Setenv("GOOGLE_SDK_CONFIG", env.googleSDKConfig)

	return func(t *testing.T, env Env) {
		// Reset keys back to original
		tmpgoogAPIKey := os.Getenv("tmp_GOOGLE_API_KEY")
		os.Setenv("GOOGLE_API_KEY", tmpgoogAPIKey)

		tmpgoogSDKConfig := os.Getenv("tmp_GOOGLE_SDK_CONFIG")
		os.Setenv("GOOGLE_SDK_CONFIG", tmpgoogSDKConfig)

		os.Unsetenv("tmp_GOOGLE_API_KEY")
		os.Unsetenv("tmp_GOOGLE_SDK_CONFIG")
	}
}
