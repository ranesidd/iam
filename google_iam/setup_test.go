package googleiam_test

import (
	"errors"
	"os"
	"testing"

	googleiam "github.com/ranesidd/iam/google_iam"
	"github.com/stretchr/testify/assert"
)

type Env struct {
	googleProjectID string
	googleAPIKey    string
}

func TestNew(t *testing.T) {
	table := []struct {
		name        string
		env         Env
		expectedErr error
	}{
		{
			name: "Valid Environment",
			env: Env{
				googleProjectID: "test-project-id",
				googleAPIKey:    "api-key",
			},
			expectedErr: nil,
		},
		{
			name: "Missing Project ID",
			env: Env{
				googleAPIKey: "api-key",
			},
			expectedErr: errors.New("GOOGLE_PROJECT_ID not found in environment"),
		},
		{
			name: "Missing API Key",
			env: Env{
				googleProjectID: "test-project-id",
			},
			expectedErr: errors.New("GOOGLE_API_KEY not found in environment"),
		},
	}

	for _, test := range table {
		t.Run(test.name, func(t *testing.T) {
			teardown := setupTest(t, test.env)
			defer teardown(t, test.env)

			_, err := googleiam.New()
			assert.Equal(t, test.expectedErr, err)
		})
	}
}

func setupTest(t *testing.T, env Env) func(t *testing.T, env Env) {
	// Save original environment variables
	origProjectID := os.Getenv("GOOGLE_PROJECT_ID")
	origAPIKey := os.Getenv("GOOGLE_API_KEY")

	// Set test environment variables
	os.Setenv("GOOGLE_PROJECT_ID", env.googleProjectID)
	os.Setenv("GOOGLE_API_KEY", env.googleAPIKey)

	// Return cleanup function
	return func(t *testing.T, env Env) {
		// Restore original environment variables
		if origProjectID != "" {
			os.Setenv("GOOGLE_PROJECT_ID", origProjectID)
		} else {
			os.Unsetenv("GOOGLE_PROJECT_ID")
		}

		if origAPIKey != "" {
			os.Setenv("GOOGLE_API_KEY", origAPIKey)
		} else {
			os.Unsetenv("GOOGLE_API_KEY")
		}
	}
}
