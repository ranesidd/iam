package googleiam

import (
	"context"
	"errors"
	"os"

	firebase "firebase.google.com/go"
)

type GoogleIAM struct {
	app    *firebase.App
	apiKey string
}

func New() (*GoogleIAM, error) {
	app, err := initializeGoogleAdminSDK()
	if err != nil {
		return nil, err
	}

	apiKey := os.Getenv("GOOGLE_API_KEY")
	if len(apiKey) == 0 {
		return nil, errors.New("GOOGLE_API_KEY not found in environment")
	}

	return &GoogleIAM{
		app:    app,
		apiKey: apiKey,
	}, nil
}

func initializeGoogleAdminSDK() (*firebase.App, error) {
	projectID := os.Getenv("GOOGLE_PROJECT_ID")
	if len(projectID) == 0 {
		return nil, errors.New("GOOGLE_PROJECT_ID not found in environment")
	}

	config := &firebase.Config{
		ProjectID: projectID,
	}

	// Uses Application Default Credentials (ADC)
	application, err := firebase.NewApp(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return application, nil
}
