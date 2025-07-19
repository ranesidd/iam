package googleiam

import (
	"context"
	"database/sql"
	"errors"
	"os"

	firebase "firebase.google.com/go"
	"google.golang.org/api/option"
)

type GoogleIAM struct {
	db     *sql.DB
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

func NewWithOTP(db *sql.DB) (*GoogleIAM, error) {
	iamInstance, err := New()
	if err != nil {
		return nil, err
	}

	iamInstance.db = db

	return iamInstance, nil
}

func initializeGoogleAdminSDK() (*firebase.App, error) {
	goolgeConfig := os.Getenv("GOOGLE_SDK_CONFIG")
	if len(goolgeConfig) == 0 {
		return nil, errors.New("GOOGLE_SDK_CONFIG not found in environment")
	}

	opt := option.WithCredentialsJSON([]byte(goolgeConfig))
	application, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, errors.New(err.Error())
	}

	return application, nil
}
