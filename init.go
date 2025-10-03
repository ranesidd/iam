package iam

import (
	"database/sql"
	"os"
	"strings"

	googleiam "github.com/ranesidd/iam/google_iam"
)

type IAM struct {
	db        *sql.DB
	googleIAM *googleiam.GoogleIAM
}

func New() (*IAM, error) {

	iamInstance := &IAM{}

	gcpFlag := os.Getenv("PROVIDER_GCP")
	if len(gcpFlag) != 0 && strings.Contains(strings.ToLower(gcpFlag), "true") {
		googleIAM, err := googleiam.New()
		if err != nil {
			return nil, err
		}

		iamInstance.googleIAM = googleIAM
	}

	return iamInstance, nil
}

func NewWithDatabase(db *sql.DB) (*IAM, error) {
	iamInstance, err := New()
	if err != nil {
		return nil, err
	}

	iamInstance.db = db

	return iamInstance, nil
}
