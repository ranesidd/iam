package googleiam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	OTPExpiration = 24
)

func (c *GoogleIAM) GenerateOTP(ctx context.Context, email string) (*OTP, error) {
	uuidStr := uuid.NewString()
	expiresAt := time.Now().UTC().Add(OTPExpiration * time.Hour)
	code := strings.ToUpper(uuidStr[:6])

	verificationCode := OTP{
		Email:     email,
		Code:      code,
		ExpiresAt: expiresAt,
	}

	err := c.insertVerificationCode(ctx, verificationCode)
	if err != nil {
		return nil, err
	}

	return &verificationCode, nil
}

func (c *GoogleIAM) ValidateOTP(ctx context.Context, email, code string) error {
	verificationCode, err := c.getVerificationCode(ctx, email)
	if err != nil {
		return err
	}

	if verificationCode.Code != code {
		return errors.New("invalid verification code")
	}

	if time.Now().UTC().After(verificationCode.ExpiresAt) {
		return errors.New("invalid verification code")
	}

	err = c.deleteVerificationCode(ctx, email)
	if err != nil {
		return nil
	}

	return nil
}

func (c *GoogleIAM) getVerificationCode(ctx context.Context, email string) (OTP, error) {
	query := "SELECT email, code, expires_at FROM verification_codes where email = ?"

	row := c.db.QueryRowContext(ctx, query, email)

	var codes OTP
	err := row.Scan(&codes.Email, &codes.Code, &codes.ExpiresAt)
	if err != nil {
		return OTP{}, fmt.Errorf("error reading row: %v", err)
	}
	return codes, nil
}

func (c *GoogleIAM) insertVerificationCode(ctx context.Context, code OTP) error {
	query := "INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?"

	_, err := c.db.ExecContext(ctx, query, code.Email, code.Code, code.ExpiresAt, code.Code, code.ExpiresAt)
	if err != nil {
		return fmt.Errorf("error inserting verification code: %v", err)
	}
	return nil
}

func (c *GoogleIAM) deleteVerificationCode(ctx context.Context, email string) error {
	query := "DELETE FROM verification_codes WHERE email = ?"

	_, err := c.db.ExecContext(ctx, query, email)
	if err != nil {
		return fmt.Errorf("error deleting verification code: %v", err)
	}
	return nil
}
