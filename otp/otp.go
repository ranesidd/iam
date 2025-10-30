package otp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type OTP struct {
	db *sql.DB
}

func New(db *sql.DB) *OTP {
	return &OTP{db: db}
}

func (c *OTP) Generate(ctx context.Context, email string, expirationHours int) (*OTPPayload, error) {
	uuidStr := uuid.NewString()
	expiresAt := time.Now().UTC().Add(time.Duration(expirationHours) * time.Hour)
	code := strings.ToUpper(uuidStr[:6])

	verificationCode := OTPPayload{
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

func (c *OTP) Validate(ctx context.Context, email, code string) error {
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

func (c *OTP) getVerificationCode(ctx context.Context, email string) (OTPPayload, error) {
	query := "SELECT email, code, expires_at FROM verification_codes where email = ?"

	row := c.db.QueryRowContext(ctx, query, email)

	var codes OTPPayload
	err := row.Scan(&codes.Email, &codes.Code, &codes.ExpiresAt)
	if err != nil {
		return OTPPayload{}, fmt.Errorf("error reading row: %v", err)
	}
	return codes, nil
}

func (o *OTP) insertVerificationCode(ctx context.Context, otp OTPPayload) error {
	// Delete existing code if any
	_, err := o.db.ExecContext(ctx, "DELETE FROM verification_codes WHERE email = ?", otp.Email)
	if err != nil {
		return fmt.Errorf("failed to delete existing code: %w", err)
	}

	// Insert new code
	_, err = o.db.ExecContext(ctx,
		"INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)",
		otp.Email, otp.Code, otp.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to insert verification code: %w", err)
	}

	return nil
}

func (c *OTP) deleteVerificationCode(ctx context.Context, email string) error {
	query := "DELETE FROM verification_codes WHERE email = ?"

	_, err := c.db.ExecContext(ctx, query, email)
	if err != nil {
		return fmt.Errorf("error deleting verification code: %v", err)
	}
	return nil
}
