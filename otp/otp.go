package otp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
)

type OTP struct {
	db                *sql.DB
	placeholderFormat sq.PlaceholderFormat
}

func New(db *sql.DB, driverName ...string) *OTP {
	inferredDriverName := extractDriverName(driverName...)
	placeholderFormat := placeholderFormatForDriver(inferredDriverName)
	return &OTP{
		db:                db,
		placeholderFormat: placeholderFormat,
	}
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
	query, args, err := sq.Select("email", "code", "expires_at").
		From("verification_codes").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(c.placeholderFormat).
		ToSql()
	if err != nil {
		return OTPPayload{}, fmt.Errorf("failed to build select query: %w", err)
	}

	row := c.db.QueryRowContext(ctx, query, args...)

	var codes OTPPayload
	err = row.Scan(&codes.Email, &codes.Code, &codes.ExpiresAt)
	if err != nil {
		return OTPPayload{}, fmt.Errorf("error reading row: %v", err)
	}
	return codes, nil
}

func (o *OTP) insertVerificationCode(ctx context.Context, otp OTPPayload) error {
	// Delete existing code if any
	deleteQuery, deleteArgs, err := sq.Delete("verification_codes").
		Where(sq.Eq{"email": otp.Email}).
		PlaceholderFormat(o.placeholderFormat).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build delete query: %w", err)
	}

	_, err = o.db.ExecContext(ctx, deleteQuery, deleteArgs...)
	if err != nil {
		return fmt.Errorf("failed to delete existing code: %w", err)
	}

	// Insert new code
	insertQuery, insertArgs, err := sq.Insert("verification_codes").
		Columns("email", "code", "expires_at").
		Values(otp.Email, otp.Code, otp.ExpiresAt).
		PlaceholderFormat(o.placeholderFormat).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build insert query: %w", err)
	}

	_, err = o.db.ExecContext(ctx, insertQuery, insertArgs...)
	if err != nil {
		return fmt.Errorf("failed to insert verification code: %w", err)
	}

	return nil
}

func (c *OTP) deleteVerificationCode(ctx context.Context, email string) error {
	query, args, err := sq.Delete("verification_codes").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(c.placeholderFormat).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build delete query: %w", err)
	}

	_, err = c.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("error deleting verification code: %v", err)
	}
	return nil
}

func extractDriverName(driverName ...string) string {
	var inferredDriverName string
	if len(driverName) > 0 {
		inferredDriverName = strings.ToLower(driverName[0])
	}
	return inferredDriverName
}

func placeholderFormatForDriver(driverName string) sq.PlaceholderFormat {
	switch driverName {
	case "postgres", "pgx", "pgx/v4", "pgx/v5":
		return sq.Dollar
	default:
		return sq.Question
	}
}
