package otp_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/ranesidd/iam/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testHelper creates an OTP instance with a mock database
func newTestOTP(db *sql.DB) *otp.OTP {
	return otp.New(db)
}

func TestGenerateOTP(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		setupMock   func(mock sqlmock.Sqlmock)
		expectError bool
		errorMsg    string
	}{
		{
			name:  "successful OTP generation",
			email: "test@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Expect DELETE first (to remove any existing code)
				mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnResult(sqlmock.NewResult(0, 0))
				// Then expect INSERT (Squirrel generates SQL without spaces after commas)
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email,code,expires_at) VALUES (?,?,?)")).
					WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
		},
		{
			name:  "database error during delete",
			email: "test@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnError(errors.New("delete failed"))
			},
			expectError: true,
			errorMsg:    "failed to delete existing code",
		},
		{
			name:  "database error during insert",
			email: "test@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				// DELETE succeeds
				mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnResult(sqlmock.NewResult(0, 0))
				// INSERT fails (Squirrel generates SQL without spaces after commas)
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email,code,expires_at) VALUES (?,?,?)")).
					WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("database connection failed"))
			},
			expectError: true,
			errorMsg:    "failed to insert verification code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			otpService := newTestOTP(db)

			ctx := context.Background()
			otpPayload, err := otpService.Generate(ctx, tt.email, 24)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, otpPayload)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, otpPayload)
				assert.Equal(t, tt.email, otpPayload.Email)
				assert.Len(t, otpPayload.Code, 6)
				assert.True(t, otpPayload.ExpiresAt.After(time.Now()))
				assert.True(t, otpPayload.ExpiresAt.Before(time.Now().Add(25*time.Hour)))
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestValidateOTP(t *testing.T) {
	now := time.Now().UTC()
	validExpiry := now.Add(1 * time.Hour)
	expiredTime := now.Add(-1 * time.Hour)

	tests := []struct {
		name         string
		email        string
		code         string
		setupMock    func(mock sqlmock.Sqlmock)
		expectError  bool
		errorMsg     string
		expectDelete bool
	}{
		{
			name:  "successful OTP validation",
			email: "test@example.com",
			code:  "ABC123",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"email", "code", "expires_at"}).
					AddRow("test@example.com", "ABC123", validExpiry)
				// Squirrel generates SELECT with spaces after commas
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnRows(rows)
				mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError:  false,
			expectDelete: true,
		},
		{
			name:  "OTP not found in database",
			email: "test@example.com",
			code:  "ABC123",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Squirrel generates SELECT with spaces after commas
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnError(sql.ErrNoRows)
			},
			expectError:  true,
			errorMsg:     "error reading row",
			expectDelete: false,
		},
		{
			name:  "invalid verification code",
			email: "test@example.com",
			code:  "WRONG1",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"email", "code", "expires_at"}).
					AddRow("test@example.com", "ABC123", validExpiry)
				// Squirrel generates SELECT with spaces after commas
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnRows(rows)
			},
			expectError:  true,
			errorMsg:     "invalid verification code",
			expectDelete: false,
		},
		{
			name:  "expired verification code",
			email: "test@example.com",
			code:  "ABC123",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"email", "code", "expires_at"}).
					AddRow("test@example.com", "ABC123", expiredTime)
				// Squirrel generates SELECT with spaces after commas
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnRows(rows)
			},
			expectError:  true,
			errorMsg:     "invalid verification code",
			expectDelete: false,
		},
		{
			name:  "database error during delete",
			email: "test@example.com",
			code:  "ABC123",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"email", "code", "expires_at"}).
					AddRow("test@example.com", "ABC123", validExpiry)
				// Squirrel generates SELECT with spaces after commas
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnRows(rows)
				mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
					WithArgs("test@example.com").
					WillReturnError(errors.New("delete failed"))
			},
			expectError:  false,
			expectDelete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			otpService := newTestOTP(db)

			ctx := context.Background()
			err = otpService.Validate(ctx, tt.email, tt.code)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGenerateOTP_CodeFormat(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Expect DELETE first
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
		WithArgs("test@example.com").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Then expect INSERT (Squirrel generates SQL without spaces after commas)
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email,code,expires_at) VALUES (?,?,?)")).
		WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	otpService := newTestOTP(db)

	ctx := context.Background()
	otpPayload, err := otpService.Generate(ctx, "test@example.com", 24)

	require.NoError(t, err)
	require.NotNil(t, otpPayload)

	assert.Len(t, otpPayload.Code, 6)
	assert.Regexp(t, "^[A-Z0-9]{6}$", otpPayload.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGenerateOTP_ExpirationTime(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Expect DELETE first
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM verification_codes WHERE email = ?")).
		WithArgs("test@example.com").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Then expect INSERT (Squirrel generates SQL without spaces after commas)
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email,code,expires_at) VALUES (?,?,?)")).
		WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	otpService := newTestOTP(db)

	ctx := context.Background()
	beforeGenerate := time.Now().UTC()
	otpPayload, err := otpService.Generate(ctx, "test@example.com", 24)
	afterGenerate := time.Now().UTC()

	require.NoError(t, err)
	require.NotNil(t, otpPayload)

	expectedMin := beforeGenerate.Add(24 * time.Hour)
	expectedMax := afterGenerate.Add(24 * time.Hour)

	assert.True(t, otpPayload.ExpiresAt.After(expectedMin) || otpPayload.ExpiresAt.Equal(expectedMin))
	assert.True(t, otpPayload.ExpiresAt.Before(expectedMax) || otpPayload.ExpiresAt.Equal(expectedMax))

	assert.NoError(t, mock.ExpectationsWereMet())
}
