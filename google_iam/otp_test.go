package googleiam_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	googleiam "github.com/ranesidd/iam/google_iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testHelper creates a GoogleIAM instance with a mock database
func newTestGoogleIAM(db *sql.DB) *googleiam.GoogleIAM {
	iam, err := googleiam.NewWithOTP(db)
	if err != nil {
		panic(err)
	}

	return iam
}

func TestGenerateOTP(t *testing.T) {

	env := Env{
		googleSDKConfig: "{}",
		googleAPIKey:    "api-key",
	}
	teardown := setupTest(t, env)
	defer teardown(t, env)

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
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?")).
					WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectError: false,
		},
		{
			name:  "database error during insert",
			email: "test@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?")).
					WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("database connection failed"))
			},
			expectError: true,
			errorMsg:    "error inserting verification code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			iam := newTestGoogleIAM(db)

			ctx := context.Background()
			otp, err := iam.GenerateOTP(ctx, tt.email)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, otp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, otp)
				assert.Equal(t, tt.email, otp.Email)
				assert.Len(t, otp.Code, 6)
				assert.True(t, otp.ExpiresAt.After(time.Now()))
				assert.True(t, otp.ExpiresAt.Before(time.Now().Add(25*time.Hour)))
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestValidateOTP(t *testing.T) {

	env := Env{
		googleSDKConfig: "{}",
		googleAPIKey:    "api-key",
	}
	teardown := setupTest(t, env)
	defer teardown(t, env)

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
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes where email = ?")).
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
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes where email = ?")).
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
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes where email = ?")).
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
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes where email = ?")).
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
				mock.ExpectQuery(regexp.QuoteMeta("SELECT email, code, expires_at FROM verification_codes where email = ?")).
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

			iam := newTestGoogleIAM(db)

			ctx := context.Background()
			err = iam.ValidateOTP(ctx, tt.email, tt.code)

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

	env := Env{
		googleSDKConfig: "{}",
		googleAPIKey:    "api-key",
	}
	teardown := setupTest(t, env)
	defer teardown(t, env)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?")).
		WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	iam := newTestGoogleIAM(db)

	ctx := context.Background()
	otp, err := iam.GenerateOTP(ctx, "test@example.com")

	require.NoError(t, err)
	require.NotNil(t, otp)

	assert.Len(t, otp.Code, 6)
	assert.Regexp(t, "^[A-Z0-9]{6}$", otp.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGenerateOTP_ExpirationTime(t *testing.T) {

	env := Env{
		googleSDKConfig: "{}",
		googleAPIKey:    "api-key",
	}
	teardown := setupTest(t, env)
	defer teardown(t, env)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?")).
		WithArgs("test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	iam := newTestGoogleIAM(db)

	ctx := context.Background()
	beforeGenerate := time.Now().UTC()
	otp, err := iam.GenerateOTP(ctx, "test@example.com")
	afterGenerate := time.Now().UTC()

	require.NoError(t, err)
	require.NotNil(t, otp)

	expectedMin := beforeGenerate.Add(googleiam.OTPExpiration * time.Hour)
	expectedMax := afterGenerate.Add(googleiam.OTPExpiration * time.Hour)

	assert.True(t, otp.ExpiresAt.After(expectedMin) || otp.ExpiresAt.Equal(expectedMin))
	assert.True(t, otp.ExpiresAt.Before(expectedMax) || otp.ExpiresAt.Equal(expectedMax))

	assert.NoError(t, mock.ExpectationsWereMet())
}
