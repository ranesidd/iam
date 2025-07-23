package googleiam

import (
	"time"
)

type Account struct {
	UID           string  `json:"uid,omitempty"`
	DisplayName   string  `json:"display_name,omitempty"`
	Email         string  `json:"email,omitempty"`
	Phone         *string `json:"phone,omitempty"`
	PhotoURL      *string `json:"photo_url,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
	Disabled      *bool   `json:"disabled,omitempty"`
}

type CreateAccountRequest struct {
	DisplayName string         `json:"display_name"`
	Email       string         `json:"email"`
	Password    string         `json:"password"`
	Phone       *string        `json:"phone,omitempty"`
	PhotoURL    *string        `json:"photo_url,omitempty"`
	Claims      map[string]any `json:"claims,omitempty"`
}

type CreateAccountResponse struct {
	Account Account `json:"account"`
}

type UpdateAccountRequest struct {
	DisplayName *string        `json:"display_name"`
	Claims      map[string]any `json:"claims,omitempty"`
}

type UpdateAccountResponse struct {
	Account Account `json:"account"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type ResetPasswordRequest struct {
	Email string `json:"email"`
}

type InitiateAccountRequest struct {
	Email string `json:"email"`
}

type SignInRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type SignInResponse struct {
	Kind         string `json:"kind"`
	LocalID      string `json:"localId"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
	IDToken      string `json:"idToken"`
	Registered   bool   `json:"registered"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
}

type SignOutRequest struct {
	UID string `json:"uid"`
}

type OTP struct {
	Email     string    `json:"email,omitempty"`
	Code      string    `json:"code,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
