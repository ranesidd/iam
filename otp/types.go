package otp

import "time"

type OTPPayload struct {
	Email     string    `json:"email,omitempty"`
	Code      string    `json:"code,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
