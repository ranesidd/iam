package googleiam

type Account struct {
	UUID          string  `json:"uuid,omitempty"`
	DisplayName   string  `json:"display_name,omitempty"`
	Email         string  `json:"email,omitempty"`
	Phone         *string `json:"phone,omitempty"`
	PhotoURL      *string `json:"photo_url,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
	Disabled      *bool   `json:"disabled,omitempty"`
}

type CreateAccountRequest struct {
	DisplayName string  `json:"display_name"`
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	Phone       *string `json:"phone,omitempty"`
	PhotoURL    *string `json:"photo_url,omitempty"`
	TenantID    *string `json:"tenant_id,omitempty"`
}

type CreateAccountResponse struct {
	Account        Account        `json:"account"`
	SignInResponse SignInResponse `json:"sign_in_response"`
}

type UpdateAccountRequest struct {
	DisplayName string `json:"display_name"`
}

type UpdateAccountResponse struct {
	Account Account `json:"account"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string  `json:"current_password"`
	NewPassword     string  `json:"new_password"`
	TenantID        *string `json:"tenant_id,omitempty"`
}

type SignInRequest struct {
	Email             string  `json:"email"`
	Password          string  `json:"password"`
	ReturnSecureToken bool    `json:"returnSecureToken"`
	TenantID          *string `json:"tenantId,omitempty"`
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
	UUID string `json:"uuid"`
}

type CreateTenantRequest struct {
	DisplayName           string `json:"display_name"`
	AllowPasswordSignUp   *bool  `json:"allow_password_sign_up,omitempty"`
	EnableEmailLinkSignIn *bool  `json:"enable_email_link_sign_in,omitempty"`
}

type TenantInfo struct {
	ID                    string `json:"id"`
	DisplayName           string `json:"display_name"`
	AllowPasswordSignUp   bool   `json:"allow_password_sign_up"`
	EnableEmailLinkSignIn bool   `json:"enable_email_link_sign_in"`
}
