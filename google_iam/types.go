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

type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	ExpiresIn    string `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	UUID         string `json:"user_id"`
	ProjectID    string `json:"project_id"`
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

type DecodedToken struct {
	AuthTime int64                  `json:"auth_time"`
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	Expires  int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	Subject  string                 `json:"sub,omitempty"`
	UUID     string                 `json:"uuid,omitempty"`
	Claims   map[string]interface{} `json:"-"`
	Firebase FirebaseInfo           `json:"firebase"`
}

type FirebaseInfo struct {
	SignInProvider string                 `json:"sign_in_provider"`
	Tenant         string                 `json:"tenant"`
	Identities     map[string]interface{} `json:"identities"`
}
