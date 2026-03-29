package handlers

type AuthorizeQueryParams struct {
	ClientID     string `query:"client_id"`
	RedirectURI  string `query:"redirect_uri"`
	ResponseType string `query:"response_type"`
	State        string `query:"state"`
	Scope        string `query:"scope"`
}

type RegisterRequest struct {
	AuthSessionID string `json:"auth_session_id"`
	Email         string `json:"email"`
	Password      string `json:"password"`
}

type LoginRequest struct {
	AuthSessionID string `json:"auth_session_id"`
	Email         string `json:"email"`
	Password      string `json:"password"`
}

type TFARequest struct {
	AuthSessionID string `json:"auth_session_id"`
	TFASessionID  string `json:"tfa_session_id"`
	Code          string `json:"code"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"    form:"grant_type"`
	Code         string `json:"code"          form:"code"`
	RedirectURI  string `json:"redirect_uri"  form:"redirect_uri"`
	ClientID     string `json:"client_id"     form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
}

type AuthorizeInitResponse struct {
	AuthSessionID string `json:"auth_session_id"`
	ClientName    string `json:"client_name"`
	Scope         string `json:"scope"`
}

type LoginSuccessResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type TFARequiredResponse struct {
	TFARequired  bool   `json:"tfa_required"`
	TFASessionID string `json:"tfa_session_id"`
	TFAMethod    string `json:"tfa_method"`
	ExpiresIn    int    `json:"expires_in"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

type FieldError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error            string       `json:"error"`
	ErrorDescription string       `json:"error_description,omitempty"`
	Errors           []FieldError `json:"errors,omitempty"`
}
