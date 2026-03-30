package auth

type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TfaRequiredResult struct {
	TfaRequired  bool   `json:"tfa_required"`
	TfaSessionID string `json:"tfa_session_id"`
	TfaMethod    string `json:"tfa_method"`
	ExpiresIn    int    `json:"expires_in"`
}

type VerificationRequiredResult struct {
	VerificationRequired  bool   `json:"verification_required"`
	VerificationSessionID string `json:"verification_session_id"`
	VerificationMethod    string `json:"verification_method"`
}
