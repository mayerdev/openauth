package handlers

type OAuthStartRequest struct {
	AuthSessionID string `json:"auth_session_id"`
}

type OAuthStartResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type Web3StartRequest struct {
	AuthSessionID string `json:"auth_session_id"`
	Address       string `json:"address"`
}

type Web3StartResponse struct {
	Message string `json:"message"`
	Hash    string `json:"hash"`
}

type Web3ConsumeRequest struct {
	AuthSessionID string `json:"auth_session_id"`
	Message       string `json:"message"`
	Signature     string `json:"signature"`
}
