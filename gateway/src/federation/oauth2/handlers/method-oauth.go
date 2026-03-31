package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var providerEndpoints = map[string]oauth2.Endpoint{
	"google": google.Endpoint,
	"github": github.Endpoint,
}

var providerUserInfoURLs = map[string]string{
	"google": "https://www.googleapis.com/oauth2/v2/userinfo",
	"github": "https://api.github.com/user",
}

type providerUserInfo struct {
	ID    string `json:"id"`
	Sub   string `json:"sub"` // Google uses "sub"
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"` // GitHub uses "login" as name
}

func (u *providerUserInfo) id() string {
	if u.Sub != "" {
		return u.Sub
	}

	if u.ID != "" {
		return u.ID
	}

	return ""
}

func (u *providerUserInfo) name() string {
	if u.Name != "" {
		return u.Name
	}

	return u.Login
}

type OAuthMethodHandler struct {
	sessions    AuthSessionRepo
	oauthStates *services.OAuthStateService
	worker      transport.Worker
	codes       AuthCodeRepo
}

func NewOAuthMethodHandler(
	sessions AuthSessionRepo,
	oauthStates *services.OAuthStateService,
	worker transport.Worker,
	codes AuthCodeRepo,
) *OAuthMethodHandler {
	return &OAuthMethodHandler{
		sessions:    sessions,
		oauthStates: oauthStates,
		worker:      worker,
		codes:       codes,
	}
}

func (h *OAuthMethodHandler) PostStart(c fiber.Ctx) error {
	provider := c.Params("provider")

	providerCfg := utils.FindOAuthProvider(provider)
	if providerCfg == nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "unknown provider"})
	}

	endpoint, ok := providerEndpoints[provider]
	if !ok {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "unsupported provider"})
	}

	var req OAuthStartRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	if _, err := h.sessions.Get(c.Context(), req.AuthSessionID); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	codeVerifier := hex.EncodeToString(b)

	state, err := h.oauthStates.Store(c.Context(), services.OAuthState{
		AuthSessionID: req.AuthSessionID,
		CodeVerifier:  codeVerifier,
	}, 10*time.Minute)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	oauthConfig := &oauth2.Config{
		ClientID:     providerCfg.ClientID,
		ClientSecret: providerCfg.ClientSecret,
		RedirectURL:  providerCfg.RedirectURI,
		Endpoint:     endpoint,
		Scopes:       providerScopes(provider),
	}

	authURL := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))

	return c.JSON(OAuthStartResponse{RedirectURL: authURL})
}

func (h *OAuthMethodHandler) GetCallback(c fiber.Ctx) error {
	provider := c.Params("provider")

	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "missing code or state"})
	}

	oauthState, err := h.oauthStates.Consume(c.Context(), state)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid or expired state"})
	}

	sess, err := h.sessions.Get(c.Context(), oauthState.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "auth session expired"})
	}

	providerCfg := utils.FindOAuthProvider(provider)
	endpoint := providerEndpoints[provider]

	oauthConfig := &oauth2.Config{
		ClientID:     providerCfg.ClientID,
		ClientSecret: providerCfg.ClientSecret,
		RedirectURL:  providerCfg.RedirectURI,
		Endpoint:     endpoint,
		Scopes:       providerScopes(provider),
	}

	token, err := oauthConfig.Exchange(context.Background(), code, oauth2.VerifierOption(oauthState.CodeVerifier))
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: "failed to exchange code"})
	}

	userInfo, err := fetchUserInfo(provider, token.AccessToken)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error", ErrorDescription: "failed to fetch user info"})
	}

	result, err := h.worker.OAuthMethod(provider, userInfo.id(), userInfo.Email, userInfo.name(), sess.Scope)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_credentials", ErrorDescription: err.Error()})
	}

	if result.TFARequired {
		redirectURL := fmt.Sprintf("%s?tfa_session_id=%s&auth_session_id=%s&tfa_method=%s",
			utils.Config.Frontend.TFARedirectURI,
			result.TFASessionID,
			oauthState.AuthSessionID,
			result.TFAMethod,
		)

		return c.Redirect().To(redirectURL)
	}

	authCode, err := h.codes.Create(c.Context(), services.AuthCodeEntry{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		Scope:        sess.Scope,
		ClientID:     sess.ClientID,
		RedirectURI:  sess.RedirectURI,
	}, 10*time.Minute)

	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	h.sessions.Delete(c.Context(), oauthState.AuthSessionID)

	return c.Redirect().To(buildRedirectURL(sess.RedirectURI, authCode, sess.State))
}

func fetchUserInfo(provider, accessToken string) (*providerUserInfo, error) {
	url, ok := providerUserInfoURLs[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info providerUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func providerScopes(provider string) []string {
	switch provider {
	case "google":
		return []string{"openid", "email", "profile"}
	case "github":
		return []string{"user:email", "read:user"}
	default:
		return []string{"openid", "email"}
	}
}
