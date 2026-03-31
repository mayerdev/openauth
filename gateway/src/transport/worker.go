package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Worker interface {
	Register(method, identifier, password string) (*RegisterResult, error)
	Login(method, identifier, password, scope string) (*LoginResult, error)
	TFAVerify(sessionID, code, scope string) (*TokenResult, error)
	RefreshToken(refreshToken string) (*TokenResult, error)
	Verify(accessToken string) (*UserResult, error)
	Logout(accessToken string) error
	OAuthMethod(provider, providerID, email, name, scope string) (*LoginResult, error)
	Web3Method(address, scope string) (*TokenResult, error)
	TotpStart(accessToken string) (*TotpStartResult, error)
	TotpConfirm(accessToken, code string) (*TotpConfirmResult, error)
	TotpUnlink(accessToken string) error
	TfaMethodGet(accessToken string) (string, error)
	TfaMethodSet(accessToken, method string) error
	CredentialVerify(sessionID, code, scope string) (*TokenResult, error)
	CredentialVerifyResend(sessionID string) error
	ListRoles(userID string) ([]string, error)
}

type RegisterResult struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	VerificationRequired  bool   `json:"verification_required"`
	VerificationSessionID string `json:"verification_session_id"`
	VerificationMethod    string `json:"verification_method"`
}

type TotpStartResult struct {
	ProvisioningURI string `json:"provisioning_uri"`
	Secret          string `json:"secret"`
}

type TotpConfirmResult struct {
	BackupCodes []string `json:"backup_codes"`
}

type LoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TFARequired  bool   `json:"tfa_required"`
	TFASessionID string `json:"tfa_session_id"`
	TFAMethod    string `json:"tfa_method"`
	ExpiresIn    int    `json:"expires_in"`
}

type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type CredentialResult struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
}

type UserResult struct {
	ID          string             `json:"id"`
	Status      string             `json:"status"`
	TfaMethod   string             `json:"tfa_method"`
	CreatedAt   string             `json:"created_at"`
	UpdatedAt   string             `json:"updated_at"`
	Credentials []CredentialResult `json:"credentials"`
}

type workerError struct {
	Message string             `json:"message"`
	Errors  []WorkerFieldError `json:"errors"`
}

type WorkerFieldError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type WorkerValidationError struct {
	Message string
	Fields  []WorkerFieldError
}

func (e *WorkerValidationError) Error() string { return e.Message }

type WorkerClient struct {
	nc      *nats.Conn
	timeout time.Duration
}

func NewWorkerClient(nc *nats.Conn, timeout time.Duration) *WorkerClient {
	return &WorkerClient{nc: nc, timeout: timeout}
}

func (w *WorkerClient) Register(method, identifier, password string) (*RegisterResult, error) {
	m := map[string]string{"method": method, "password": password}
	if method == "phone" {
		m["phone"] = identifier
	} else {
		m["email"] = identifier
	}
	payload, _ := json.Marshal(m)
	msg, err := w.nc.Request("auth.register", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker register: %w", err)
	}

	var result RegisterResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker register decode: %w", err)
	}

	if !result.VerificationRequired && result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		if len(e.Errors) > 0 {
			return nil, &WorkerValidationError{Message: e.Message, Fields: e.Errors}
		}
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) Login(method, identifier, password, scope string) (*LoginResult, error) {
	m := map[string]string{"method": method, "password": password, "scope": scope}
	if method == "phone" {
		m["phone"] = identifier
	} else {
		m["email"] = identifier
	}
	payload, _ := json.Marshal(m)
	msg, err := w.nc.Request("auth.login", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker login: %w", err)
	}

	var result LoginResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker login decode: %w", err)
	}

	if result.AccessToken == "" && !result.TFARequired {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) TFAVerify(sessionID, code, scope string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"session_id": sessionID, "code": code, "scope": scope})
	msg, err := w.nc.Request("auth.tfa.verify", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker tfa.verify: %w", err)
	}

	var result TokenResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker tfa.verify decode: %w", err)
	}

	if result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) RefreshToken(refreshToken string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	msg, err := w.nc.Request("auth.token.refresh", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker token.refresh: %w", err)
	}

	var result TokenResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker token.refresh decode: %w", err)
	}

	if result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) Verify(accessToken string) (*UserResult, error) {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	msg, err := w.nc.Request("auth.session.verify", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker session.verify: %w", err)
	}

	var result UserResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker session.verify decode: %w", err)
	}

	if result.ID == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) OAuthMethod(provider, providerID, email, name, scope string) (*LoginResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"provider":    provider,
		"provider_id": providerID,
		"email":       email,
		"name":        name,
		"scope":       scope,
	})

	msg, err := w.nc.Request("auth.method.oauth", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker method.oauth: %w", err)
	}

	var result LoginResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker method.oauth decode: %w", err)
	}

	if result.AccessToken == "" && !result.TFARequired {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) Web3Method(address, scope string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"address": address, "scope": scope})
	msg, err := w.nc.Request("auth.method.web3", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker method.web3: %w", err)
	}

	var result TokenResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker method.web3 decode: %w", err)
	}

	if result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) TotpStart(accessToken string) (*TotpStartResult, error) {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	msg, err := w.nc.Request("auth.totp.start", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker totp.start: %w", err)
	}

	var result TotpStartResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker totp.start decode: %w", err)
	}

	if result.ProvisioningURI == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) TotpConfirm(accessToken, code string) (*TotpConfirmResult, error) {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken, "code": code})
	msg, err := w.nc.Request("auth.totp.confirm", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker totp.confirm: %w", err)
	}

	var result TotpConfirmResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker totp.confirm decode: %w", err)
	}

	if result.BackupCodes == nil {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) TotpUnlink(accessToken string) error {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	msg, err := w.nc.Request("auth.totp.unlink", payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker totp.unlink: %w", err)
	}

	var e workerError
	json.Unmarshal(msg.Data, &e)
	if e.Message != "" {
		return fmt.Errorf("%s", e.Message)
	}

	return nil
}

func (w *WorkerClient) TfaMethodGet(accessToken string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	msg, err := w.nc.Request("auth.tfa.method.get", payload, w.timeout)
	if err != nil {
		return "", fmt.Errorf("worker tfa.method.get: %w", err)
	}

	var result struct {
		Method  string `json:"method"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return "", fmt.Errorf("worker tfa.method.get decode: %w", err)
	}

	if result.Method == "" {
		return "", fmt.Errorf("%s", result.Message)
	}

	return result.Method, nil
}

func (w *WorkerClient) TfaMethodSet(accessToken, method string) error {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken, "method": method})
	msg, err := w.nc.Request("auth.tfa.method.set", payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker tfa.method.set: %w", err)
	}

	var e workerError
	json.Unmarshal(msg.Data, &e)
	if e.Message != "" {
		return fmt.Errorf("%s", e.Message)
	}

	return nil
}

func (w *WorkerClient) CredentialVerify(sessionID, code, scope string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"session_id": sessionID, "code": code, "scope": scope})
	msg, err := w.nc.Request("auth.credential.verify", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker credential.verify: %w", err)
	}

	var result TokenResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker credential.verify decode: %w", err)
	}

	if result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) CredentialVerifyResend(sessionID string) error {
	payload, _ := json.Marshal(map[string]string{"session_id": sessionID})
	msg, err := w.nc.Request("auth.credential.verify.resend", payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker credential.verify.resend: %w", err)
	}

	var e workerError
	json.Unmarshal(msg.Data, &e)
	if e.Message != "" {
		return fmt.Errorf("%s", e.Message)
	}

	return nil
}

func (w *WorkerClient) ListRoles(userID string) ([]string, error) {
	payload, _ := json.Marshal(map[string]string{"user_id": userID})
	msg, err := w.nc.Request("auth.roles.list", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker roles.list: %w", err)
	}

	var result struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker roles.list decode: %w", err)
	}

	if result.Roles == nil {
		return []string{}, nil
	}

	return result.Roles, nil
}

func (w *WorkerClient) Logout(accessToken string) error {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken})
	msg, err := w.nc.Request("auth.logout", payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker logout: %w", err)
	}

	var e workerError
	if err := json.Unmarshal(msg.Data, &e); err != nil {
		return fmt.Errorf("worker logout decode: %w", err)
	}

	if e.Message != "" {
		return fmt.Errorf("%s", e.Message)
	}

	return nil
}
