package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Worker interface {
	Register(method, identifier, password string) (*RegisterResult, error)
	Login(method, identifier, password, scope, authSessionID, ipAddress, userAgent string) (*LoginResult, error)
	TFAVerify(sessionID, code, scope, ipAddress, userAgent string) (*TokenResult, error)
	RefreshToken(refreshToken string) (*TokenResult, error)
	Verify(accessToken string) (*UserResult, error)
	OAuthMethod(provider, providerID, email, name, scope, authSessionID, ipAddress, userAgent string) (*LoginResult, error)
	Web3Method(address, scope, ipAddress, userAgent string) (*TokenResult, error)
	TotpStart(accessToken string, tfaSessionID, code string) (*TotpStartResult, error)
	TotpConfirm(accessToken, code string) (*TotpConfirmResult, error)
	TotpUnlink(accessToken string, tfaSessionID, code string) (*TotpUnlinkResult, error)
	TfaMethodGet(accessToken string) (string, error)
	TfaMethodSet(accessToken, method string) error
	CredentialVerify(sessionID, code, scope, ipAddress, userAgent string) (*TokenResult, error)
	CredentialVerifyResend(sessionID string) error
	ListRoles(userID string) ([]string, error)
	Logout(accessToken string) error
	GetAuthHistory(accessToken string, page, pageSize int) (*AuthHistoryResult, error)
	LinkEmailStart(accessToken, email, tfaSessionID, code string) (*CredentialLinkStartResult, error)
	LinkEmailConfirm(accessToken, verificationSessionID, code string) error
	LinkPhoneStart(accessToken, phone, tfaSessionID, code string) (*CredentialLinkStartResult, error)
	LinkPhoneConfirm(accessToken, verificationSessionID, code string) error
	LinkOAuth(accessToken, provider, providerID, email, name, tfaSessionID, code string) (*CredentialDirectResult, error)
	LinkWeb3(accessToken, address, tfaSessionID, code string) (*CredentialDirectResult, error)
	UnlinkDirect(accessToken, credentialID, tfaSessionID, code string) (*CredentialDirectResult, error)
	TfaResend(accessToken, tfaSessionID string) error
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
	TFARequired     bool   `json:"tfa_required"`
	TFASessionID    string `json:"tfa_session_id"`
	TFAMethod       string `json:"tfa_method"`
	ExpiresIn       int    `json:"expires_in"`
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

type TotpUnlinkResult struct {
	Ok           bool   `json:"ok"`
	TfaRequired  bool   `json:"tfa_required"`
	TfaSessionID string `json:"tfa_session_id"`
	TfaMethod    string `json:"tfa_method"`
	ExpiresIn    int    `json:"expires_in"`
}

type HistoryEntry struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Method    string `json:"method"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
	CreatedAt string `json:"created_at"`
}

type AuthHistoryResult struct {
	History  []HistoryEntry `json:"history"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

type CredentialLinkStartResult struct {
	TFARequired           bool   `json:"tfa_required,omitempty"`
	TFASessionID          string `json:"tfa_session_id,omitempty"`
	TFAMethod             string `json:"tfa_method,omitempty"`
	VerificationSessionID string `json:"verification_session_id,omitempty"`
	VerificationMethod    string `json:"verification_method,omitempty"`
	ExpiresIn             int    `json:"expires_in,omitempty"`
}

type CredentialDirectResult struct {
	TFARequired  bool   `json:"tfa_required,omitempty"`
	TFASessionID string `json:"tfa_session_id,omitempty"`
	TFAMethod    string `json:"tfa_method,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Ok           bool   `json:"ok,omitempty"`
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

func (w *WorkerClient) Login(method, identifier, password, scope, authSessionID, ipAddress, userAgent string) (*LoginResult, error) {
	m := map[string]string{
		"method": method, "password": password, "scope": scope, "auth_session_id": authSessionID,
		"ip_address": ipAddress, "user_agent": userAgent,
	}
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

func (w *WorkerClient) TFAVerify(sessionID, code, scope, ipAddress, userAgent string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"session_id": sessionID, "code": code, "scope": scope,
		"ip_address": ipAddress, "user_agent": userAgent,
	})
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

func (w *WorkerClient) OAuthMethod(provider, providerID, email, name, scope, authSessionID, ipAddress, userAgent string) (*LoginResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"provider":        provider,
		"provider_id":     providerID,
		"email":           email,
		"name":            name,
		"scope":           scope,
		"auth_session_id": authSessionID,
		"ip_address":      ipAddress,
		"user_agent":      userAgent,
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

func (w *WorkerClient) Web3Method(address, scope, ipAddress, userAgent string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"address": address, "scope": scope,
		"ip_address": ipAddress, "user_agent": userAgent,
	})
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

func (w *WorkerClient) TotpStart(accessToken, tfaSessionID, code string) (*TotpStartResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})
	msg, err := w.nc.Request("auth.totp.start", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker totp.start: %w", err)
	}

	var result TotpStartResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker totp.start decode: %w", err)
	}

	if result.ProvisioningURI == "" && !result.TFARequired {
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

func (w *WorkerClient) TotpUnlink(accessToken, tfaSessionID, code string) (*TotpUnlinkResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})
	msg, err := w.nc.Request("auth.totp.unlink", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker totp.unlink: %w", err)
	}

	var res TotpUnlinkResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return nil, fmt.Errorf("worker totp.unlink decode: %w", err)
	}

	if !res.Ok && !res.TfaRequired {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &res, nil
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

func (w *WorkerClient) CredentialVerify(sessionID, code, scope, ipAddress, userAgent string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"session_id": sessionID, "code": code, "scope": scope,
		"ip_address": ipAddress, "user_agent": userAgent,
	})
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

func (w *WorkerClient) linkStart(subject, accessToken, field, value, tfaSessionID, code string) (*CredentialLinkStartResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		field:            value,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})
	msg, err := w.nc.Request(subject, payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker %s: %w", subject, err)
	}

	var result CredentialLinkStartResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker %s decode: %w", subject, err)
	}

	if result.VerificationSessionID == "" && !result.TFARequired {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) linkConfirm(subject, accessToken, sessionID, code string) error {
	payload, _ := json.Marshal(map[string]string{
		"access_token":            accessToken,
		"verification_session_id": sessionID,
		"code":                    code,
	})
	msg, err := w.nc.Request(subject, payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker %s: %w", subject, err)
	}

	var result struct {
		Ok      bool   `json:"ok"`
		Message string `json:"message"`
	}
	json.Unmarshal(msg.Data, &result)
	if !result.Ok {
		return fmt.Errorf("%s", result.Message)
	}

	return nil
}

func (w *WorkerClient) credentialDirect(subject string, payload []byte) (*CredentialDirectResult, error) {
	msg, err := w.nc.Request(subject, payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker %s: %w", subject, err)
	}

	var result CredentialDirectResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker %s decode: %w", subject, err)
	}

	if !result.Ok && !result.TFARequired {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) LinkEmailStart(accessToken, email, tfaSessionID, code string) (*CredentialLinkStartResult, error) {
	return w.linkStart("auth.credential.link.email.start", accessToken, "email", email, tfaSessionID, code)
}

func (w *WorkerClient) LinkEmailConfirm(accessToken, verificationSessionID, code string) error {
	return w.linkConfirm("auth.credential.link.email.confirm", accessToken, verificationSessionID, code)
}

func (w *WorkerClient) LinkPhoneStart(accessToken, phone, tfaSessionID, code string) (*CredentialLinkStartResult, error) {
	return w.linkStart("auth.credential.link.phone.start", accessToken, "phone", phone, tfaSessionID, code)
}

func (w *WorkerClient) LinkPhoneConfirm(accessToken, verificationSessionID, code string) error {
	return w.linkConfirm("auth.credential.link.phone.confirm", accessToken, verificationSessionID, code)
}

func (w *WorkerClient) LinkOAuth(accessToken, provider, providerID, email, name, tfaSessionID, code string) (*CredentialDirectResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		"provider":       provider,
		"provider_id":    providerID,
		"email":          email,
		"name":           name,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})

	return w.credentialDirect("auth.credential.link.oauth", payload)
}

func (w *WorkerClient) LinkWeb3(accessToken, address, tfaSessionID, code string) (*CredentialDirectResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		"address":        address,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})

	return w.credentialDirect("auth.credential.link.web3", payload)
}

func (w *WorkerClient) UnlinkDirect(accessToken, credentialID, tfaSessionID, code string) (*CredentialDirectResult, error) {
	payload, _ := json.Marshal(map[string]string{
		"access_token":   accessToken,
		"credential_id":  credentialID,
		"tfa_session_id": tfaSessionID,
		"code":           code,
	})

	return w.credentialDirect("auth.credential.unlink", payload)
}

func (w *WorkerClient) TfaResend(accessToken, tfaSessionID string) error {
	payload, _ := json.Marshal(map[string]string{"access_token": accessToken, "tfa_session_id": tfaSessionID})
	msg, err := w.nc.Request("auth.tfa.resend", payload, w.timeout)
	if err != nil {
		return fmt.Errorf("worker tfa.resend: %w", err)
	}

	var result struct {
		Ok      bool   `json:"ok"`
		Message string `json:"message"`
	}
	json.Unmarshal(msg.Data, &result)
	if !result.Ok {
		return fmt.Errorf("%s", result.Message)
	}

	return nil
}

func (w *WorkerClient) GetAuthHistory(accessToken string, page, pageSize int) (*AuthHistoryResult, error) {
	payload, _ := json.Marshal(map[string]any{
		"access_token": accessToken,
		"page":         page,
		"page_size":    pageSize,
	})
	msg, err := w.nc.Request("auth.history.get", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker history.get: %w", err)
	}

	var result struct {
		AuthHistoryResult
		Message string `json:"message"`
	}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker history.get decode: %w", err)
	}

	if result.History == nil && result.Message != "" {
		return nil, fmt.Errorf("%s", result.Message)
	}

	if result.History == nil {
		result.History = []HistoryEntry{}
	}

	return &result.AuthHistoryResult, nil
}
