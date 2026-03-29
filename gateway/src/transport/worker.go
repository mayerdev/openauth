package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Worker interface {
	Register(email, password string) (*TokenResult, error)
	Login(email, password string) (*LoginResult, error)
	TFAVerify(sessionID, code string) (*TokenResult, error)
	RefreshToken(refreshToken string) (*TokenResult, error)
	Verify(accessToken string) (*UserResult, error)
	Logout(accessToken string) error
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

func (w *WorkerClient) Register(email, password string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"email": email, "password": password})
	msg, err := w.nc.Request("auth.register", payload, w.timeout)
	if err != nil {
		return nil, fmt.Errorf("worker register: %w", err)
	}

	var result TokenResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return nil, fmt.Errorf("worker register decode: %w", err)
	}

	if result.AccessToken == "" {
		var e workerError
		json.Unmarshal(msg.Data, &e)
		if len(e.Errors) > 0 {
			return nil, &WorkerValidationError{Message: e.Message, Fields: e.Errors}
		}
		return nil, fmt.Errorf("%s", e.Message)
	}

	return &result, nil
}

func (w *WorkerClient) Login(email, password string) (*LoginResult, error) {
	payload, _ := json.Marshal(map[string]string{"email": email, "password": password})
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

func (w *WorkerClient) TFAVerify(sessionID, code string) (*TokenResult, error) {
	payload, _ := json.Marshal(map[string]string{"session_id": sessionID, "code": code})
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
