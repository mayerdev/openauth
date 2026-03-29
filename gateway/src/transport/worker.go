package transport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Worker interface {
	Login(email, password string) (*LoginResult, error)
	TFAVerify(sessionID, code string) (*TokenResult, error)
	RefreshToken(refreshToken string) (*TokenResult, error)
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

type workerError struct {
	Message string `json:"message"`
}

type WorkerClient struct {
	nc      *nats.Conn
	timeout time.Duration
}

func NewWorkerClient(nc *nats.Conn, timeout time.Duration) *WorkerClient {
	return &WorkerClient{nc: nc, timeout: timeout}
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
