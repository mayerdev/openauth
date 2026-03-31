package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"openauth/gateway/transport"
	"openauth/gateway/utils"

	"github.com/gofiber/fiber/v3"
)

type IntrospectHandler struct {
	worker transport.Worker
}

func NewIntrospectHandler(worker transport.Worker) *IntrospectHandler {
	return &IntrospectHandler{worker: worker}
}

func (h *IntrospectHandler) PostIntrospect(c fiber.Ctx) error {
	var req IntrospectRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	if id, secret, ok := parseBasicAuth(c.Get("Authorization")); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	client := utils.FindClient(req.ClientID)
	if client == nil || client.Secret != req.ClientSecret {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_client"})
	}

	if req.Token == "" {
		return c.JSON(IntrospectResponse{Active: false})
	}

	user, err := h.worker.Verify(req.Token)
	if err != nil {
		return c.JSON(IntrospectResponse{Active: false})
	}

	exp, iat := jwtPayloadTimes(req.Token)

	username := ""
	for _, cred := range user.Credentials {
		if cred.Type == "email" && cred.Verified {
			username = cred.Value
			break
		}
	}

	roles, _ := h.worker.ListRoles(user.ID)
	tokenScope := jwtPayloadScope(req.Token)

	var creds []IntrospectCredential
	if strings.Contains(tokenScope, "credentials") {
		for _, c := range user.Credentials {
			creds = append(creds, IntrospectCredential{
				ID:       c.ID,
				Type:     c.Type,
				Value:    c.Value,
				Verified: c.Verified,
			})
		}
	}

	return c.JSON(IntrospectResponse{
		Active:      true,
		Sub:         user.ID,
		Username:    username,
		Roles:       roles,
		Credentials: creds,
		Scope:       tokenScope,
		TokenType:   "Bearer",
		Exp:         exp,
		Iat:         iat,
	})
}

func parseBasicAuth(header string) (id, secret string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

func jwtPayloadScope(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	return claims.Scope
}

func jwtPayloadTimes(token string) (exp, iat int64) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, 0
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, 0
	}

	var claims struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, 0
	}

	return claims.Exp, claims.Iat
}
