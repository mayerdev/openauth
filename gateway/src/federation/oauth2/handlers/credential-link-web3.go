package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/services"
	"openauth/gateway/transport"
)

type CredentialLinkWeb3Handler struct {
	worker transport.Worker
	nonces *services.Web3NonceService
}

type web3LinkConsumeRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func NewCredentialLinkWeb3Handler(worker transport.Worker, nonces *services.Web3NonceService) *CredentialLinkWeb3Handler {
	return &CredentialLinkWeb3Handler{worker: worker, nonces: nonces}
}

func (h *CredentialLinkWeb3Handler) PostStart(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req struct {
		Address string `json:"address"`
	}

	if err := c.Bind().Body(&req); err != nil || req.Address == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "address is required"})
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	nonce := hex.EncodeToString(b)

	if err := h.nonces.StoreForLink(c.Context(), token, nonce, 5*time.Minute); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	message := buildSIWEMessage(req.Address, nonce)
	hash := hex.EncodeToString(ethcrypto.Keccak256([]byte(message)))

	return c.JSON(Web3StartResponse{Message: message, Hash: hash})
}

func (h *CredentialLinkWeb3Handler) PostConsume(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req web3LinkConsumeRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	nonce, err := h.nonces.ConsumeForLink(c.Context(), token)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "nonce expired or already used"})
	}

	address, err := recoverAddress(req.Message, req.Signature)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid signature"})
	}

	if !strings.Contains(req.Message, nonce) {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "nonce mismatch"})
	}

	result, err := h.worker.LinkWeb3(token, address, "", "")
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	if !result.Ok {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	return c.JSON(map[string]bool{"ok": true})
}
