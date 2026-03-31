package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"
)

type Web3MethodHandler struct {
	sessions AuthSessionRepo
	nonces   *services.Web3NonceService
	worker   transport.Worker
	codes    AuthCodeRepo
}

func NewWeb3MethodHandler(
	sessions AuthSessionRepo,
	nonces *services.Web3NonceService,
	worker transport.Worker,
	codes AuthCodeRepo,
) *Web3MethodHandler {
	return &Web3MethodHandler{
		sessions: sessions,
		nonces:   nonces,
		worker:   worker,
		codes:    codes,
	}
}

func (h *Web3MethodHandler) PostStart(c fiber.Ctx) error {
	var req Web3StartRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	if _, err := h.sessions.Get(c.Context(), req.AuthSessionID); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	nonce := hex.EncodeToString(b)

	if err := h.nonces.Store(c.Context(), req.AuthSessionID, nonce, 5*time.Minute); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	message := buildSIWEMessage(req.Address, nonce)
	hash := hex.EncodeToString(ethcrypto.Keccak256([]byte(message)))

	return c.JSON(Web3StartResponse{Message: message, Hash: hash})
}

func (h *Web3MethodHandler) PostConsume(c fiber.Ctx) error {
	var req Web3ConsumeRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	sess, err := h.sessions.Get(c.Context(), req.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	nonce, err := h.nonces.Consume(c.Context(), req.AuthSessionID)
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

	result, err := h.worker.Web3Method(address, sess.Scope)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_credentials", ErrorDescription: err.Error()})
	}

	return issueCodeAndRedirect(c, h.sessions, h.codes, sess, req.AuthSessionID, result.AccessToken, result.RefreshToken)
}

func buildSIWEMessage(address, nonce string) string {
	domain := utils.Config.Web3.Domain
	uri := utils.Config.Web3.URI
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	return fmt.Sprintf(
		"%s wants you to sign in with your Ethereum account:\n%s\n\nSign in with Ethereum.\n\nURI: %s\nVersion: 1\nChain ID: 1\nNonce: %s\nIssued At: %s",
		domain, address, uri, nonce, issuedAt,
	)
}

func recoverAddress(message, sigHex string) (string, error) {
	sig := common.FromHex(sigHex)
	if len(sig) != 65 {
		return "", fmt.Errorf("invalid signature length")
	}

	if sig[64] >= 27 {
		sig[64] -= 27
	}

	msgHash := accounts.TextHash([]byte(message))
	pubKey, err := ethcrypto.SigToPub(msgHash, sig)
	if err != nil {
		return "", err
	}

	return strings.ToLower(ethcrypto.PubkeyToAddress(*pubKey).Hex()), nil
}
