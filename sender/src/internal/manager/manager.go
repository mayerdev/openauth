package manager

import (
	"encoding/json"
	"fmt"
	"openauth/sender/internal/provider"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

type ProviderManager struct {
	nc        *nats.Conn
	providers map[string]provider.Provider
}

func NewProviderManager(nc *nats.Conn) *ProviderManager {
	return &ProviderManager{
		nc:        nc,
		providers: make(map[string]provider.Provider),
	}
}

func (m *ProviderManager) Register(p provider.Provider) {
	m.providers[p.Type()] = p
}

func (m *ProviderManager) Start() error {
	for pType, p := range m.providers {
		subject := fmt.Sprintf("openauth.sender.%s", pType)

		_, err := m.nc.QueueSubscribe(subject, "senders", m.handleMessage(p))
		if err != nil {
			return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
		}

		log.Info().Str("type", pType).Str("provider", p.ID()).Msg("provider registered and subscribed")
	}

	return nil
}

func (m *ProviderManager) handleMessage(p provider.Provider) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var payload struct {
			To   string `json:"to"`
			Code string `json:"code"`
		}

		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Error().Err(err).Str("type", p.Type()).Msg("failed to decode message")
			return
		}

		if err := p.Send(payload.To, payload.Code); err != nil {
			log.Error().Err(err).Str("type", p.Type()).Str("to", payload.To).Msg("failed to send")
			return
		}
	}
}
