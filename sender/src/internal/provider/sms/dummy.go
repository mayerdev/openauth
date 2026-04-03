package sms

import (
	"github.com/rs/zerolog/log"
)

type DummyProvider struct{}

func NewDummyProvider() *DummyProvider {
	return &DummyProvider{}
}

func (p *DummyProvider) Send(to, code string) error {
	log.Info().Str("to", to).Str("code", code).Msg("sms (dummy)")
	return nil
}

func (p *DummyProvider) Type() string {
	return "sms"
}

func (p *DummyProvider) ID() string {
	return "dummy"
}
