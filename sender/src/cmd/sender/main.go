package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"openauth/sender/internal/manager"
	"openauth/sender/internal/provider/email"
	"openauth/sender/internal/provider/sms"
)

type Config struct {
	Providers struct {
		Email string `yaml:"email"`
		SMS   string `yaml:"sms"`
	} `yaml:"providers"`

	Nats struct {
		URL string `yaml:"url"`
	} `yaml:"nats"`
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	natsURL := cfg.Nats.URL
	if envURL := os.Getenv("NATS_URL"); envURL != "" {
		natsURL = envURL
	}
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatal().Err(err).Msg("nats connect")
	}
	defer nc.Close()

	log.Info().Str("url", natsURL).Msg("connected to NATS")

	mgr := manager.NewProviderManager(nc)

	switch cfg.Providers.Email {
	case "dummy":
		mgr.Register(email.NewDummyProvider())
	default:
		log.Warn().Str("provider", cfg.Providers.Email).Msg("unknown email provider, skipping")
	}

	switch cfg.Providers.SMS {
	case "dummy":
		mgr.Register(sms.NewDummyProvider())
	default:
		log.Warn().Str("provider", cfg.Providers.SMS).Msg("unknown sms provider, skipping")
	}

	if err := mgr.Start(); err != nil {
		log.Fatal().Err(err).Msg("failed to start manager")
	}

	nc.Flush()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Info().Msg("shutting down sender service")
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return &cfg, nil
}
