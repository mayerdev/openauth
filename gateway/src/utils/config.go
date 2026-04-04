package utils

import (
	"errors"
	"os"

	"github.com/spf13/viper"
)

type Client struct {
	ID           string   `mapstructure:"id"`
	Secret       string   `mapstructure:"secret"`
	Name         string   `mapstructure:"name"`
	RedirectURIs []string `mapstructure:"redirect_uris"`
}

type OAuthProviderConfig struct {
	ClientID        string `mapstructure:"client_id"`
	ClientSecret    string `mapstructure:"client_secret"`
	RedirectURI     string `mapstructure:"redirect_uri"`
	LinkRedirectURI string `mapstructure:"link_redirect_uri"`
}

type ConfigFile struct {
	Server struct {
		Port int `mapstructure:"port"`
	} `mapstructure:"server"`

	NATS struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"nats"`

	Redis struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"redis"`

	JWT struct {
		AccessTokenTTL int `mapstructure:"access_token_ttl"`
	} `mapstructure:"jwt"`

	Clients []Client `mapstructure:"clients"`

	OAuthProviders map[string]OAuthProviderConfig `mapstructure:"oauth_providers"`

	Frontend struct {
		TFARedirectURI string `mapstructure:"tfa_redirect_uri"`
	} `mapstructure:"frontend"`

	Web3 struct {
		Domain string `mapstructure:"domain"`
		URI    string `mapstructure:"uri"`
	} `mapstructure:"web3"`
}

var Config ConfigFile

func LoadConfig() {
	viper.SetConfigFile("config.yaml")

	if err := viper.ReadInConfig(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
	}

	viper.SetDefault("server.port", 8080)
	viper.SetDefault("nats.host", "localhost")
	viper.SetDefault("nats.port", 4222)
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("jwt.access_token_ttl", 21600)

	viper.SetEnvPrefix("APP")
	viper.AutomaticEnv()

	if err := viper.Unmarshal(&Config); err != nil {
		panic(err)
	}
}

func FindOAuthProvider(name string) *OAuthProviderConfig {
	cfg, ok := Config.OAuthProviders[name]
	if !ok {
		return nil
	}

	return &cfg
}

func FindClient(id string) *Client {
	for i := range Config.Clients {
		if Config.Clients[i].ID == id {
			return &Config.Clients[i]
		}
	}

	return nil
}
