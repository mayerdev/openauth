package utils

import (
	"github.com/spf13/viper"
)

type ConfigFile struct {
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		Database string `mapstructure:"database"`
		Schema   string `mapstructure:"schema"`
	} `mapstructure:"database"`

	Redis struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"redis"`

	NATS struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"nats"`

	JWT struct {
		Secret          string `mapstructure:"secret"`
		RefreshSecret   string `mapstructure:"refresh_secret"`
		AccessTokenTTL  int    `mapstructure:"access_token_ttl"`
		RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"`
	} `mapstructure:"jwt"`
}

var Config ConfigFile

func LoadConfig() {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	viper.AddConfigPath(".")

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.schema", "public")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "password")
	viper.SetDefault("database.database", "openauth")
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)

	viper.SetDefault("nats.host", "localhost")
	viper.SetDefault("nats.port", 4222)

	viper.SetDefault("jwt.access_token_ttl", 21600)
	viper.SetDefault("jwt.refresh_token_ttl", 604800)

	viper.SetEnvPrefix("OA")
	viper.AutomaticEnv()

	if err := viper.Unmarshal(&Config); err != nil {
		panic(err)
	}
}
