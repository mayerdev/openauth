package utils

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Database *gorm.DB

func DatabaseConnect() {
	connectionString := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable search_path=%s",
		Config.Database.Host,
		Config.Database.Port,
		Config.Database.User,
		Config.Database.Password,
		Config.Database.Name,
		Config.Database.Schema,
	)

	var err error

	Database, err = gorm.Open(postgres.Open(connectionString), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("Failed to connect PostgreSQL: %v", err))
	}

	log.Info().
		Str("host", Config.Database.Host).
		Int("port", Config.Database.Port).
		Str("db", Config.Database.Name).
		Str("schema", Config.Database.Schema).
		Msg("PostgreSQL connected")
}
