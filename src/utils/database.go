package utils

import (
	"fmt"

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
		Config.Database.Database,
		Config.Database.Schema,
	)

	var err error

	Database, err = gorm.Open(postgres.Open(connectionString), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("Failed to connect PostgreSQL: %v", err))
	}
}
