package utils

import (
	"fmt"

	"github.com/nats-io/nats.go"
)

var Nats *nats.Conn

func NatsConnect() {
	url := fmt.Sprintf("nats://%s:%d", Config.NATS.Host, Config.NATS.Port)

	var err error

	Nats, err = nats.Connect(url)
	if err != nil {
		panic(err)
	}
}
