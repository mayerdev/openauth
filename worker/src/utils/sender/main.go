package sender

import (
	"encoding/json"

	"github.com/nats-io/nats.go"
)

func SendCode(nc *nats.Conn, sendType, to, code string) {
	payload, _ := json.Marshal(map[string]string{"to": to, "code": code})
	_ = nc.Publish("openauth.sender."+sendType, payload)
}
