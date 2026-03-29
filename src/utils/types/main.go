package types

import "encoding/json"

type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

var NoErrors = make([]Error, 0)

type ErrorResponse struct {
	Message string  `json:"message"`
	Errors  []Error `json:"errors"`
}

func EmitError(message string, errors []Error) []byte {
	data, err := json.Marshal(ErrorResponse{
		Message: message,
		Errors:  errors,
	})

	if err != nil {
		panic(err)
	}

	return data
}
