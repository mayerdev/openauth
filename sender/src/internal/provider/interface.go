package provider

type Provider interface {
	Send(to, code string) error
	Type() string
	ID() string
}
