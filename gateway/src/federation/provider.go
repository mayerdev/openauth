package federation

import "github.com/gofiber/fiber/v3"

type Provider interface {
	Name() string
	Register(app *fiber.App)
}
