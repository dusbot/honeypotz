//go:build wireinject

package app

import (
	"github.com/dusbot/honeypotz/init_"
	"github.com/google/wire"
)

func NewApp() *app {
	wire.Build(
		AppSet,
		init_.InitQuery,
	)
	return new(app)
}
