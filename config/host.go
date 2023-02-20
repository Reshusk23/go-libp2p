package config

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"

	"go.uber.org/fx"
)

type closableHost struct {
	*fx.App
	host.Host
}

func (h *closableHost) Close() error {
	_ = h.App.Stop(context.Background())
	return h.Host.Close()
}
