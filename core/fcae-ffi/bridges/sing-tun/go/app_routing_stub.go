//go:build fcae_sing_tun && !fcae_singbox

package main

import (
	"context"
	"fmt"
)

func mtunNewAppRouter(context.Context, []byte) (mtunAppRouter, error) {
	return nil, fmt.Errorf("sing-tun app routing requires embedded sing-box")
}
