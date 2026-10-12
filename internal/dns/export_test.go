package dns

import (
	"context"
	"net"
)

// ListenWith is listen, for a test that injects a bind error through the
// socket options.
func ListenWith(ctx context.Context, config *net.ListenConfig, port int) (Sockets, error) {
	return listen(ctx, config, port)
}
