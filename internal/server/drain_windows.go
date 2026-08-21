//go:build !unix

package server

import "context"

// watchDrainSignal is a no-op where SIGUSR1 does not exist. The drain
// workflow is a production-server affair, and production is Linux; a
// Windows development build simply never drains by signal.
func (s *Server) watchDrainSignal(ctx context.Context) {}
