//go:build unix

package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchDrainSignal toggles maintenance mode on SIGUSR1.
//
// A signal rather than an API call, because the thing that sends it is a
// root shell mid-upgrade with no session cookie: `systemctl kill -s USR1
// bkd`, then poll /healthz until open_terminals reaches zero.
func (s *Server) watchDrainSignal(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				next := !s.terminals.Draining()
				s.terminals.SetDraining(next)
				s.log.Info("drain mode toggled", "draining", next,
					"open_terminals", s.terminals.OpenCount())
			}
		}
	}()
}

