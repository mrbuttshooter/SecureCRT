package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// copyBufferSize matches the file transfer engine's, for the same reason: big
// enough that a fast link is not syscall-bound, small enough that a hundred
// idle connections are not holding megabytes between them.
const copyBufferSize = 64 * 1024

// accept serves a listening tunnel until its context ends.
func (m *Manager) accept(ctx context.Context, t *Tunnel, port int) {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			// A closed listener is how a tunnel shuts down, not a fault.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			m.log.Warn("accepting on a tunnel", "tunnel", t.ID, "error", err)
			t.fail(err)
			return
		}

		t.live.Add(1)
		go func() {
			defer t.live.Done()
			defer func() { _ = conn.Close() }()

			t.connections.Add(1)
			t.active.Add(1)
			defer t.active.Add(-1)
			t.touch()

			if err := m.serve(ctx, t, conn); err != nil && ctx.Err() == nil {
				m.log.Debug("a forwarded connection ended",
					"tunnel", t.ID, "kind", t.Kind, "error", err)
			}
		}()
	}
}

// serve handles one accepted connection.
func (m *Manager) serve(ctx context.Context, t *Tunnel, local net.Conn) error {
	host, port := t.Host, t.Port

	if t.Kind == KindSOCKS {
		var err error
		// SOCKS names its destination per connection, which is the whole
		// point of it: one tunnel reaches everything the far side can.
		host, port, err = socksHandshake(local)
		if err != nil {
			return err
		}
	}

	remote, err := t.conn.Client().Conn().DialContext(ctx, "tcp",
		net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if t.Kind == KindSOCKS {
			_ = socksReplyFailure(local)
		}
		return err
	}
	defer func() { _ = remote.Close() }()

	if t.Kind == KindSOCKS {
		if err := socksReplySuccess(local); err != nil {
			return err
		}
	}

	return pipe(ctx, t, local, remote)
}

// pipe copies in both directions until either end stops or the tunnel does.
func pipe(ctx context.Context, t *Tunnel, local, remote net.Conn) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		fail error
	)

	record := func(err error) {
		mu.Lock()
		if fail == nil && err != nil && !errors.Is(err, io.EOF) {
			fail = err
		}
		mu.Unlock()
	}

	// Closing both ends is what unblocks the copies. A context cancellation
	// cannot interrupt an io.Copy already inside a read, so cancellation is
	// expressed by closing the sockets underneath it.
	stop := context.AfterFunc(ctx, func() {
		_ = local.Close()
		_ = remote.Close()
	})
	defer stop()

	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := copyCounting(remote, local, t.bytesUp.Add)
		record(err)
		_ = n
		// Half-close rather than a full close: a client that has finished
		// sending still wants what comes back.
		if half, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = remote.Close()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := copyCounting(local, remote, t.bytesDown.Add)
		record(err)
		_ = n
		if half, ok := local.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = local.Close()
		}
	}()

	wg.Wait()
	t.touch()

	mu.Lock()
	defer mu.Unlock()
	return fail
}

// copyCounting is io.Copy with a running total, so a tunnel can report how
// much it has carried while it is still carrying it.
func copyCounting(dst io.Writer, src io.Reader, count func(int64) int64) (int64, error) {
	buf := make([]byte, copyBufferSize)
	var total int64

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			count(int64(written))
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

// deadline is how long a SOCKS handshake may take. A client that connects and
// then says nothing must not hold a slot indefinitely.
const socksHandshakeTimeout = 10 * time.Second
