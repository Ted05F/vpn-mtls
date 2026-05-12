// internal/tunnel/client.go — TUN interface client-side
package tunnel

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// TunClient manages the client-side TUN interface.
type TunClient struct {
	iface *water.Interface
	name  string
}

// NewClient creates a TUN interface with the given name.
func NewClient(name string) (*TunClient, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create TUN interface %s: %w", name, err)
	}
	logrus.WithField("iface", iface.Name()).Info("TUN client interface created")
	return &TunClient{iface: iface, name: iface.Name()}, nil
}

// Configure sets the IP address on the TUN interface once the server
// assigns one. Called after the mTLS handshake when the server sends
// the assigned IP in the control channel.
func (c *TunClient) Configure(assignedIP, subnet string) error {
	return configureInterface(c.name, assignedIP, subnet)
}

// Bridge copies packets between the TUN interface and the TLS connection.
// It blocks until the context is cancelled or an error occurs.
func (c *TunClient) Bridge(ctx context.Context, conn io.ReadWriter) error {
	var (
		bytesIn  int64
		bytesOut int64
	)

	errCh := make(chan error, 2)

	// TUN → TLS (outbound to server)
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}
			n, err := c.iface.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("TUN read: %w", err)
				return
			}
			if err := WriteFramed(conn, buf[:n]); err != nil {
				errCh <- fmt.Errorf("conn write: %w", err)
				return
			}
			atomic.AddInt64(&bytesOut, int64(n))
		}
	}()

	// TLS → TUN (inbound from server)
	go func() {
		buf := make([]byte, 65536)
		for {
			packet, err := ReadFramed(conn, buf)
			if err != nil {
				if err == io.EOF {
					errCh <- fmt.Errorf("server closed connection")
				} else {
					errCh <- fmt.Errorf("conn read: %w", err)
				}
				return
			}
			if _, err := c.iface.Write(packet); err != nil {
				errCh <- fmt.Errorf("TUN write: %w", err)
				return
			}
			atomic.AddInt64(&bytesIn, int64(len(packet)))
		}
	}()

	select {
	case <-ctx.Done():
		err := ctx.Err()
		logrus.WithFields(logrus.Fields{
			"bytes_in":  atomic.LoadInt64(&bytesIn),
			"bytes_out": atomic.LoadInt64(&bytesOut),
		}).Info("client bridge stopped (context)")
		return err
	case err := <-errCh:
		logrus.WithFields(logrus.Fields{
			"bytes_in":  atomic.LoadInt64(&bytesIn),
			"bytes_out": atomic.LoadInt64(&bytesOut),
		}).WithError(err).Info("client bridge stopped")
		return err
	}
}

// Close releases the TUN interface.
func (c *TunClient) Close() error {
	return c.iface.Close()
}
