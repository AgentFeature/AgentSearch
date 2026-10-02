package network

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// uTLSDialer supplies an experimental browser-like TLS handshake.
// It uses uTLS in place of the standard TLS dialer.
// Compatibility with all servers and proxy combinations is not guaranteed.
type uTLSDialer struct {
	netDialer *net.Dialer
	rootCAs   *x509.CertPool
}

// newUTLSDialer creates a dialer using the Chrome handshake profile.
func newUTLSDialer(timeout time.Duration) *uTLSDialer {
	return &uTLSDialer{
		netDialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialContext opens a connection and performs a cancellable uTLS handshake.
// The selected profile is HelloChrome_Auto.
func (d *uTLSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	plainConn, err := d.netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		plainConn.Close()
		return nil, err
	}
	// Configure verified TLS for the actual destination.
	cfg := &utls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
		RootCAs:            d.rootCAs,
		MinVersion:         utls.VersionTLS12,
	}

	uconn := utls.UClient(plainConn, cfg, utls.HelloChrome_Auto)
	// net/http cannot inspect a uTLS connection as a crypto/tls.Conn, so it
	// cannot switch this custom connection to HTTP/2. Advertise HTTP/1.1 only.
	if err := uconn.BuildHandshakeState(); err != nil {
		plainConn.Close()
		return nil, err
	}
	extensions := uconn.Extensions[:0]
	for _, extension := range uconn.Extensions {
		switch e := extension.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
		case *utls.ApplicationSettingsExtension:
			continue
		case *utls.ApplicationSettingsExtensionNew:
			continue
		}
		extensions = append(extensions, extension)
	}
	uconn.Extensions = extensions
	if err := uconn.HandshakeContext(ctx); err != nil {
		plainConn.Close()
		return nil, err
	}
	return uconn, nil
}

// EnableUTLS installs a uTLS dialer when enabled.
// Otherwise it leaves the transport unchanged.
func EnableUTLS(tr *http.Transport, useUTLS bool) {
	if !useUTLS {
		return
	}
	dialer := newUTLSDialer(5 * time.Second)
	if tr.TLSClientConfig != nil {
		dialer.rootCAs = tr.TLSClientConfig.RootCAs
	}
	tr.DialTLSContext = dialer.DialContext
}
