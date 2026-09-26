package csbouncer

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// certReloadInterval bounds how often the certificate files are read again.
// Renewal happens hours before expiry, so a few seconds of delay cost nothing.
const certReloadInterval = 10 * time.Second

// certReloader presents the bouncer's client certificate and picks up a new
// one when the files change on disk, so short-lived certificates renewed in
// place (Kubernetes pod certificates, cert-manager Secrets) work without a
// restart. A restart matters for bouncers like the firewall bouncer, which
// remove their rules on exit.
type certReloader struct {
	certFile string
	keyFile  string
	interval time.Duration
	now      func() time.Time
	logger   logrus.FieldLogger

	mu          sync.Mutex
	cert        *tls.Certificate
	certPEM     []byte
	keyPEM      []byte
	checkedAt   time.Time
	lastWarning string
}

func newCertReloader(certFile, keyFile string, logger logrus.FieldLogger) (*certReloader, error) {
	r := &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: certReloadInterval,
		now:      time.Now,
		logger:   logger,
	}

	pair, err := r.read()
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(pair.cert, pair.key)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate '%s' and key '%s': %w", certFile, keyFile, err)
	}

	r.cert, r.certPEM, r.keyPEM, r.checkedAt = &cert, pair.cert, pair.key, r.now()

	return r, nil
}

type pemPair struct {
	cert []byte
	key  []byte
}

func (r *certReloader) read() (pemPair, error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return pemPair{}, fmt.Errorf("unable to read certificate '%s': %w", r.certFile, err)
	}

	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return pemPair{}, fmt.Errorf("unable to read key '%s': %w", r.keyFile, err)
	}

	return pemPair{cert: certPEM, key: keyPEM}, nil
}

// refresh re-reads the files if the interval has passed and reports whether
// a new certificate was loaded. The files are read without holding the lock,
// so handshakes on other connections are not held up by slow storage.
func (r *certReloader) refresh() bool {
	r.mu.Lock()

	now := r.now()
	if now.Sub(r.checkedAt) < r.interval {
		r.mu.Unlock()
		return false
	}

	// Claim this check before reading, so concurrent requests do not read
	// the files as well.
	r.checkedAt = now
	r.mu.Unlock()

	pair, err := r.read()

	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		r.warnOnce("keeping the current client certificate: %s", err)
		return false
	}

	if bytes.Equal(pair.cert, r.certPEM) && bytes.Equal(pair.key, r.keyPEM) {
		r.lastWarning = ""
		return false
	}

	// A pair that does not parse is usually one caught halfway through a
	// renewal (cert written, key not yet). Keep the old one and try again
	// after the interval.
	cert, err := tls.X509KeyPair(pair.cert, pair.key)
	if err != nil {
		r.warnOnce("keeping the current client certificate, the new pair does not load: %s", err)
		return false
	}

	r.logger.Infof("reloaded client certificate from '%s'", r.certFile)

	r.cert, r.certPEM, r.keyPEM, r.lastWarning = &cert, pair.cert, pair.key, ""

	return true
}

// warnOnce logs a warning unless it is the one logged last, so a file that
// stays broken does not repeat the same line every interval. Callers hold mu.
func (r *certReloader) warnOnce(format string, err error) {
	msg := fmt.Sprintf(format, err)
	if msg == r.lastWarning {
		return
	}

	r.lastWarning = msg
	r.logger.Warn(msg)
}

func (r *certReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.cert, nil
}

// certReloadingTransport checks for a renewed certificate before each
// request. The client certificate is only presented during the handshake, and
// the transport keeps connections alive, so a renewal alone would never reach
// the server: closing the idle connections forces the next request to
// handshake with the new certificate.
type certReloadingTransport struct {
	base     *http.Transport
	reloader *certReloader
}

func (t *certReloadingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.reloader.refresh() {
		t.base.CloseIdleConnections()
	}

	return t.base.RoundTrip(req)
}
