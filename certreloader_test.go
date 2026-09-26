package csbouncer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// writePair writes a self-signed client certificate with the given serial
// and its key to dir, and returns the PEM of the certificate.
func writePair(t *testing.T, dir string, serial int64) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "bouncer", OrganizationalUnit: []string{"bouncer-ou"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certPEM
}

func presentedSerial(t *testing.T, r *certReloader) int64 {
	t.Helper()

	cert, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	return leaf.SerialNumber.Int64()
}

func testReloader(t *testing.T, dir string) (*certReloader, *time.Time) {
	t.Helper()

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	clock := time.Now()
	r.now = func() time.Time { return clock }
	r.checkedAt = clock

	return r, &clock
}

func TestCertReloaderRefresh(t *testing.T) {
	tests := []struct {
		name        string
		change      func(t *testing.T, dir string)
		wait        time.Duration
		wantChanged bool
		want        int64
	}{
		{
			name:   "unchanged files keep the certificate",
			change: func(*testing.T, string) {},
			wait:   time.Minute,
			want:   1,
		},
		{
			name:        "renewed pair is picked up after the interval",
			change:      func(t *testing.T, dir string) { t.Helper(); writePair(t, dir, 2) },
			wait:        certReloadInterval,
			wantChanged: true,
			want:        2,
		},
		{
			name:   "renewed pair is not read again before the interval",
			change: func(t *testing.T, dir string) { t.Helper(); writePair(t, dir, 2) },
			wait:   certReloadInterval - time.Second,
			want:   1,
		},
		{
			name: "half-written renewal keeps the old certificate",
			change: func(t *testing.T, dir string) {
				t.Helper()
				certPEM := writePair(t, t.TempDir(), 3)
				if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wait: certReloadInterval,
			want: 1,
		},
		{
			name: "missing files keep the old certificate",
			change: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
					t.Fatal(err)
				}
			},
			wait: certReloadInterval,
			want: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writePair(t, dir, 1)

			r, clock := testReloader(t, dir)

			tc.change(t, dir)
			*clock = clock.Add(tc.wait)

			if got := r.refresh(); got != tc.wantChanged {
				t.Fatalf("refresh() = %v, want %v", got, tc.wantChanged)
			}

			if got := presentedSerial(t, r); got != tc.want {
				t.Fatalf("serial = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCertReloaderMissingFilesAtStart(t *testing.T) {
	dir := t.TempDir()

	if _, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), logrus.New()); err == nil {
		t.Fatal("expected an error for missing files")
	}
}

// TestCertReloadingTransportUsesRenewedCertificate sends two requests over
// one client to a server that requires a client certificate. The second
// request after a renewal must arrive with the new certificate, although the
// first connection is still alive.
func TestCertReloadingTransportUsesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)

	r, clock := testReloader(t, dir)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprint(w, req.TLS.PeerCertificates[0].SerialNumber.Int64())
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &certReloadingTransport{
		base: &http.Transport{TLSClientConfig: &tls.Config{
			GetClientCertificate: r.GetClientCertificate,
			InsecureSkipVerify:   true, //nolint:gosec // the test inspects the presented certificate, it does not trust the server
		}},
		reloader: r,
	}}

	serial := func() string {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		return string(body)
	}

	if got := serial(); got != "1" {
		t.Fatalf("first request presented serial %s, want 1", got)
	}

	writePair(t, dir, 2)
	*clock = clock.Add(certReloadInterval)

	if got := serial(); got != "2" {
		t.Fatalf("request after renewal presented serial %s, want 2", got)
	}
}

func TestCertReloaderWarnsOncePerError(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)

	logger, hook := logtest.NewNullLogger()

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), logger)
	if err != nil {
		t.Fatal(err)
	}

	clock := time.Now()
	r.now = func() time.Time { return clock }
	r.checkedAt = clock

	warnings := func() int {
		n := 0

		for _, e := range hook.AllEntries() {
			if e.Level == logrus.WarnLevel {
				n++
			}
		}

		return n
	}

	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}

	for range 5 {
		clock = clock.Add(certReloadInterval)
		r.refresh()
	}

	if got := warnings(); got != 1 {
		t.Fatalf("the same broken file was reported %d times, want 1", got)
	}

	// a key that does not match the certificate is a different error
	other := t.TempDir()
	writePair(t, other, 9)

	keyPEM, err := os.ReadFile(filepath.Join(other, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(certReloadInterval)
	r.refresh()

	if got := warnings(); got != 2 {
		t.Fatalf("a new error was not reported: %d warnings, want 2", got)
	}
}

// TestCertReloaderConcurrentRefresh refreshes from many goroutines while the
// files are renewed; run with -race. Exactly one of them loads the new
// certificate.
func TestCertReloaderConcurrentRefresh(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, 1)

	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), logrus.New())
	if err != nil {
		t.Fatal(err)
	}

	var clock atomic.Int64

	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	r.checkedAt = r.now()

	writePair(t, dir, 2)
	clock.Add(int64(certReloadInterval))

	var (
		wg      sync.WaitGroup
		changed atomic.Int32
	)

	for range 50 {
		wg.Go(func() {
			if r.refresh() {
				changed.Add(1)
			}

			if _, err := r.GetClientCertificate(nil); err != nil {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if got := changed.Load(); got != 1 {
		t.Fatalf("%d refreshes reported a change, want 1", got)
	}

	if got := presentedSerial(t, r); got != 2 {
		t.Fatalf("serial = %d, want 2", got)
	}
}
