// Command tls-upstream is a tiny deterministic TLS 1.3 HTTPS server used
// as the upstream for this app's /quote and /echo routes in CI.
//
// It replaces the live public services the routes default to
// (api.github.com / httpbin.org). Those rate-limit and go down for
// minutes at a time, which makes keploy's run_sample_tls_pcap e2e flaky
// on shared CI runners. Pointing QUOTE_URL / ECHO_URL at this server
// instead removes that external dependency while still exercising a real
// outbound TLS 1.3 handshake through keploy's proxy.
//
// It answers every path with a 200 and a small JSON body that echoes the
// request line, so the decrypted-pcap assertions have a stable target.
// TLS 1.3 is forced so every session emits a CLIENT_TRAFFIC_SECRET_0
// keylog line (keploy's keylog assertion requires one).
//
// Usage: tls-upstream <cert.pem> <key.pem> <bind-host> <port>
//
// The cert must be signed by a CA the client trusts (in CI, the same CA
// that's installed into the OS trust store) and carry SANs for the
// upstream hostnames, so the app's system-pool TLS verification passes
// both directly and through keploy's MITM.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("usage: %s <cert.pem> <key.pem> <bind-host> <port>", os.Args[0])
	}
	cert, key, host, port := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"upstream": "local-tls",
			"method":   r.Method,
			"path":     r.URL.RequestURI(),
		})
	})

	srv := &http.Server{
		Addr:      fmt.Sprintf("%s:%s", host, port),
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	log.Printf("local TLS upstream listening on https://%s:%s (TLS 1.3)", host, port)
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("server: %v", err)
	}
}
