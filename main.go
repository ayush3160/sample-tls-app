// A tiny HTTP server that fans every incoming request out to a public
// HTTPS endpoint. The whole point is to give keploy something to mock
// over a real TLS connection so --capture-packets can produce a
// non-trivial traffic.pcap + sslkeys.log pair.
//
// Routes:
//
//	GET  /            health probe; no outbound call
//	GET  /quote       calls https://api.github.com/zen (returns a koan)
//	GET  /echo?msg=x  calls https://httpbin.org/anything?msg=x
//
// httpbin and api.github.com are the two endpoints used because they:
//   - speak TLS 1.2 / 1.3 with mainstream cipher suites (the ones Wireshark
//     can decrypt cleanly given a keylog),
//   - are public and unauthenticated,
//   - return small JSON / plaintext bodies so the pcap stays readable.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultAddr = ":8080"
	quoteURL    = "https://api.github.com/zen"
	echoURL     = "https://httpbin.org/anything"
)

// failMode is set at startup from the FAIL_MODE env var. When true,
// /quote and /echo return HTTP 500 instead of their normal 200
// payloads. The toggle exists to drive a deliberate replay failure
// in keploy without changing recorded test cases: record once with
// FAIL_MODE unset (status 200 captured), then redeploy with
// FAIL_MODE=1 and run keploy test — the recorded 200 vs the live
// 500 is reported as a high-risk failure (status mismatches cannot
// be silenced by noise rules the way body fields can), and once
// enough tests fail the cluster-proxy debug bundle auto-shares.
var failMode bool

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	switch strings.ToLower(os.Getenv("FAIL_MODE")) {
	case "1", "true", "yes", "on":
		failMode = true
		log.Print("FAIL_MODE enabled — /quote and /echo will return HTTP 500 to trigger keploy replay failures")
	}

	// One shared client; default transport already does TLS 1.2/1.3 with
	// the host's CA roots. Modest timeout so a hung upstream cannot
	// wedge the keploy recording session.
	client := &http.Client{Timeout: 10 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("/", health)
	mux.HandleFunc("/quote", quoteHandler(client))
	mux.HandleFunc("/echo", echoHandler(client))

	log.Printf("sample-tls-app listening on %s (try GET /quote and GET /echo?msg=hi)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func health(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, `{"status":"ok"}`+"\n")
}

func quoteHandler(client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, quoteURL, nil)
		if err != nil {
			httpError(w, "build request", err)
			return
		}
		req.Header.Set("User-Agent", "sample-tls-app/0.1 (+github.com/keploy)")

		resp, err := client.Do(req)
		if err != nil {
			httpError(w, "github fetch", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			httpError(w, "read response", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// Optional fail-mode toggle for keploy replay: when the
		// FAIL_MODE env var is "1" or "true", return 500 instead of
		// the upstream's 200. Keploy compares the response status
		// strictly (it cannot be noise-marked the way body fields
		// can), so a recorded 200 vs a replayed 500 is reported as
		// a high-risk failure. Once enough tests fail, the
		// cluster-proxy debug bundle auto-shares — which is the
		// artefact under test here.
		if failMode {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":    "fail mode enabled",
				"upstream": quoteURL,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"upstream":   quoteURL,
			"statusCode": resp.StatusCode,
			"quote":      string(body),
		})
	}
}

func echoHandler(client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		if msg == "" {
			msg = "hello-from-keploy"
		}

		url := fmt.Sprintf("%s?msg=%s", echoURL, msg)
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
		if err != nil {
			httpError(w, "build request", err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			httpError(w, "httpbin fetch", err)
			return
		}
		defer resp.Body.Close()

		// Same fail-mode hook as /quote: switch to 500 so the
		// recorded 200 mismatches at replay time as a high-risk
		// status delta (not noise-noiseable like body fields).
		if failMode {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":    "fail mode enabled",
				"upstream": echoURL,
			})
			return
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func httpError(w http.ResponseWriter, where string, err error) {
	log.Printf("%s: %v", where, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": fmt.Sprintf("%s: %v", where, err),
	})
}
