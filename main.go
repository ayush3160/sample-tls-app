// A tiny HTTP server that fans every incoming request out over a real
// TLS connection — either to a public HTTPS endpoint, or to a local
// MySQL / Postgres instance running with TLS. The point is to give
// keploy a heterogeneous fixture so --capture-packets / the new
// --opportunistic-tls-intercept flag can be exercised against:
//
//   - HTTP-over-TLS (api.github.com / httpbin.org)
//   - MySQL-over-TLS (CLIENT_SSL capability flow)
//   - Postgres-over-TLS (SSLRequest preamble flow)
//
// Routes:
//
//	GET  /                 health probe; no outbound call
//	GET  /quote            calls https://api.github.com/zen (returns a koan)
//	GET  /echo?msg=x       calls https://httpbin.org/anything?msg=x
//	GET  /mysql/items      reads the items table from MySQL (TLS)         [optional, see MYSQL_DSN]
//	POST /mysql/items?name=x  inserts a row                              [optional]
//	GET  /postgres/items   reads the items table from Postgres (TLS)      [optional, see POSTGRES_DSN]
//	POST /postgres/items?name=x  inserts a row                           [optional]
//
// The DB routes register only when MYSQL_DSN / POSTGRES_DSN are set;
// older deployments that just want the HTTP routes are unaffected.
//
// All upstream TLS connections trust the OS root pool (no pinning,
// no manual cert install in the app). When keploy MITMs, its
// auto-installed CA is in that pool, so validation still passes.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
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

const mysqlTLSConfig = "system-pool"

// mysqlDB and pgDB are populated only when their respective DSN env
// vars are set. The HTTP handlers check for nil and return 503 if
// the route is not configured; this lets old HTTP-only deployments
// keep working without the new env vars.
var (
	mysqlDB *sql.DB
	pgDB    *sql.DB
)

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

	// Always register the DB routes so a missing DSN yields a clear
	// 503 instead of falling through to the "/" health catch-all.
	mux.HandleFunc("/mysql/items", mysqlItemsHandler)
	mux.HandleFunc("/postgres/items", postgresItemsHandler)

	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		var err error
		mysqlDB, err = openMySQL(dsn)
		if err != nil {
			log.Fatalf("mysql open: %v", err)
		}
		log.Printf("mysql route configured (DSN host=%s)", redactedHost(dsn, "mysql"))
	}
	if dsn := os.Getenv("POSTGRES_DSN"); dsn != "" {
		var err error
		pgDB, err = openPostgres(dsn)
		if err != nil {
			log.Fatalf("postgres open: %v", err)
		}
		log.Printf("postgres route configured (DSN host=%s)", redactedHost(dsn, "postgres"))
	}

	log.Printf("sample-tls-app listening on %s", addr)
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

// ---- MySQL ----

// openMySQL opens an *sql.DB against MYSQL_DSN. The DSN must NOT
// embed any tls= option; we register one programmatically that uses
// the OS root pool with chain-only verification (no hostname pin).
// MySQL's auto-generated server certs have a fixed CN that doesn't
// match real hostnames, so verify-CA semantics are required to
// validate the chain without the hostname check.
//
// When keploy MITMs the connection, its synthesized cert chains up
// to keploy's auto-installed root in the OS pool; the same
// VerifyConnection callback accepts both halves. No code change
// needed to switch between direct and intercepted modes.
func openMySQL(dsn string) (*sql.DB, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return nil, fmt.Errorf("system cert pool unavailable: %v", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            pool,
		InsecureSkipVerify: true, // hostname check disabled — see VerifyConnection
		VerifyConnection: func(state tls.ConnectionState) error {
			opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
			for _, c := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, verr := state.PeerCertificates[0].Verify(opts)
			if verr == nil {
				log.Printf("mysql TLS chain OK; subject=%q issuer=%q",
					state.PeerCertificates[0].Subject, state.PeerCertificates[0].Issuer)
			}
			return verr
		},
	}
	if err := mysqldriver.RegisterTLSConfig(mysqlTLSConfig, tlsCfg); err != nil {
		return nil, fmt.Errorf("register mysql tls: %w", err)
	}

	// Append our TLS config name to the DSN. Easier than parsing.
	if strings.Contains(dsn, "?") {
		dsn += "&tls=" + mysqlTLSConfig
	} else {
		dsn += "?tls=" + mysqlTLSConfig
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if err := db.PingContext(ctx); err == nil {
			break
		} else if ctx.Err() != nil {
			return nil, fmt.Errorf("mysql ping: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS items (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		created_at DATETIME NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("mysql init schema: %w", err)
	}
	return db, nil
}

func mysqlItemsHandler(w http.ResponseWriter, r *http.Request) {
	if mysqlDB == nil {
		http.Error(w, "mysql not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		dbInsert(w, r, mysqlDB, "INSERT INTO items (name, created_at) VALUES (?, ?)")
	case http.MethodGet:
		dbList(w, r, mysqlDB, "SELECT id, name, created_at FROM items ORDER BY id DESC LIMIT 20")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Postgres ----

// openPostgres opens an *sql.DB against POSTGRES_DSN. The DSN should
// already include sslmode=verify-ca (or stronger) so pgx validates
// the chain via the OS root pool. Same trust model as MySQL: no
// hostname pin (Postgres test certs typically don't match real
// hostnames), no embedded CA path — we lean on the system pool.
func openPostgres(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		if err := db.PingContext(ctx); err == nil {
			log.Printf("postgres ping OK")
			break
		} else if ctx.Err() != nil {
			return nil, fmt.Errorf("postgres ping: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS items (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		created_at TIMESTAMPTZ NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("postgres init schema: %w", err)
	}
	return db, nil
}

func postgresItemsHandler(w http.ResponseWriter, r *http.Request) {
	if pgDB == nil {
		http.Error(w, "postgres not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		dbInsert(w, r, pgDB, "INSERT INTO items (name, created_at) VALUES ($1, $2)")
	case http.MethodGet:
		dbList(w, r, pgDB, "SELECT id, name, created_at FROM items ORDER BY id DESC LIMIT 20")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- DB shared helpers ----

func dbInsert(w http.ResponseWriter, r *http.Request, db *sql.DB, query string) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name=", http.StatusBadRequest)
		return
	}
	if _, err := db.ExecContext(r.Context(), query, name, time.Now().UTC()); err != nil {
		httpError(w, "insert", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"name": name})
}

func dbList(w http.ResponseWriter, r *http.Request, db *sql.DB, query string) {
	rows, err := db.QueryContext(r.Context(), query)
	if err != nil {
		httpError(w, "query", err)
		return
	}
	defer rows.Close()
	type item struct {
		ID        int       `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := make([]item, 0)
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.Name, &it.CreatedAt); err != nil {
			httpError(w, "scan", err)
			return
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		httpError(w, "iterate", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// redactedHost extracts the host:port from a DSN for logging without
// surfacing credentials. Best-effort; falls back to the protocol name
// on parse errors.
func redactedHost(dsn, kind string) string {
	switch kind {
	case "postgres":
		if u, err := url.Parse(dsn); err == nil {
			return u.Host
		}
	case "mysql":
		// "user:pass@tcp(host:port)/db" — find the (...) chunk.
		if i := strings.Index(dsn, "tcp("); i >= 0 {
			rest := dsn[i+4:]
			if j := strings.Index(rest, ")"); j >= 0 {
				return rest[:j]
			}
		}
	}
	return "unknown"
}
