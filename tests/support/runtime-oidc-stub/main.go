package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	listenAddress := "127.0.0.1:15556"
	flag.StringVar(&listenAddress, "listen", listenAddress, "loopback listen address")
	flag.Parse()
	if err := validateListenAddress(listenAddress); err != nil {
		fmt.Fprintf(os.Stderr, "runtime OIDC stub configuration failed: %v\n", err)
		os.Exit(1)
	}
	issuer := "http://" + listenAddress
	handler, err := newOIDCStubHandler(issuer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime OIDC stub configuration failed: %v\n", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()
	fmt.Printf("runtime OIDC stub listening on %s\n", issuer)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			fmt.Fprintf(os.Stderr, "runtime OIDC stub shutdown failed: %v\n", err)
			os.Exit(1)
		}
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "runtime OIDC stub failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" || port == "" {
		return errors.New("listen address must include an explicit loopback host and port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	parsedHost := net.ParseIP(host)
	if parsedHost == nil || !parsedHost.IsLoopback() {
		return errors.New("listen host must be loopback")
	}
	return nil
}

func newOIDCStubHandler(issuer string) (http.Handler, error) {
	parsedIssuer, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || parsedIssuer.Scheme != "http" || parsedIssuer.Host == "" || parsedIssuer.Path != "" || parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" || !isLoopbackIssuerHost(parsedIssuer.Hostname()) {
		return nil, errors.New("issuer must be an origin-only loopback HTTP URL")
	}

	discovery := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(writer, discovery)
		case "/keys":
			writeJSON(writer, map[string]any{"keys": []any{}})
		default:
			http.NotFound(writer, request)
		}
	}), nil
}

func isLoopbackIssuerHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsedHost := net.ParseIP(host)
	return parsedHost != nil && parsedHost.IsLoopback()
}

func writeJSON(writer http.ResponseWriter, value any) {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return
	}
}
