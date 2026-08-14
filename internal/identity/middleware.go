package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"xminds-release-platform/internal/platform/httpx"
)

const maximumBearerTokenLength = 16 * 1024

var ErrAuthenticationFailed = errors.New("authentication failed")

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Principal, error)
}

type principalContextKey struct{}

func AuthenticationMiddleware(verifier Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			rawToken, ok := bearerToken(request)
			if !ok {
				writeAuthenticationProblem(writer, request, "AUTHENTICATION_REQUIRED", "Authentication is required", nil)
				return
			}
			if verifier == nil {
				writeAuthenticationProblem(writer, request, "AUTHENTICATION_FAILED", "Authentication failed", ErrAuthenticationFailed)
				return
			}
			principal, err := verifier.Verify(request.Context(), rawToken)
			if err != nil {
				writeAuthenticationProblem(writer, request, "AUTHENTICATION_FAILED", "Authentication failed", err)
				return
			}
			if err := principal.Validate(); err != nil {
				writeAuthenticationProblem(writer, request, "AUTHENTICATION_FAILED", "Authentication failed", err)
				return
			}
			ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	rawToken := strings.TrimSpace(parts[1])
	if rawToken == "" || len(rawToken) > maximumBearerTokenLength {
		return "", false
	}
	return rawToken, true
}

func writeAuthenticationProblem(writer http.ResponseWriter, request *http.Request, code string, title string, cause error) {
	writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
	httpx.WriteProblem(writer, httpx.NewProblem(
		http.StatusUnauthorized,
		code,
		title,
		cause,
	).WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}
