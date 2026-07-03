package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/Dallin-Cawley/public-api-auth/output"
)

type contextKey int

const tokenKey contextKey = iota

// FromContext returns the token information from the request context.
func FromContext(ctx context.Context) (*output.ValidateOutputBody, bool) {
	val, ok := ctx.Value(tokenKey).(*output.ValidateOutputBody)
	return val, ok
}

// Middleware is a middleware that authenticates incoming requests using a Bearer token.
// It validates the token against the api-auth server using VerifyToken.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "authorization header is required", http.StatusUnauthorized)
			return
		}

		parts := strings.Fields(authHeader)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid authorization header format. expected 'bearer <token>'", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		tokenInfo, err := VerifyToken(token)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), tokenKey, tokenInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
