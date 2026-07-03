package auth

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Decorator is an interface that defines the Decorate method for adding authorization to an HTTP request.
type Decorator interface {
	// Decorate adds authorization to the provided HTTP request.
	Decorate(r *http.Request) error
}

// ClientCredentialsDecorator implements the Decorator interface using the OAuth 2.0 Client Credentials flow.
type ClientCredentialsDecorator struct {
	clientID     string
	clientSecret string
	token        string
	expiresAt    time.Time
	mu           sync.RWMutex
}

// NewClientCredentialsDecorator creates a new instance of ClientCredentialsDecorator.
func NewClientCredentialsDecorator(clientID, clientSecret string) *ClientCredentialsDecorator {
	return &ClientCredentialsDecorator{
		clientID:     clientID,
		clientSecret: clientSecret,
		mu:           sync.RWMutex{},
	}
}

// isTokenValid checks if the current cached token is non-empty and has not expired.
func (decorator *ClientCredentialsDecorator) isTokenValid() bool {
	return decorator.token != "" && time.Now().Before(decorator.expiresAt)
}

// Decorate adds a Bearer token to the Authorization header of the provided HTTP request.
// It refreshes the token if it is missing or expired.
func (decorator *ClientCredentialsDecorator) Decorate(r *http.Request) error {
	decorator.mu.RLock()

	if decorator.isTokenValid() {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", decorator.token))
		decorator.mu.RUnlock()
		return nil
	}
	decorator.mu.RUnlock()

	decorator.mu.Lock()
	defer decorator.mu.Unlock()

	if err := decorator.refreshToken(); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", decorator.token))
	return nil
}

// refreshToken fetches a new access token from the api-auth server and updates the decorator's state.
func (decorator *ClientCredentialsDecorator) refreshToken() error {
	// Double check after acquiring write lock
	if decorator.isTokenValid() {
		return nil
	}

	resp, err := GetToken()
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, resp.AccessExpires)
	if err != nil {
		return fmt.Errorf("failed to parse expiration time: %w", err)
	}

	decorator.token = resp.AccessToken
	decorator.expiresAt = expiresAt

	return nil
}
