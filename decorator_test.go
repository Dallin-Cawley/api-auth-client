package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Dallin-Cawley/public-api-auth/output"
	"github.com/stretchr/testify/suite"
)

type DecoratorTestSuite struct {
	suite.Suite
}

func (testSuite *DecoratorTestSuite) TestClientCredentialsDecorator_Decorate() {
	tokenCount := 0
	expectedToken1 := "token-1"
	expectedToken2 := "token-2"

	// Future expiration for the first token
	expires1 := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	// Past expiration for the second token (not used yet, will be returned on second call)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var token string
		var expires string
		if tokenCount == 1 {
			token = expectedToken1
			expires = expires1
		} else {
			token = expectedToken2
			expires = time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		}

		resp := output.NewCreateTokenOutputBody(token, expires)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	SetConfig(server.URL)

	decorator := &ClientCredentialsDecorator{
		clientID:     "client-id",
		clientSecret: "client-secret",
	}

	// 1. Initial Decorate
	req1, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err := decorator.Decorate(req1)
	testSuite.NoError(err)
	testSuite.Equal("Bearer "+expectedToken1, req1.Header.Get("Authorization"))
	testSuite.Equal(1, tokenCount)

	// 2. Cached Decorate
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err = decorator.Decorate(req2)
	testSuite.NoError(err)
	testSuite.Equal("Bearer "+expectedToken1, req2.Header.Get("Authorization"))
	testSuite.Equal(1, tokenCount)

	// 3. Expired Decorate
	decorator.mu.Lock()
	decorator.expiresAt = time.Now().Add(-1 * time.Minute)
	decorator.mu.Unlock()

	req3, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err = decorator.Decorate(req3)
	testSuite.NoError(err)
	testSuite.Equal("Bearer "+expectedToken2, req3.Header.Get("Authorization"))
	testSuite.Equal(2, tokenCount)
}

func (testSuite *DecoratorTestSuite) TestClientCredentialsDecorator_ConcurrentDecorate() {
	tokenCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := output.NewCreateTokenOutputBody("concurrent-token", time.Now().Add(1*time.Hour).Format(time.RFC3339))
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	SetConfig(server.URL)

	signer := &ClientCredentialsDecorator{
		clientID:     "client-id",
		clientSecret: "client-secret",
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	for range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
			err := signer.Decorate(req)
			if err != nil {
				testSuite.Fail(fmt.Sprintf("Decorate failed: %v", err))
			}
			testSuite.Equal("Bearer concurrent-token", req.Header.Get("Authorization"))
		})
	}
	wg.Wait()

	// Should only have requested token once due to locking
	testSuite.Equal(1, tokenCount)
}

func (testSuite *DecoratorTestSuite) TestNewClientCredentialsDecorator() {
	clientID := "client-id"
	clientSecret := "client-secret"
	signer := NewClientCredentialsDecorator(clientID, clientSecret)

	testSuite.NotNil(signer)
	testSuite.Equal(clientID, signer.clientID)
	testSuite.Equal(clientSecret, signer.clientSecret)
}

func (testSuite *DecoratorTestSuite) TestClientCredentialsDecorator_Decorate_RefreshTokenError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	SetConfig(server.URL)

	signer := &ClientCredentialsDecorator{
		clientID:     "client-id",
		clientSecret: "client-secret",
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err := signer.Decorate(req)
	testSuite.ErrorContains(err, "failed to refresh token")
}

func (testSuite *DecoratorTestSuite) TestClientCredentialsDecorator_Decorate_ParseExpirationError() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := output.NewCreateTokenOutputBody("token", "invalid-date")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	SetConfig(server.URL)

	signer := &ClientCredentialsDecorator{
		clientID:     "client-id",
		clientSecret: "client-secret",
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err := signer.Decorate(req)
	testSuite.ErrorContains(err, "failed to parse expiration time")
}

func (testSuite *DecoratorTestSuite) TestClientCredentialsDecorator_RefreshTokenDoubleCheck() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := output.NewCreateTokenOutputBody("token", time.Now().Add(1*time.Hour).Format(time.RFC3339))
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	SetConfig(server.URL)

	signer := &ClientCredentialsDecorator{
		clientID:     "client-id",
		clientSecret: "client-secret",
	}

	// First refresh (successful)
	err := signer.refreshToken()
	testSuite.NoError(err)

	// Second refresh (should hit the double check)
	err = signer.refreshToken()
	testSuite.NoError(err)
}

func Test_RunDecoratorTestSuite(t *testing.T) {
	suite.Run(t, new(DecoratorTestSuite))
}
