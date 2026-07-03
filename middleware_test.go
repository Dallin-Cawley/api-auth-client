package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dallin-Cawley/public-api-auth/output"
	"github.com/stretchr/testify/suite"
)

type MiddlewareTestSuite struct {
	suite.Suite
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_Success() {
	// Mock auth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&output.ValidateOutputBody{
			Subject: "user-123",
		})
	}))
	defer server.Close()

	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	// Next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenInfo, ok := FromContext(r.Context())
		testSuite.True(ok)
		testSuite.Equal("user-123", tokenInfo.Subject)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Middleware
	middleware := Middleware(nextHandler)

	// Request
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusOK, rr.Code)
	testSuite.Equal("OK", rr.Body.String())
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_MissingHeader() {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Fail("Next handler should not be called")
	})

	middleware := Middleware(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusUnauthorized, rr.Code)
	testSuite.Contains(rr.Body.String(), "authorization header is required")
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_InvalidFormat() {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Fail("Next handler should not be called")
	})

	middleware := Middleware(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "InvalidFormat token")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusUnauthorized, rr.Code)
	testSuite.Contains(rr.Body.String(), "invalid authorization header format")
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_InvalidToken() {
	// Mock auth server returning error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Fail("Next handler should not be called")
	})

	middleware := Middleware(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusUnauthorized, rr.Code)
	testSuite.Contains(rr.Body.String(), "invalid or expired token")
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_LowercaseBearer() {
	// Mock auth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&output.ValidateOutputBody{
			Subject: "user-123",
		})
	}))
	defer server.Close()

	loader := &mockLoader{creds: NewCredentials("id", "secret")}
	_ = Init(WithBaseURL(server.URL), WithLoader(loader))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(nextHandler)
	// Test lowercase
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "bearer valid-token")
	rr := httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)
	testSuite.Equal(http.StatusOK, rr.Code)

	// Test multiple spaces
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "Bearer    valid-token")
	rr = httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)
	testSuite.Equal(http.StatusOK, rr.Code)
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_InvalidFormat_EmptyToken() {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Fail("Next handler should not be called")
	})

	middleware := Middleware(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusUnauthorized, rr.Code)
}

func (testSuite *MiddlewareTestSuite) TestAuthMiddleware_InvalidFormat_TooManyFields() {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testSuite.Fail("Next handler should not be called")
	})

	middleware := Middleware(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(testSuite.T().Context())
	req.Header.Set("Authorization", "Bearer token extra")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	testSuite.Equal(http.StatusUnauthorized, rr.Code)
}

func Test_RunMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}
