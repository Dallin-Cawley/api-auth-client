package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/Dallin-Cawley/httpw"
	"github.com/Dallin-Cawley/public-api-auth/input"
	"github.com/Dallin-Cawley/public-api-auth/output"
)

var (
	theConfig *config
	logger    = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
)

type config struct {
	BaseURL string
}

func SetConfig(baseURL string) {
	theConfig = &config{
		BaseURL: baseURL,
	}
}

func SetLogger(l *slog.Logger) {
	logger = l
}

func GetToken(inputBody *input.CreateTokenInputBody) (*output.CreateTokenOutputBody, error) {
	return do[*output.CreateTokenOutputBody]("token", http.MethodPost, inputBody)
}

func VerifyToken(inputBody *input.ValidateTokenInputBody) (*output.ValidateOutputBody, error) {
	return do[*output.ValidateOutputBody]("validate", http.MethodPost, inputBody)
}

func do[T any](path, method string, inputBody any) (T, error) {
	requestBodyBytes, err := json.Marshal(inputBody)
	if err != nil {
		return *new(T), fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/%s", theConfig.BaseURL, path)
	request, err := http.NewRequest(method, url, bytes.NewReader(requestBodyBytes))
	if err != nil {
		return *new(T), fmt.Errorf("failed to create request: %w", err)
	}

	return httpw.Do[T](
		request,
		&http.Client{},
		logger,
	)
}
