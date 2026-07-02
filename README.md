# api-auth-client

The `api-auth-client` repository provides convenience methods for interacting with the `api-auth` server for token creation and validation.

## Installation

```bash
go get github.com/Dallin-Cawley/api-auth-client
```

## Initialization

To use this library, you first need to initialize the configuration with the base URL of your `api-auth` server. You can also optionally provide a custom logger.

```go
package main

import (
    "github.com/Dallin-Cawley/api-auth-client"
)

func init() {
    auth.SetConfig("https://auth.your-server.com")
}
```

### Setting a Custom Logger

By default, the library uses a JSON handler logging to `os.Stdout` at `Debug` level. You can override this:

```go
package main

import (
    "log/slog"
    "os"
    "github.com/Dallin-Cawley/api-auth-client"
)

auth.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))
```

## Usage

### Token Creation

To create a new token, use the `GetToken` method with the appropriate credentials.

```go
package main

import (
    "fmt"
    "github.com/Dallin-Cawley/api-auth-client"
    "github.com/Dallin-Cawley/public-api-auth/input"
)

func main() {
    clientID := "my-client-id"
    clientSecret := "my-client-secret"
    inputBody := input.NewCreateTokenInputBody(&clientID, &clientSecret)

    token, err := auth.GetToken(inputBody)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Access Token: %s\n", token.AccessToken)
}
```

### Token Validation

To verify an existing token, use the `VerifyToken` method.

```go
package main

import (
    "fmt"
    "github.com/Dallin-Cawley/api-auth-client"
    "github.com/Dallin-Cawley/public-api-auth/input"
)

func validate(accessToken string) {
    inputBody := input.NewValidateTokenInputBody(accessToken)

    result, err := auth.VerifyToken(inputBody)
    if err != nil {
        fmt.Println("Token is invalid:", err)
        return
    }

    fmt.Printf("Token is valid for subject: %s\n", result.Subject)
}
```

### Request Decoration

For automatic token management and request decoration, use the `ClientCredentialsDecorator`. It handles token caching and automatic refreshing when the token expires. The decorator is thread-safe and can be shared across multiple clients or goroutines.

```go
package main

import (
    "net/http"
    "github.com/Dallin-Cawley/api-auth-client"
)

func main() {
    decorator := auth.NewClientCredentialsDecorator("my-client-id", "my-client-secret")

    req, _ := http.NewRequest("GET", "https://api.your-service.com/data", nil)
    
    // Decorate the request with a Bearer token
    if err := decorator.Decorate(req); err != nil {
        panic(err)
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    // ...
}
```

### Auth Middleware

The library also provides a standard library-compatible middleware for authenticating incoming HTTP requests.

```go
package main

import (
    "fmt"
    "net/http"
    "github.com/Dallin-Cawley/api-auth-client"
)

func main() {
    mux := http.NewServeMux()

    // Protected endpoint
    mux.Handle("GET /protected", auth.AuthMiddleware(http.HandlerFunc(protectedHandler)))

    http.ListenAndServe(":8080", mux)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve token information from the context
    tokenInfo, ok := auth.FromContext(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    fmt.Fprintf(w, "Hello, %s!", tokenInfo.Subject)
}
```

