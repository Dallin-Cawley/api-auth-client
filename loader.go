package auth

type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func NewCredentials(clientID, clientSecret string) *Credentials {
	return &Credentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

type Loader interface {
	Load() (*Credentials, error)
}
