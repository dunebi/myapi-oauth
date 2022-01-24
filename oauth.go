package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

func RandToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func GetOauth2Config(CA string) *oauth2.Config {
	fmt.Println("oauth module called")
	oauth2Config := &oauth2.Config{
		ClientID:     os.Getenv(CA + "_CLIENT_ID"),
		ClientSecret: os.Getenv(CA + "_CLIENT_SECRET"),
		RedirectURL:  os.Getenv(CA + "_REDIRECT_URL"),
	}

	if CA == "GOOGLE" {
		oauth2Config.Scopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
		oauth2Config.Endpoint = google.Endpoint
	} else if CA == "FACEBOOK" {
		oauth2Config.Scopes = []string{"email"}
		oauth2Config.Endpoint = facebook.Endpoint
	} else {
		oauth2Config.Scopes = []string{"user"}
		oauth2Config.Endpoint = github.Endpoint
	}

	return oauth2Config
}
