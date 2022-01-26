package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type A interface {
	DbProcess(CA string) (string, error)
}

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

func LoginProcess() func(newCA string) (string, error) {
	var oauth2Config *oauth2.Config
	CA := ""

	return func(newCA string) (string, error) { // (redirectURL, error)
		if (newCA != "GOOGLE") && (newCA != "FACEBOOK") && (newCA != "GITHUB") {
			return "", errors.New("use google, facebook or github")
		}

		if CA != newCA {
			oauth2Config = GetOauth2Config(newCA)
			os.Setenv("CA", newCA)
			CA = newCA
		}
		URL := oauth2Config.AuthCodeURL(RandToken(), oauth2.AccessTypeOffline)
		return URL, nil
	}
}

func LoginCallbackProcess() func(code string) (interface{}, error) {
	apiURL := map[string]string{
		"GOOGLE":   "https://www.googleapis.com/oauth2/v3/userinfo",
		"FACEBOOK": "https://graph.facebook.com/me?locale=en_US&fields=name,email",
		"GITHUB":   "https://api.github.com/user",
	}
	var oauth2Config *oauth2.Config
	CA := ""

	return func(code string) (interface{}, error) {
		newCA := os.Getenv("CA")
		if CA != newCA {
			oauth2Config = GetOauth2Config(newCA)
			CA = newCA
			log.Println("oauth2Config changed")
		}

		token, err := oauth2Config.Exchange(oauth2.NoContext, code)
		if err != nil {
			return "", errors.New("error on get token")
		}

		client := oauth2Config.Client(oauth2.NoContext, token)
		userInfoResp, err := client.Get(apiURL[CA])
		if err != nil {
			return "", errors.New("error on call api with get method")
		}
		defer userInfoResp.Body.Close()

		userInfo, err := ioutil.ReadAll(userInfoResp.Body)
		if err != nil {
			return "", errors.New("error on read userInfo response body")
		}

		var account interface{}
		json.Unmarshal(userInfo, &account)
		return account, nil
	}
}
