package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// AddUser ...
func AddUser(username, domain, backend string) {

	// Check if requested backend is supported
	if _, ok := backends[backend]; !ok {
		fmt.Println("Backend " + backend + " does not exist.")
		os.Exit(1)
	}

	// Create user config, password left empty
	cfg := userConfig{
		username,
		"",
		domain,
		backend,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Println(err)
		panic(err)
	}
	// Write config to user file
	err = ioutil.WriteFile(path.Join("users", username+".json"), b, 0644)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	// Set our claims, type is "signup" (one time usage token)
	claims := atClaims{
		&jwt.StandardClaims{
			// Set the expire time
			// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		"signup",
		username,
	}

	// Create a signer for HS 256
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create token string
	serverSecret, _ := ioutil.ReadFile("id_sha256")
	token, err := t.SignedString(serverSecret)
	// NOTE: Very unreliable way of zeroing memory
	serverSecret = []byte("")
	if err != nil {
		log.Println(err)
		panic(err)
	}

	fmt.Println("New user added:\n", string(b))
	fmt.Println("http://" + atConfig.SiteURL + "/signup/?token=" + token)
}
