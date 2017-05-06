package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type userConfig struct {
	Username string
	Password string
	Domain   string
	Backend  string
}

type atClaims struct {
	*jwt.StandardClaims
	TokenType string
	Username  string
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tks := r.Header.Get("Authorization")
		if !strings.HasPrefix(tks, "Bearer ") {
			http.Error(w, "No token found", http.StatusUnauthorized)
			return
		}
		tks = strings.TrimPrefix(tks, "Bearer ")
		fmt.Println(tks)

		token, err := jwt.ParseWithClaims(tks, &atClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			serverSecret, _ := ioutil.ReadFile("id_sha256")
			return serverSecret, nil
		})
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Could not parse token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*atClaims); ok && token.Valid {
			fmt.Println(claims)
			ctx := context.WithValue(r.Context(), "Username", claims.Username)
			next(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	})
}

func usermeta(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Context().Value("Username"))

	cfgStr, err := ioutil.ReadFile(filepath.Join("users/", r.Context().Value("Username").(string)+".json"))
	if err != nil {
		// Handle error
		log.Println(err)
		return
	}

	var cfg userConfig
	if err = json.Unmarshal(cfgStr, &cfg); err != nil {
		log.Println(err)
	}

	json, err := json.Marshal(&struct {
		Username string `json:"username"`
		Domain   string `json:"domain"`
		Backend  string `json:"backend"`
	}{
		Username: cfg.Username,
		Domain:   cfg.Domain,
		Backend:  cfg.Backend,
	})
	if err != nil {
		return
	}

	w.Write(json)
}

func signup(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method)

	// Retrieve token from request parameters
	tks := r.URL.Query()["token"][0]
	fmt.Println(tks)

	token, err := jwt.ParseWithClaims(tks, &atClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		serverSecret, _ := ioutil.ReadFile("id_sha256")
		return serverSecret, nil
	})
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Could not parse token", http.StatusUnauthorized)
		return
	}

	// TokenType must be "signup"
	if claims, ok := token.Claims.(*atClaims); ok && token.Valid && claims.TokenType == "signup" {
		fmt.Println(claims)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"status\":\"OK\"}"))
	} else {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		// Handle error
		log.Println(err)
		return
	}

	cfgStr, err := ioutil.ReadFile(filepath.Join("users/", r.FormValue("user")+".json"))
	if err != nil {
		// Handle error
		log.Println(err)
		return
	}

	var cfg userConfig
	if err = json.Unmarshal(cfgStr, &cfg); err != nil {
		log.Println(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cfg.Password), []byte(r.FormValue("password"))); err != nil {
		log.Println("Failed login attempt for user", r.FormValue("user"), err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	log.Println("Successful login for user", r.FormValue("user"))

	// Set our claims
	claims := atClaims{
		&jwt.StandardClaims{
			// Set the expire time
			// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		"site-owner",
		r.FormValue("user"),
	}

	// Create a signer for HS 256
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create token string
	serverSecret, _ := ioutil.ReadFile("id_sha256")
	token, err := t.SignedString(serverSecret)
	// NOTE: Very unreliable way of zeroing memory
	serverSecret = []byte("")
	if err != nil {
		fmt.Println("lol", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	w.Write([]byte("{\"jwt\":\"" + token + "\"}"))
}

func main() {
	addUserCommand := flag.NewFlagSet("adduser", flag.ExitOnError)
	addUserName := addUserCommand.String("name", "", "New user name. (Required)")
	addUserDomain := addUserCommand.String("domain", "", "New user site domain. (Required)")
	addUserBackend := addUserCommand.String("backend", "", "New user generator backend {hugo|hexo|pdf|raw}. (Required)")

	if len(os.Args) > 1 {
		if os.Args[1] == "adduser" {
			addUserCommand.Parse(os.Args[2:])
			AddUser(*addUserName, *addUserDomain, *addUserBackend)
		} else {
			fmt.Println("Available commands:\n\nadduser - add a new user and destination site")
			addUserCommand.Usage()
			fmt.Println("")
			os.Exit(1)
		}
	} else {
		// Main router
		r := mux.NewRouter()

		// Api subrouter and handlers
		api := r.PathPrefix("/a").Subrouter()
		api.HandleFunc("/login", login).
			Methods("POST")
		api.HandleFunc("/signup/", signup).
			Methods("GET")
		api.HandleFunc("/usermeta", auth(usermeta)).
			Methods("GET")

		// Router to static frontend files
		// NOTE(Simon-L): Fix ASAP, proxying to frontend served by Aurelia cli
		url, _ := url.Parse("http://localhost:9000/")
		proxy := httputil.NewSingleHostReverseProxy(url)
		r.HandleFunc("/{rest:.*}", func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = mux.Vars(r)["rest"]
			proxy.ServeHTTP(w, r)
		})

		log.Println("Serving on :8000...")
		log.Fatal(http.ListenAndServe(":8000", r))
	}
}
