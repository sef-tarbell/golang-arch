package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// {"data":{"viewer":{"id":"<returned-from-github>"}}}
type githubOAuthResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

var githubOauthConfig = &oauth2.Config{
	ClientID:     "e21fc64e6333e75e190c",
	ClientSecret: "8d6a0ce82f6d081e6c998d1bb9fc5556592a30e4",
	Endpoint:     github.Endpoint,
}

// key is github ID, value is user ID
var githubConnections map[string]string

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/oauth/github", oauthGithubHandler)
	http.HandleFunc("/oauth2/receive", oauthReceiveHandler)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w,
		`<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>Title</title>
		</head>
		<body>
			<form action="/oauth/github" method="POST">
				<input type="submit" value="Login with Github" />
			</form>
		</body>
		</html>`)
}

func oauthGithubHandler(w http.ResponseWriter, r *http.Request) {
	// should be passing some sort of state - session or something
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func oauthReceiveHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	// this would check the session id
	if state != "0000" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}

	ts := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Failed to retrieve user id", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var gr githubOAuthResponse
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		return
	}

	githubID := gr.Data.Viewer.ID
	userID, ok := githubConnections[githubID]
	if !ok {
		// create user account
	}

	// login to account using JWT
}
