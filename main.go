package main

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var githubOauthConfig = &oauth2.Config{
	ClientID:     "e21fc64e6333e75e190c",
	ClientSecret: "8d6a0ce82f6d081e6c998d1bb9fc5556592a30e4",
	Endpoint:     github.Endpoint,
}

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/oauth/github", oauthGithubHandler)
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
