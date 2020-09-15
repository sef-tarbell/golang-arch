package main

import (
	"fmt"
	"net/http"
)

// github
// Client ID e21fc64e6333e75e190c
// Client Secret 8d6a0ce82f6d081e6c998d1bb9fc5556592a30e4

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
}
