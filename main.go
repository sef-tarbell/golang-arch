package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type CustomClaims struct {
	jwt.StandardClaims
	Email string
}

const myKey = "there are 37 ferrets in your backyard"

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/submit", submitHandler)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	signedToken := c.Value
	token, err := jwt.ParseWithClaims(signedToken, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(myKey), nil
	})

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		// bad claims
	}

	message := "Not logged in"
	if ok && token.Valid && err == nil {
		message = "Logged in"
	}

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Example</title>
	</head>
	<body>
		<p>Email: ` + claims.Email + `</p>
		<p>` + message + `</p>
		<form action="/submit" method="POST">
			<input type="email" name="email" />
			<input type="submit" />
		</form>
	</body>
	</html>`
	io.WriteString(w, html)
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ss, err := getJWT(email)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	c := http.Cookie{
		Name:  "session",
		Value: ss,
	}

	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getJWT(msg string) (string, error) {
	claims := &CustomClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(myKey))
	if err != nil {
		return "", fmt.Errorf("Error in getJWT, Couldn't get signed string: %w", err)
	}

	return ss, nil
}
