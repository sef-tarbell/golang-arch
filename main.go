package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type CustomClaims struct {
	jwt.StandardClaims
	UserName string
}

const signingKey = "there are 37 ferrets in your backyard"

var db = map[string][]byte{}
var hmacKey = "supercalifragistic expialidotious 2221 aardvarks"

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	errorMsg := r.FormValue("errorMsg")

	signedToken := c.Value
	token, err := jwt.ParseWithClaims(signedToken, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}
		return []byte(signingKey), nil
	})

	message := "Not logged in"
	if err == nil && token.Valid {
		claims := token.Claims.(*CustomClaims)
		message = "Logged in as " + claims.UserName
	}

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Example</title>
	</head>
	<body>
		<p>` + message + `</p>
		<p>` + errorMsg + `</p>
		<hr>
		<h3>Register</h3>
		<form action="/register" method="POST">
			Username: <input type="text" name="username" /><br />
			Password: <input type="password" name="password" /><br />
			<input type="submit" name="Register" />
		</form>
		<hr>
		<h3>Login</h3>
		<form action="/login" method="POST">
			Username: <input type="text" name="username" /><br />
			Password: <input type="password" name="password" /><br />
			<input type="submit" name="Login" />
		</form>
	</body>
	</html>`
	io.WriteString(w, html)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	db[username] = hashedPassword

	ss, err := getJWT(username)
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	if _, ok := db[username]; !ok {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(db[username], []byte(password))
	if err != nil {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	ss, err := getJWT(username)
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

func getJWT(username string) (string, error) {
	claims := &CustomClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
		UserName: username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", fmt.Errorf("Error in getJWT, Couldn't get signed string: %w", err)
	}

	return ss, nil
}

func hashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error in hashPassword: %w", err)
	}

	return hash, nil
}

/**
 * takes a session id (string?)
 * uses HMAC to create a signature for the session id
 * return signed string: signature + session id
 */
func createToken(sid string) (string, error) {
	h := hmac.New(sha512.New, []byte(hmacKey))
	_, err := h.Write([]byte(sid))
	if err != nil {
		return "", fmt.Errorf("Error in createToken: %w", err)
	}

	ss := base64.StdEncoding.EncodeToString(h.Sum(nil))
	//return string(ss), nil
	// not sure why we are doing this...
	return ss + "|" + sid
}

/**
 * takes a signed string
 * separate the signature from the session id
 * verify that signature matches session id
 * return session id
 */
func parseToken(ss string) (string, error) {
	toks := strings.Split(ss, ".")
	if len(toks) != 2 {
		return "", fmt.Errorf("Error in parseToken: malformed token")
	}

	sig := toks[0]
	sid := toks[1]

	if !validMAC([]byte(sid), []byte(sig), []byte(hmacKey)) {
		return "", fmt.Errorf("Error in parseToken: mismatched token")
	}

	return sid, nil
}

/**
 * helper func to compare mac
 */
func validMAC(msg, msgMAC, k []byte) bool {
	mac := hmac.New(sha512.New, k)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(msgMAC, expectedMAC)
}
