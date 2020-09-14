package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type CustomClaims struct {
	jwt.StandardClaims
	UserName string
}

var db = map[string][]byte{}
var sessions = map[string]string{}

var hmacKey = "supercalifragistic expialidotious 2221 aardvarks"

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	sid := ""
	message := "Not logged in"
	errorMsg := r.FormValue("errorMsg") // fuck it

	// retrieve the session id from the cookie
	if c, err := r.Cookie("session"); err == nil {
		// parse the cookie to get the session id
		sid, err = parseToken(c.Value)
		if err != nil {
			errorMsg = url.QueryEscape("Missing or corrupted cookie")
		}
	}

	// session is in the db
	if sid != "" {
		userName, ok := sessions[sid]
		if !ok {
			errorMsg = url.QueryEscape("Missing session user")
		} else {
			message = "Logged in as " + string(userName)
		}
	}

	fmt.Fprintf(w,
		`<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>HMAC Example</title>
		</head>
		<body>
			<p>`+message+`</p>
			<p>`+errorMsg+`</p>
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
		</html>`)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// safety check, only handle POST requests
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get the form data
	userName := r.FormValue("username")
	password := r.FormValue("password")

	// safety check username and password required
	if userName == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// create a hash of the password
	hashedPassword, err := hashPassword(password)
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	password = ""
	db[userName] = hashedPassword

	// create a uuid for session id
	sid, err := uuid.NewV4()
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	sessions[sid.String()] = userName

	// create a token to store as cookie
	t, err := createToken(sid.String())
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// store cookie
	c := http.Cookie{
		Name:  "session",
		Value: t,
	}

	// return with no error
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// safety check, only handle POST requests
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get the form data
	userName := r.FormValue("username")
	password := r.FormValue("password")

	// safety check username and password required
	if userName == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// user is in the db
	if _, ok := db[userName]; !ok {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// password check
	err := bcrypt.CompareHashAndPassword(db[userName], []byte(password))
	if err != nil {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}
	password = ""

	// create a uuid for session id
	sid, err := uuid.NewV4()
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	sessions[sid.String()] = userName

	// create a token to store as cookie
	t, err := createToken(sid.String())
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// store cookie
	c := http.Cookie{
		Name:  "session",
		Value: t,
	}

	// return with no error
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	return ss + "|" + sid, nil
}

/**
 * takes a signed string
 * separate the signature from the session id
 * verify that signature matches session id
 * return session id
 */
func parseToken(ss string) (string, error) {
	toks := strings.Split(ss, "|")
	if len(toks) != 2 {
		return "", fmt.Errorf("Error in parseToken: malformed token")
	}

	sig, err := base64.StdEncoding.DecodeString(toks[0])
	if err != nil {
		return "", fmt.Errorf("Error in parseToken: %w", err)
	}

	if !validMAC([]byte(toks[1]), []byte(sig), []byte(hmacKey)) {
		return "", fmt.Errorf("Error in parseToken: mismatched token")
	}

	return string(toks[1]), nil
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
