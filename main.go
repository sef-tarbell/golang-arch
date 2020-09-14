package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type CustomClaims struct {
	SessionID string
	jwt.StandardClaims
}

type UserData struct {
	UserName     string
	FirstName    string
	Registration string
	LastLogin    string
	Password     []byte
}

var db = map[string]UserData{}
var sessions = map[string]string{}

const (
	SIGNINGKEY = "fourhundredtonsofuranium235mixedwithcookiedough"
)

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

	// session is in the sessions store
	if sid != "" {
		userName, ok := sessions[sid]
		if !ok {
			errorMsg = url.QueryEscape("Missing session user")
		} else {
			u := db[userName]
			message = "Logged in as <b>" + u.FirstName + "</b> (" + string(userName) + ") registered: " + u.Registration
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
				<label for="firstname">First Name:</label>
					<input type="text" name="firstname" placeholder="First Name" id="firstname" /><br />
				<label for="username">User Name:</label>
					<input type="text" name="username" placeholder="User Name" id="username" /><br />
				<label for="password">Password:</label>
					<input type="password" name="password" id="password" /><br />
				<button type="submit">Register</button>
			</form>
			<hr>
			<h3>Login</h3>
			<form action="/login" method="POST">
				<label for="username">User Name:</label>
					<input type="text" name="username" placeholder="User Name" id="username" /><br />
				<label for="password">Password:</label>
					<input type="password" name="password" id="password" /><br />
				<button type="submit">Login</button>
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
	firstName := r.FormValue("firstname")
	password := r.FormValue("password")

	// safety check username and password required
	if userName == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// create a hash of the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	password = ""

	u := UserData{
		UserName:     userName,
		FirstName:    firstName,
		Registration: time.Now().Format(time.RFC3339),
		LastLogin:    time.Now().Format(time.RFC3339),
		Password:     hash,
	}
	db[userName] = u

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
	u, ok := db[userName]
	if !ok {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?errorMsg="+errorMsg, http.StatusSeeOther)
		return
	}

	// password check
	err := bcrypt.CompareHashAndPassword(u.Password, []byte(password))
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

	u.LastLogin = time.Now().Format(time.RFC3339)
	db[userName] = u

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

/**
 * takes a session id (string?)
 * creates a jwt with session id and expiration set to 15 min
 * return jwt
 */
func createToken(sid string) (string, error) {
	c := &CustomClaims{
		SessionID: sid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	ss, err := t.SignedString([]byte(SIGNINGKEY))
	if err != nil {
		return "", fmt.Errorf("Error in createToken: %w", err)
	}

	return ss, nil
}

/**
 * takes jwt
 * verify jwt is valid
 * return session id
 */
func parseToken(j string) (string, error) {
	t, err := jwt.ParseWithClaims(j, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Error in parseToken: Unexpected signing method")
		}
		return []byte(SIGNINGKEY), nil
	})
	if err != nil {
		return "", fmt.Errorf("Error in parseToken: Unable to parse token")
	}

	if !t.Valid {
		return "", fmt.Errorf("Error in parseToken: Invalid token")
	}

	claims, ok := t.Claims.(*CustomClaims)
	if !ok {
		return "", fmt.Errorf("Error in parseToken: Unable to parse claims")
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return "", fmt.Errorf("Error in parseToken: Expired token")
	}

	return claims.SessionID, nil
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
