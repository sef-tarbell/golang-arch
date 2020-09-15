package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

// {"data":{"viewer":{"id":"<returned-from-amazon>"}}}
/*
type amazonOAuthResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}
*/

type UserData struct {
	UserName     string
	FirstName    string
	Registration string
	LastLogin    string
	Password     []byte
}

// key is username, value is userdata
var db = map[string]UserData{}

// key is sessionid, value is token
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiration time
var oauthExp = map[string]time.Time{}

var amazonOAuthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.441cca64a275479194c4ae19bf32b33b",
	ClientSecret: "106ff65dbe038691be6c03211ff64cd02d14d8215149e195f36949a06ec87771",
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
	Scopes:       []string{"profile"},
}

// key is amazon ID, value is user ID
var amazonConnections map[string]string

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/oauth/amazon/login", oauthAmazonLogin)
	http.HandleFunc("/oauth/amazon/receive", oauthAmazonReceive)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{
			Name:  "session",
			Value: "",
		}
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		log.Println("root failed to parseToken", err)
	}

	var userName string
	if sid != "" {
		userName = sessions[sid]
	}

	var firstName string
	if userData, ok := db[userName]; ok {
		firstName = userData.FirstName
	}

	msg := r.FormValue("msg")

	fmt.Fprintf(w,
		`<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>OAuth Example</title>
		</head>
		<body>
			<p>Logged in as <b>%s</b> (%s)</p>
			<p>Message: %s</p>
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
			<hr>
			<h3>Login With Amazon</h3>
			<form action="/oauth/amazon/login" method="POST">
				<button type="submit">Login With Amazon</button>
			</form>
			<hr>
			<h3>Logout</h3>
			<form action="/logout" method="POST">
				<button type="submit">Logout</button>
			</form>
		</body>
		</html>`, firstName, userName, msg)
}

func register(w http.ResponseWriter, r *http.Request) {
	// safety check, only handle POST requests
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get the form data
	userName := r.FormValue("username")
	firstName := r.FormValue("firstname")
	password := r.FormValue("password")

	// safety check username and password required
	if userName == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
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
	sid := uuid.New().String()
	sessions[sid] = userName

	// create a token to store as cookie
	t, err := createToken(sid)
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// store cookie
	c := http.Cookie{
		Name:  "session",
		Value: t,
		Path:  "/",
	}

	// return with no error
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	// safety check, only handle POST requests
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get the form data
	userName := r.FormValue("username")
	password := r.FormValue("password")

	// safety check username and password required
	if userName == "" || password == "" {
		errorMsg := url.QueryEscape("Missing required data")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// user is in the db
	u, ok := db[userName]
	if !ok {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// password check
	err := bcrypt.CompareHashAndPassword(u.Password, []byte(password))
	if err != nil {
		errorMsg := url.QueryEscape("Username or password mismatch")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}
	password = ""

	// create a uuid for session id
	sid := uuid.New().String()
	sessions[sid] = userName

	u.LastLogin = time.Now().Format(time.RFC3339)
	db[userName] = u

	// create a token to store as cookie
	t, err := createToken(sid)
	if err != nil {
		errorMsg := "Internal Server Error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// store cookie
	c := http.Cookie{
		Name:  "session",
		Value: t,
		Path:  "/",
	}

	// return with no error
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	sid := ""
	message := "Logged out"

	// retrieve the session id from the cookie
	if c, err := r.Cookie("session"); err == nil {
		// parse the cookie to get the session id
		sid, err = parseToken(c.Value)
		if err != nil {
			// log out an error?
			message = "Failed to parse cookie"
		}

		if sid != "" {
			// delete the session
			delete(sessions, sid)
		}

		newCookie := http.Cookie{
			Name:    "session",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
		}

		http.SetCookie(w, &newCookie)
	}

	http.Redirect(w, r, "/?msg="+message, http.StatusSeeOther)
}

func oauthAmazonLogin(w http.ResponseWriter, r *http.Request) {
	// safety check, only handle POST requests
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("HTTP method was not a POST")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// create a uuid for session id
	id := uuid.New().String()
	oauthExp[id] = time.Now().Add(time.Hour)

	// redirect to amazon for login
	http.Redirect(w, r, amazonOAuthConfig.AuthCodeURL(id), http.StatusSeeOther)
}

func oauthAmazonReceive(w http.ResponseWriter, r *http.Request) {
}
