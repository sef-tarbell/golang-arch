package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

// {"user_id":"amzn1.account.AGPCHSCJL6ZCTBHQTEU4CG67MHJQ","name":"Sef Tarbell","email":"sef.tarbell@gmail.com"}
type amazonProfileResponse struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

type UserData struct {
	UserName     string
	FirstName    string
	Registration string
	LastLogin    string
	Password     []byte
}

type IndexPageData struct {
	PageTitle string
	LoggedIn  bool
	FirstName string
	UserName  string
	Message   string
}

type PartialPageData struct {
	PageTitle    string
	FirstName    string
	UserName     string
	SignedUserID string
}

// key is username, value is userdata
// initializing with test user
var db = map[string]UserData{}

// key is sessionid, value is token
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiration time
var oauthExp = map[string]time.Time{}

// key is amazon ID, value is user ID
var oauthConnections map[string]string

var amazonOAuthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.441cca64a275479194c4ae19bf32b33b",
	ClientSecret: "106ff65dbe038691be6c03211ff64cd02d14d8215149e195f36949a06ec87771",
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
	Scopes:       []string{"profile"},
}

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/oauth/amazon/login", oauthAmazonLogin)
	http.HandleFunc("/oauth/amazon/receive", oauthAmazonReceive)
	http.HandleFunc("/oauth/amazon/register", oauthAmazonRegister)
	http.HandleFunc("/partial-register", partialRegister)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{
			Name:  "session",
			Path:  "/",
			Value: "",
		}
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		log.Println("root failed to parseToken", err)
	}

	var userName string
	var firstName string
	loggedIn := false
	if sid != "" {
		userName = sessions[sid]
		if userData, ok := db[userName]; ok {
			firstName = userData.FirstName
		}
		loggedIn = true
	}

	msg := r.FormValue("msg")

	tmpl := template.Must(template.ParseFiles("index.html"))
	data := IndexPageData{
		PageTitle: "Welcome",
		LoggedIn:  loggedIn,
		FirstName: firstName,
		UserName:  userName,
		Message:   msg,
	}
	tmpl.Execute(w, data)
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

	err = createSession(userName, w)
	if err != nil {
		log.Println("Error in register failed to create session", err)
		errorMsg := url.QueryEscape("Failed to create session")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

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

	err = createSession(userName, w)
	if err != nil {
		log.Println("Error in login failed to create session", err)
		errorMsg := url.QueryEscape("Failed to create session")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{
			Name:  "session",
			Path:  "/",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	delete(sessions, sID)

	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	code := r.FormValue("code")
	id := r.FormValue("state")

	// check session expired
	exp, ok := oauthExp[id]
	if !ok {
		errorMsg := url.QueryEscape("Invalid Session")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	if time.Now().After(exp) {
		errorMsg := url.QueryEscape("Expired Session")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// exchange to get a token
	token, err := amazonOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		errorMsg := url.QueryEscape("Failed Token Exchange")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	// get token source and client
	ts := amazonOAuthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	// query for profile info
	resp, err := client.Get("https://api.amazon.com/user/profile")
	if err != nil {
		errorMsg := url.QueryEscape("Amazon Access Failed")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		errorMsg := url.QueryEscape("Amazon Access Failed")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	var p amazonProfileResponse
	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		errorMsg := url.QueryEscape("Amazon Access Failed")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	amazonID := p.UserID
	userName, ok := oauthConnections[amazonID]
	if !ok {
		// send to partial register create a new user
		suid, err := createToken(amazonID)
		if err != nil {
			log.Println("Failed to create signed user id: ", err)
			errorMsg := url.QueryEscape("Login with Amazon Failed")
			http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
			return
		}

		params := url.Values{}
		params.Add("suid", suid)
		params.Add("name", p.Name)
		params.Add("email", p.Email)

		http.Redirect(w, r, "/partial-register?"+params.Encode(), http.StatusSeeOther)
		return
	}

	err = createSession(userName, w)
	if err != nil {
		log.Println("Error in oauthAmazonReceive failed to create session", err)
		errorMsg := url.QueryEscape("Failed to create session")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("You logged in " + userName)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func createSession(userName string, w http.ResponseWriter) error {
	sid := uuid.New().String()
	sessions[sid] = userName
	token, err := createToken(sid)
	if err != nil {
		return fmt.Errorf("Error in createSession, failed to create token: %w", err)
	}

	c := http.Cookie{
		Name:  "session",
		Path:  "/",
		Value: token,
	}

	http.SetCookie(w, &c)
	return nil
}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	suid := r.FormValue("suid")
	name := r.FormValue("name")
	email := r.FormValue("email")

	if suid == "" {
		log.Println("Error in partialRegister, failed to receive signed user id")
		errorMsg := url.QueryEscape("Failed to login with Amazon")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("partial-register.html"))
	data := PartialPageData{
		PageTitle:    "Complete Registration",
		FirstName:    name,
		UserName:     email,
		SignedUserID: suid,
	}
	tmpl.Execute(w, data)
}

func oauthAmazonRegister(w http.ResponseWriter, r *http.Request) {
}
