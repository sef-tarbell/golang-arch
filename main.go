package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session")
	}

	return nil
}

var key = "this is a terrible key to use"

func main() {
	/*
		pass := "123456789"

		hash, err := hashPassword(pass)
		if err != nil {
			panic(err)
		}

		err = comparePassword(pass, hash)
		if err != nil {
			log.Fatalln("Not logged in")
		}

		log.Println("Logged in")
	*/

	// http.HandleFunc("/test", testFunc)
	// http.ListenAndServe(":8080", nil)

	msg := "This is a message"
	sig, err := signMessage([]byte(msg))
	if err != nil {
		panic(err)
	}

	match, err := checkSignature([]byte(msg), sig)
	if err != nil {
		panic(err)
	}
	if match {
		log.Println("Match")
	}

}

/**
 * takes a password, returns a hash
 */
func hashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}

	return hash, nil
}

/**
 * takes a password and hash, returns error with unsuccessful compare
 */
func comparePassword(password string, hash []byte) error {
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}

	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, []byte(key))
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSignature(msg []byte, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSignature while signing message: %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}

func createToken(c *UserClaims) (string, error) {
	j := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := j.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token %w", err)
	}
	return signedToken, nil
}
