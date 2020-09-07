package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
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
}

func hashPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}

	return hash, nil
}

func comparePassword(password string, hash []byte) error {
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}

	return nil
}
