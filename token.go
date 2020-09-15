package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type ourClaims struct {
	SessionID string
	jwt.StandardClaims
}

var signingKey = []byte("twotonsofuranium235!mixedwithcookiedoughandchocolatechips^")

func createToken(sid string) (string, error) {
	c := &ourClaims{
		SessionID: sid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	ss, err := t.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("Error in createToken: %w", err)
	}

	return ss, nil
}

func parseToken(j string) (string, error) {
	t, err := jwt.ParseWithClaims(j, &ourClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Error in parseToken: Unexpected signing method")
		}
		return signingKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("Error in parseToken: Unable to parse token")
	}

	if !t.Valid {
		return "", fmt.Errorf("Error in parseToken: Invalid token")
	}

	claims, ok := t.Claims.(*ourClaims)
	if !ok {
		return "", fmt.Errorf("Error in parseToken: Unable to parse claims")
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return "", fmt.Errorf("Error in parseToken: Expired token")
	}

	return claims.SessionID, nil
}
