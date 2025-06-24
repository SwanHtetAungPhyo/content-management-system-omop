package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func main() {
	claims := jwt.MapClaims{
		"sub":      "user123",
		"email":    "test@example.com",
		"username": "testuser",
		"name":     "Test User",
		"roles":    []string{"user", "admin"},
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("Z+1mxVqJ9b/lidlCkiLKp10WnTcRAxL2iHJ2aCtFO38="))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Test JWT Token:\n%s\n", tokenString)
}
