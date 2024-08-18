package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateJWT generates a JWT token for a given user ID and email.
func GenerateJWT(userID uint, email string, isPartial bool) (string, error) {
	// Create JWT claims
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       strconv.Itoa(int(userID)),
		"email":     email,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"ispartial": isPartial,
	})

	// Sign the token with the secret
	token, err := claims.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", err
	}

	return token, nil
}
