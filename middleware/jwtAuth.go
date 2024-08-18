package middleware

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT Token from Cookies
		tokenString, err := c.Cookie("jwt")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized, token not found",
			})
			c.Abort()
			return
		}

		// Parse and validate the JWT token
		claims := &jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET")), nil
		})

		if err != nil || !parsedToken.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized, invalid token",
			})
			c.Abort()
			return
		}

		// Store the claims in the context for later use
		c.Set("userID", (*claims)["sub"])
		c.Set("email", (*claims)["email"])

		// Continue to the next handler
		c.Next()
	}
}
