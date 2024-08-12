// controllers/authController.go

package controllers

import (
	"Jwt-Auth/database"
	"Jwt-Auth/models"
	"Jwt-Auth/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

/* register New User */

func Register(c *gin.Context) {

	// Parse request body
	var data map[string]string
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to parse request body",
		})
		return
	}

	// Check if the email already exists
	var existingUser models.User
	err := database.DB.Where("email = ?", data["email"]).First(&existingUser).Error
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email already exists",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Create new user
	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: string(hashedPassword),
		Address:  data["address"],
	}

	// Insert user into database
	err = database.DB.Create(&user).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
	})
}

func Login(c *gin.Context) {
	// Define the LoginRequest struct
	type LoginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	// Parse request body
	var data LoginRequest
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to parse request body",
		})
		return
	}

	// Check if the email exists in db
	var existingUser models.User
	err := database.DB.Where("email = ?", data.Email).First(&existingUser).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Email Not registered in the DB",
		})
		return
	}

	// Check if the password is correct
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(data.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Generate JWT Token using the separate function
	token, err := utils.GenerateJWT(existingUser.ID, existingUser.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	// Set JWT Token in Cookies
	c.SetCookie(
		"jwt",
		token,
		3600,
		"/",
		"",
		false,
		true,
	)

	// Respond with a success message or additional data
	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

// Request to Get User
func User(c *gin.Context) {
	// Retrieve user information from the context
	userID, _ := c.Get("userID")
	email, _ := c.Get("email")

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"email":   email,
	})
}

func Logout(c *gin.Context) {
	// Clear the JWT Token by setting the cookie to an empty value and a past expiration time
	c.SetCookie(
		"jwt",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	// Respond with a success message
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}
