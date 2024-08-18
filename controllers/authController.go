// controllers/authController.go

package controllers

import (
	"Jwt-Auth/database"
	"Jwt-Auth/models"
	"Jwt-Auth/utils"
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mrz1836/postmark"
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
	token, err := utils.GenerateJWT(existingUser.ID, existingUser.Email, false)
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

// forgot password
func ForgetPassword(c *gin.Context) {
	type ForgetPasswordRequest struct {
		Email string `json:"email"`
	}
	var data ForgetPasswordRequest
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to parse request body",
		})
		return
	}
	// Check if the email exists in the database
	var existingUser models.User
	if err := database.DB.Where("email = ?", data.Email).First(&existingUser).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email not found",
		})
		return
	}

	// Check if an OTP already exists for this user
	var existingOTP models.OTP
	if err := database.DB.Where("user_id = ?", existingUser.ID).First(&existingOTP).Error; err == nil {
		// If an OTP exists, delete it
		if err := database.DB.Delete(&existingOTP).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove existing OTP",
			})
			return
		}
	}

	otpCode := utils.GenerateOTP()

	// Create OTP instance
	otp := models.OTP{
		UserID:    existingUser.ID, // Foreign key linking to the user
		Code:      otpCode,
		ExpiresAt: time.Now().Add(time.Second * 50),
		CreatedAt: time.Now(),
	}

	// Save OTP to the database
	if err := database.DB.Create(&otp).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create OTP",
		})
		return
	}

	// Load and render the email template
	tmpl, err := utils.LoadTemplate("templates/otp_email_template.html")
	if err != nil {
		log.Printf("Error loading template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load email template",
		})
		return
	}

	// Render the template with context
	ctx := map[string]interface{}{"OTP": otpCode}
	renderedBody, err := tmpl.Execute(ctx)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to render email template",
		})
		return
	}

	client := postmark.NewClient("0bcfcab9-e681-4dde-aa9a-a7482fa297b5", "384df086-9d59-4016-8583-e86768236355")

	email := postmark.Email{
		From:       "mote.sai@todaypay.me",
		To:         existingUser.Email,
		Subject:    "Reset your password",
		HTMLBody:   renderedBody,
		TextBody:   "Please use the HTML version of this email.",
		Tag:        "pw-reset",
		TrackOpens: true,
	}

	_, err = client.SendEmail(context.Background(), email)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send email",
		})
		return
	}

	// Generate JWT Token using the separate function
	token, err := utils.GenerateJWT(existingUser.ID, existingUser.Email, true)
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
		600,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Password reset email sent",
		"token":   token,
	})
}

// verify otp
func VerifyOTP(c *gin.Context) {
	type verifyOTPRequest struct {
		OTP string `json:"otp"`
	}

	var data verifyOTPRequest
	err := c.ShouldBindJSON(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "bad Request",
		})
		return
	}

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

	// Extract userID from the "sub" claim
	userID, _ := (*claims)["sub"].(string)
	userEmail, _ := (*claims)["email"].(string)

	var existingOTP models.OTP
	if err := database.DB.Where("user_id = ?", userID).First(&existingOTP).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "No OTP generated",
		})
		return
	}

	// Check if the OTP is correct and not expired
	if data.OTP != existingOTP.Code {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid OTP",
		})
		return
	}

	if time.Now().After(existingOTP.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "OTP has expired",
		})
		return
	}

	// OTP is correct, delete it from the database
	if err := database.DB.Delete(&existingOTP).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete OTP",
		})
		return
	}

	// Generate JWT Token using the separate function
	token, err := utils.GenerateJWT(existingOTP.ID, userEmail, false)
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
		600,
		"/",
		"",
		false,
		true,
	)

	// OTP verification successful
	c.JSON(http.StatusOK, gin.H{
		"message": "OTP verified successfully",
	})
}

// otp resend
func ResendOTP(c *gin.Context) {
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

	// Extract userID from the "sub" claim
	userEmail, _ := (*claims)["email"].(string)

	// Check if the email exists in the database
	var existingUser models.User
	if err := database.DB.Where("email = ?", userEmail).First(&existingUser).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email not found",
		})
		return
	}

	// Check if an OTP already exists for this user
	var existingOTP models.OTP
	if err := database.DB.Where("user_id = ?", existingUser.ID).First(&existingOTP).Error; err == nil {
		// If an OTP exists, delete it
		if err := database.DB.Delete(&existingOTP).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove existing OTP",
			})
			return
		}
	}

	otpCode := utils.GenerateOTP()

	// Create OTP instance
	otp := models.OTP{
		UserID:    existingUser.ID, // Foreign key linking to the user
		Code:      otpCode,
		ExpiresAt: time.Now().Add(time.Second * 50),
		CreatedAt: time.Now(),
	}

	// Save OTP to the database
	if err := database.DB.Create(&otp).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create OTP",
		})
		return
	}

	// Load and render the email template
	tmpl, err := utils.LoadTemplate("templates/otp_email_template.html")
	if err != nil {
		log.Printf("Error loading template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load email template",
		})
		return
	}

	// Render the template with context
	ctx := map[string]interface{}{"OTP": otpCode}
	renderedBody, err := tmpl.Execute(ctx)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to render email template",
		})
		return
	}

	client := postmark.NewClient(os.Getenv("SERVER_TOKEN"), os.Getenv("ACCOUNT_TOKEN"))

	email := postmark.Email{
		From:       "mote.sai@todaypay.me",
		To:         existingUser.Email,
		Subject:    "Reset your password",
		HTMLBody:   renderedBody,
		TextBody:   "",
		Tag:        "pw-reset",
		TrackOpens: true,
	}

	_, err = client.SendEmail(context.Background(), email)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send email",
		})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Password reset email resent successful",
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
