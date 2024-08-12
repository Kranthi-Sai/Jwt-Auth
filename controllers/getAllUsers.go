package controllers

import (
	"Jwt-Auth/database"
	"Jwt-Auth/models"
	"net/http"

	"github.com/gin-gonic/gin"
)


func GetAllUsers(c *gin.Context) {
	var users []models.User

	// Query to get all users
	if err := database.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve users",
		})
		return
	}

	c.JSON(http.StatusOK, users)
}