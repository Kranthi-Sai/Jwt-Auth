package controllers

import (
	"Jwt-Auth/database"
	"Jwt-Auth/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetUserById (c *gin.Context){

	id := c.Param("id")

	// Check if the email exists in db
	var User models.User
	err := database.DB.Where("id= ?", id).First(&User).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "User is Not Found",
		})
		return
	}

	c.JSON(http.StatusFound,gin.H{
		"User": User,
	})

}