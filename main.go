package main

import (
	"Jwt-Auth/controllers"
	"Jwt-Auth/database"
	"Jwt-Auth/initializer"
	"Jwt-Auth/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	initializer.LoadEnvVariables()
	_, err := database.ConnectDB()
	if err != nil {
		panic("Database not Connected")
	}
	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)
	// Apply middleware to a group of routes
	protected := r.Group("/protected")
	protected.Use(middleware.JWTAuthMiddleware())
	{
		protected.GET("/user", controllers.User)
		protected.GET("/user/:id", controllers.GetUserById)
		protected.GET("/users", controllers.GetAllUsers)
	}

	r.Run()
}
