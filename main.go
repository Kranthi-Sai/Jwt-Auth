package main

import (
	"net/http"
	"Jwt-Auth/database"
	"Jwt-Auth/initializer"
	

  "github.com/gin-gonic/gin"
)

func main() {
	r:=gin.Default()
	initializer.LoadEnvVariables()
	_,err:= database.ConnectDB()
	if err!=nil{
		panic("Database not Connected")
	}
	r.GET("/register",func(c *gin.Context){
		c.JSON(http.StatusOK,gin.H{
			"message":"register SuccessFully",
		})
	})
	r.Run();
  }