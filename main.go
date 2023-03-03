package main

import (
	"fmt"
	"net/http"

	"learnoauth/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("hello")

	ginRouter := gin.New()
	ginRouter.LoadHTMLGlob("templates/*.html")

	indexRouting := ginRouter.Group("/")
	{
		indexRouting.GET("", func(ctx *gin.Context) {
			ctx.HTML(http.StatusOK, "index.html", nil)
		})
	}

	handlers.RegisterAPIHandlers(ginRouter)

	ginRouter.Run(":8080")
}
