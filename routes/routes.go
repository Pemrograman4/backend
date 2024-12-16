package routes

import (
	"github.com/gorilla/mux"
	"myapi/controllers"
	"myapi/middleware"
)

func RegisterRoutes(router *mux.Router) {
	// Public route
	router.HandleFunc("/login", auth.Login).Methods("POST")
	// Route for user registration
	router.HandleFunc("/register", auth.Register).Methods("POST")

	// Protected routes (require JWT)
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(middleware.JWTMiddleware)
	protected.HandleFunc("/data", auth.GetData).Methods("GET")

}
