package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"myapi/config"
	"myapi/routes"
)

func main() {
	// Load MongoDB connection
	database.ConnectMongoDB()

	// Initialize router
	router := mux.NewRouter()

	// Define API routes
	routes.RegisterRoutes(router)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port
	}

	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
