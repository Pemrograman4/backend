package main

import (
	"log"
	"net/http"
	"myapi/database"
	"myapi/handlers"

	"github.com/gorilla/mux"
)

func main() {
	// Connect to MongoDB
	database.ConnectMongoDB("mongodb://localhost:27017")

	// Setup Router
	r := mux.NewRouter()

	// Routes
	r.HandleFunc("/users", handlers.CreateUser).Methods("POST")
	r.HandleFunc("/users", handlers.GetUsers).Methods("GET")
	r.HandleFunc("/user", handlers.GetUser).Methods("GET")
	r.HandleFunc("/user", handlers.UpdateUser).Methods("PUT")
	r.HandleFunc("/user", handlers.DeleteUser).Methods("DELETE")

	// Start Server
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}