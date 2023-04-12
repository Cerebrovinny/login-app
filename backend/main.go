package main

import (
	"github.com/Cerebrovinny/login-app/handlers"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", handlers.LoginHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
