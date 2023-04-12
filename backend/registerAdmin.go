package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Cerebrovinny/login-app/config"
	"github.com/Cerebrovinny/login-app/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func createAdminUser() error {
	db, err := config.GetDatabase()
	if err != nil {
		return fmt.Errorf("Error connecting to the database: %w", err)
	}

	client, err := config.GetMongoClient()
	if err != nil {
		return fmt.Errorf("Error connecting to the database: %w", err)
	}
	defer client.Disconnect(context.Background())

	collection := db.Collection("users")

	//Admin cred
	adminUsername := "admin"
	adminPassword := "admin123"

	// Hash the admin password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("Error hashing password: %w", err)
	}

	// Check if the admin user already exists
	var existingUser models.User
	err = collection.FindOne(context.Background(), bson.M{"username": adminUsername}).Decode(&existingUser)

	// If the admin user doesn't exist, create it
	if err == mongo.ErrNoDocuments {
		adminUser := models.User{
			Username: adminUsername,
			Password: string(hashedPassword),
		}
		_, err = collection.InsertOne(context.Background(), adminUser)
		if err != nil {
			return fmt.Errorf("Error inserting admin user: %w", err)
		}
		fmt.Println("Admin user created.")
	} else if err == nil {
		fmt.Println("Admin user already exists.")
	} else {
		return fmt.Errorf("Error checking for existing admin user: %w", err)
	}

	return nil
}

func main() {
	err := createAdminUser()
	if err != nil {
		log.Fatal(err)
	}
}
