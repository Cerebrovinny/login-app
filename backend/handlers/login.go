package handlers

import (
	"context"
	"encoding/json"
	"github.com/Cerebrovinny/login-app/config"
	"github.com/Cerebrovinny/login-app/models"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"os"
	"sync"
	"time"
)

type rateLimiter struct {
	attempts      map[string]int
	lastAttempt   map[string]time.Time
	lock          sync.Mutex
	maxAttempts   int
	resetInterval time.Duration
}

func newRateLimiter(maxAttempts int, resetInterval time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts:      make(map[string]int),
		lastAttempt:   make(map[string]time.Time),
		lock:          sync.Mutex{},
		maxAttempts:   maxAttempts,
		resetInterval: resetInterval,
	}
}

func (rl *rateLimiter) exceeded(username string) bool {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	now := time.Now()

	if last, ok := rl.lastAttempt[username]; ok && now.Sub(last) > rl.resetInterval {
		rl.attempts[username] = 0
	}

	if rl.attempts[username] >= rl.maxAttempts {
		return true
	}

	rl.attempts[username]++
	rl.lastAttempt[username] = now

	return false
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtKey = []byte(os.Getenv("JWT_KEY"))

func getUser(username string) (models.User, error) {
	db, err := config.GetDatabase()
	if err != nil {
		return models.User{}, err
	}

	client, err := config.GetMongoClient()
	if err != nil {
		return models.User{}, err
	}
	defer client.Disconnect(context.Background())

	collection := db.Collection("users")
	var user models.User
	err = collection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
	return user, err
}

var loginRateLimiter = newRateLimiter(5, 1*time.Minute)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"message": "Method not allowed"})
		return
	}

	var creds models.Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid request payload"})
		return
	}

	if loginRateLimiter.exceeded(creds.Username) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"message": "Too many login attempts. Please try again later."})
		return
	}

	user, err := getUser(creds.Username)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid username or password"})
		return
	}

	err = models.CheckPassword(user.Password, creds.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid username or password"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error generating token"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful!"})
}
