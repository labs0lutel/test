package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	IsActive bool   `json:"isActive"`
	IsAdmin  bool   `json:"isAdmin"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	User         User   `json:"user"`
}

type JWTClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	users     = make(map[int]User)
	usersBy   = make(map[string]int)
	mutex     sync.RWMutex
	nextID    = 1
	jwtSecret = []byte("your-secret-key")
)

func main() {
	http.HandleFunc("/api/auth/register", registerHandler)
	http.HandleFunc("/api/auth/login", loginHandler)
	http.HandleFunc("/api/auth/refresh", refreshHandler)
	http.HandleFunc("/api/auth/logout", logoutHandler)
	http.HandleFunc("/api/auth/me", authMiddleware(meHandler))
	http.HandleFunc("/api/users", authMiddleware(adminMiddleware(usersListHandler)))
	http.HandleFunc("/api/users/", authMiddleware(adminMiddleware(userDetailHandler)))
	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID int) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User-ID", strconv.Itoa(claims.UserID))
		next(w, r)
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))
		mutex.RLock()
		user, ok := users[userID]
		mutex.RUnlock()
		if !ok || !user.IsAdmin {
			http.Error(w, `{"error": "Admin access required"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func validateRegistration(username, email, password string) string {
	if len(username) < 3 || len(username) > 20 || !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(username) {
		return "Invalid username"
	}
	if !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return "Invalid email"
	}
	if len(password) < 6 || !regexp.MustCompile(`[0-9]`).MatchString(password) || !regexp.MustCompile(`[A-Za-z]`).MatchString(password) {
		return "Invalid password"
	}
	return ""
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if msg := validateRegistration(req.Username, req.Email, req.Password); msg != "" {
		http.Error(w, `{"error": "`+msg+`"}`, http.StatusBadRequest)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	if _, exists := usersBy[req.Username]; exists {
		http.Error(w, `{"error": "Username already exists"}`, http.StatusConflict)
		return
	}
	if _, exists := usersBy[req.Email]; exists {
		http.Error(w, `{"error": "Email already exists"}`, http.StatusConflict)
		return
	}
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error": "Error hashing password"}`, http.StatusInternalServerError)
		return
	}
	isAdmin := false
	if nextID == 1 {
		isAdmin = true
	}
	user := User{
		ID:       nextID,
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		IsActive: true,
		IsAdmin:  isAdmin,
	}
	users[nextID] = user
	usersBy[req.Username] = nextID
	usersBy[req.Email] = nextID
	nextID++
	token, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := generateToken(user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if (req.Username == "" && req.Email == "") || req.Password == "" {
		http.Error(w, `{"error": "Username/email and password are required"}`, http.StatusBadRequest)
		return
	}
	mutex.RLock()
	var userID int
	var exists bool
	if req.Username != "" {
		userID, exists = usersBy[req.Username]
	} else {
		userID, exists = usersBy[req.Email]
	}
	if !exists {
		mutex.RUnlock()
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	user := users[userID]
	mutex.RUnlock()
	if !user.IsActive || !checkPasswordHash(req.Password, user.Password) {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	token, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := generateToken(user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
	})
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
		return
	}
	mutex.RLock()
	user, exists := users[claims.UserID]
	mutex.RUnlock()
	if !exists || !user.IsActive {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}
	newToken, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}
	refreshToken, _ := generateToken(user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token:        newToken,
		RefreshToken: refreshToken,
		User:         user,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))
	mutex.RLock()
	user, exists := users[userID]
	mutex.RUnlock()
	if !exists {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func usersListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	mutex.RLock()
	defer mutex.RUnlock()
	list := []User{}
	for _, u := range users {
		list = append(list, u)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func userDetailHandler(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid ID"}`, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case "GET":
		mutex.RLock()
		user, ok := users[id]
		mutex.RUnlock()
		if !ok {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	case "PUT":
		var req User
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		mutex.Lock()
		user, ok := users[id]
		if !ok {
			mutex.Unlock()
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}
		if req.Username != "" {
			user.Username = req.Username
		}
		if req.Email != "" {
			user.Email = req.Email
		}
		user.IsActive = req.IsActive
		user.IsAdmin = req.IsAdmin
		users[id] = user
		mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	case "DELETE":
		mutex.Lock()
		if _, ok := users[id]; !ok {
			mutex.Unlock()
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}
		delete(users, id)
		mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
	default:
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
