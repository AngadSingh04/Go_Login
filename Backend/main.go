package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var ctx = context.Background()

func connectDB() (*pgx.Conn, *redis.Client) {

	conn, err := pgx.Connect(ctx, "postgres://postgres:Angad@04@localhost:5432/authdb")
	if err != nil {
		log.Fatal("Unable to connect to PostgreSQL:", err)
	}


	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	return conn, redisClient
}

func main() {
	conn, redisClient := connectDB()
	defer conn.Close(ctx)
	defer redisClient.Close()

	router := mux.NewRouter()
	router.HandleFunc("/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/login", LoginHandler).Methods("POST")

	log.Println("Starting server on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	conn, _ := connectDB()
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, "INSERT INTO users (email, password) VALUES ($1, $2)", email, hashedPassword)
	if err != nil {
		log.Printf("Error saving user to the database: %v", err)
		http.Error(w, "Error saving user to the database", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Registration successful")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	conn, _ := connectDB()
	defer conn.Close(ctx)

	var hashedPassword string
	err := conn.QueryRow(ctx, "SELECT password FROM users WHERE email=$1", email).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if !checkPasswordHash(password, hashedPassword) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Login successful")
}
