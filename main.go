package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

type Article struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

type Authentication struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
	Salt     []byte `json:"salt"`
}

type AuthDB struct {
	JWTKey          string `json:"jwtkey"`
	Authentications []Authentication
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JWTToken struct {
	Token string `json:"token"`
}

type Claim struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var tlsKey string = "tls/tls.key"
var tlsCert string = "tls/tls.crt"

func homepage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Welcome to homepage</h1>")
}

func getAllArticles(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Bearer token required")
		log.Println("Status:", http.StatusBadRequest, "Empty bearer token")
		return
	}

	authHeaderSplit := strings.Split(authHeader, " ")

	if len(authHeaderSplit) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid token format")
		log.Println("Status:", http.StatusBadRequest, "Invalid token format")
		return
	}

	tokenString := authHeaderSplit[1]

	err := validateJWT(tokenString)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("Invalid token")
		log.Println("Status:", http.StatusUnauthorized, "Invalid token")
		return
	}

	dbFile, err := ioutil.ReadFile("db.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to read database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read database")
		return
	}

	// json.NewEncoder(w).Encode(Articles)
	fmt.Fprintf(w, "%v", string(dbFile))
	log.Println("Status:", http.StatusOK, "OK")
}

func getArticle(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Bearer token required")
		log.Println("Status:", http.StatusBadRequest, "Empty bearer token")
		return
	}

	authHeaderSplit := strings.Split(authHeader, " ")

	if len(authHeaderSplit) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid token format")
		log.Println("Status:", http.StatusBadRequest, "Invalid token format")
		return
	}

	tokenString := authHeaderSplit[1]

	err := validateJWT(tokenString)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("Invalid token")
		log.Println("Status:", http.StatusUnauthorized, "Invalid token")
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var Articles []Article

	dbFile, err := ioutil.ReadFile("db.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to read database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read database")
		return
	}

	json.Unmarshal(dbFile, &Articles)

	for _, article := range Articles {
		if intid, _ := strconv.Atoi(id); intid == article.ID {
			json.NewEncoder(w).Encode(article)
			log.Println("Status:", http.StatusOK, "OK")
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	log.Println("Status:", http.StatusNotFound, "No article found with id", id)
	fmt.Fprintf(w, "No article found with id %v", id)
}

func addArticle(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Bearer token required")
		log.Println("Status:", http.StatusBadRequest, "Empty bearer token")
		return
	}

	authHeaderSplit := strings.Split(authHeader, " ")

	if len(authHeaderSplit) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid token format")
		log.Println("Status:", http.StatusBadRequest, "Invalid token format")
		return
	}

	tokenString := authHeaderSplit[1]

	err := validateJWT(tokenString)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("Invalid token")
		log.Println("Status:", http.StatusUnauthorized, "Invalid token")
		return
	}

	var Articles []Article

	dbFile, err := ioutil.ReadFile("db.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to read database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read database")
		return
	}

	json.Unmarshal(dbFile, &Articles)

	reqBody, _ := ioutil.ReadAll(r.Body)
	var article Article
	json.Unmarshal(reqBody, &article)

	Articles = append(Articles, article)
	updatedData, err := json.Marshal(&Articles)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to update database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to update database")
		return
	}

	err = ioutil.WriteFile("db.json", updatedData, 0664)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to update database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to update database")
		return
	}

	json.NewEncoder(w).Encode(article)
	log.Println("Status:", http.StatusOK, "OK")
}

func deleteArticle(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Bearer token required")
		log.Println("Status:", http.StatusBadRequest, "Empty bearer token")
		return
	}

	authHeaderSplit := strings.Split(authHeader, " ")

	if len(authHeaderSplit) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid token format")
		log.Println("Status:", http.StatusBadRequest, "Invalid token format")
		return
	}

	tokenString := authHeaderSplit[1]

	err := validateJWT(tokenString)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("Invalid token")
		log.Println("Status:", http.StatusUnauthorized, "Invalid token")
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var Articles []Article

	dbFile, err := ioutil.ReadFile("db.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to read database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read database")
		return
	}

	json.Unmarshal(dbFile, &Articles)

	for i, article := range Articles {
		if intid, _ := strconv.Atoi(id); intid == article.ID {
			Articles = append(Articles[:i], Articles[i+1:]...)
			updatedData, err := json.Marshal(&Articles)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Failed to update database")
				log.Println("Status:", http.StatusInternalServerError, "Failed to update database")
				return
			}
			ioutil.WriteFile("db.json", updatedData, 0664)
			json.NewEncoder(w).Encode(Articles)
			log.Println("Status:", http.StatusOK, "OK")
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "No article found with id %v", id)
	log.Println("Status:", http.StatusNotFound, "No article found with id", id)
}

func updateArticle(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Bearer token required")
		log.Println("Status:", http.StatusBadRequest, "Empty bearer token")
		return
	}

	authHeaderSplit := strings.Split(authHeader, " ")

	if len(authHeaderSplit) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode("Invalid token format")
		log.Println("Status:", http.StatusBadRequest, "Invalid token format")
		return
	}

	tokenString := authHeaderSplit[1]

	err := validateJWT(tokenString)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("Invalid token")
		log.Println("Status:", http.StatusUnauthorized, "Invalid token")
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var Articles []Article

	reqBody, _ := ioutil.ReadAll(r.Body)
	var data Article
	json.Unmarshal(reqBody, &data)

	dbFile, err := ioutil.ReadFile("db.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Failed to read database")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read database")
		return
	}

	json.Unmarshal(dbFile, &Articles)

	for i, article := range Articles {
		if intid, _ := strconv.Atoi(id); intid == article.ID {
			Articles = append(Articles[:i], Articles[i+1:]...)
			Articles = append(Articles, data)
			updatedData, err := json.Marshal(&Articles)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Failed to update database")
				log.Println("Status:", http.StatusInternalServerError, "Failed to update database")
				return
			}
			err = ioutil.WriteFile("db.json", updatedData, 0664)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Failed to update database")
				log.Println("Status:", http.StatusInternalServerError, "Failed to update database")
				return
			}
			json.NewEncoder(w).Encode(data)
			log.Println("Status:", http.StatusOK, "OK")
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "No article found with id %v", id)
	log.Println("Status:", http.StatusNotFound, "No article found with id", id)
}

func signUp(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)
	bodyContent, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var Auth AuthDB
	var reqUserPass Credential

	json.Unmarshal(bodyContent, &reqUserPass)

	// Read auth database
	authDb, err := ioutil.ReadFile("auth.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read authentication database")
		return
	}

	json.Unmarshal(authDb, &Auth)

	for _, creds := range Auth.Authentications {
		if creds.Username == reqUserPass.Username {
			json.NewEncoder(w).Encode("User already exists")
			w.WriteHeader(http.StatusOK)
			log.Println("Status:", http.StatusOK, "OK")
			return
		}
	}

	salt, err := generateSalt(8)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to generate salt")
		return
	}

	hashedPassword, err := generateHash(reqUserPass.Password, salt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to generate hashed password")
		return
	}

	Auth.Authentications = append(Auth.Authentications, Authentication{Username: reqUserPass.Username, Password: hashedPassword, Salt: salt})
	updatedAuth, err := json.Marshal(&Auth)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to update auth database")
		return
	}

	err = ioutil.WriteFile("auth.json", updatedAuth, 0664)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to update auth database")
		return
	}
	json.NewEncoder(w).Encode("Sign Up successful.")
	log.Println("Status:", http.StatusOK, "OK")
}

func login(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)
	bodyContent, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read request body")
		return
	}

	var Auth AuthDB
	var reqUserPass Credential

	json.Unmarshal(bodyContent, &reqUserPass)

	// Read auth database
	authDb, err := ioutil.ReadFile("auth.json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode("Something went wrong")
		log.Println("Status:", http.StatusInternalServerError, "Failed to read authentication database")
		return
	}

	json.Unmarshal(authDb, &Auth)

	for _, creds := range Auth.Authentications {
		if creds.Username == reqUserPass.Username {
			hashedPassword, err := generateHash(reqUserPass.Password, creds.Salt)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Something went wrong")
				log.Println("Status:", http.StatusInternalServerError, "Failed to generate hashed password")
				return
			}

			if !bytes.Equal(hashedPassword, creds.Password) {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode("Invalid credentials")
				log.Println("Status:", http.StatusUnauthorized, "Incorrect password")
				return
			}

			w.WriteHeader(http.StatusOK)
			signedToken, err := generateJWT(reqUserPass.Username)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Something went wrong")
				log.Println("Status:", http.StatusInternalServerError, "Failed to generate JWT")
				return
			}

			var token JWTToken
			token.Token = signedToken
			json.NewEncoder(w).Encode(token)
			log.Println("Status:", http.StatusOK, "OK")
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode("User not found")
	log.Println("Status:", http.StatusUnauthorized, "User not found")
}

func generateSalt(size int) ([]byte, error) {
	token := make([]byte, size) // size bytes = size * 8 bits salt
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func generateHash(data string, salt []byte) ([]byte, error) {
	dataBytes := []byte(data)

	// fmt.Println(dataBytes)
	// fmt.Println(salt)

	hash, err := scrypt.Key(dataBytes, salt, 32768, 8, 1, 32) // Generates 32 bytes hash using scrypt kdf

	if err != nil {
		return nil, err
	}

	return hash, nil

}

func updateJWTKey() error {

	log.Println("Updating JWT key")

	var Auth AuthDB

	key, err := generateSalt(32) // Generate 256 bit random key
	if err != nil {
		log.Println("Failed to generate JWT key")
		return err
	}

	authDb, err := ioutil.ReadFile("auth.json")
	if err != nil {
		log.Println("Failed to read auth database")
		return err
	}

	json.Unmarshal(authDb, &Auth)

	Auth.JWTKey = hex.EncodeToString(key)

	updatedData, err := json.Marshal(&Auth)
	if err != nil {
		log.Println("Failed to update jwt key")
		return err
	}

	err = ioutil.WriteFile("auth.json", updatedData, 0664)
	if err != nil {
		log.Println("Failed to write to auth database")
		return err
	}

	return nil
}

func generateJWT(username string) (string, error) {
	var Auth AuthDB

	authDb, err := ioutil.ReadFile("auth.json")
	if err != nil {
		log.Println("Failed to read auth database")
		return "", err
	}

	json.Unmarshal(authDb, &Auth)

	signingKey := []byte(Auth.JWTKey)

	expirationTime := time.Now().Add(time.Minute * 15).Unix() // 15 Minutes from the current time

	claims := Claim{
		username,
		jwt.StandardClaims{
			ExpiresAt: expirationTime,
			Issuer:    "RestAPI_Go.Navratan",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		log.Println("Failed sign the token")
		return "", err
	}

	return signedToken, nil
}

func validateJWT(tokenString string) error {
	var Auth AuthDB

	authDb, err := ioutil.ReadFile("auth.json")
	if err != nil {
		log.Println("Status:", http.StatusInternalServerError, "Failed to read auth database")
		return err
	}

	json.Unmarshal(authDb, &Auth)

	signingKey := []byte(Auth.JWTKey)

	token, err := jwt.ParseWithClaims(tokenString, &Claim{}, func(tokenString *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})

	if _, ok := token.Claims.(*Claim); ok && token.Valid {
		return nil
	} else {
		log.Println("Status:", http.StatusUnauthorized, "Unauthorized")
		return err
	}

}

func handleRequests() {

	tlsFlag := flag.Bool("tls", false, "--tls=true|false Default: false")
	flag.Parse()

	// New router of mux
	router := mux.NewRouter().StrictSlash(true)

	// Home page
	router.HandleFunc("/", homepage)

	// Get all articles
	router.HandleFunc("/articles", getAllArticles).Methods("GET")

	// Get an article filtered by id
	router.HandleFunc("/article/{id}", getArticle).Methods("GET")

	// Add new article
	router.HandleFunc("/article", addArticle).Methods("POST")

	// Delete an article
	router.HandleFunc("/article/{id}", deleteArticle).Methods("DELETE")

	// Update an article
	router.HandleFunc("/article/{id}", updateArticle).Methods("PUT")

	// http.HandleFunc("/", homepage)
	// http.HandleFunc("/articles", getAllArticles)

	// Sign up

	router.HandleFunc("/signup", signUp).Methods("POST")

	// Login
	router.HandleFunc("/login", login).Methods("GET")

	if !*tlsFlag {
		fmt.Println("Starting server at port 30000")
		log.Fatal(http.ListenAndServe(":30000", router))
	} else {
		fmt.Println("Starting secure server at port 30443")
		log.Fatal(http.ListenAndServeTLS(":30443", tlsCert, tlsKey, router))
	}
}

func main() {
	updateJWTKey() // Generates and update new jwt key whenever server starts
	handleRequests()
}
