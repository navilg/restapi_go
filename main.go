package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

type Article struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

var Articles []Article

func homepage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Welcome to homepage</h1>")
}

func getAllArticles(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.Proto, r.Host)
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
	vars := mux.Vars(r)
	id := vars["id"]

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

	vars := mux.Vars(r)
	id := vars["id"]

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
	vars := mux.Vars(r)
	id := vars["id"]

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
	fmt.Println("Starting server at port 30000")
	if !*tlsFlag {
		log.Fatal(http.ListenAndServe(":30000", router))
	}
}

func main() {

	handleRequests()
}
