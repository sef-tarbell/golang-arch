package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {
	http.HandleFunc("/encode", encodeFunc)
	http.HandleFunc("/decode", decodeFunc)
	http.ListenAndServe(":8080", nil)
}

func encodeFunc(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		First: "Donna",
	}

	p2 := person{
		First: "Bart",
	}

	people := []person{p1, p2}

	err := json.NewEncoder(w).Encode(people)
	if err != nil {
		log.Println("Error while encoding people", err)
	}
}

func decodeFunc(w http.ResponseWriter, r *http.Request) {
	var people []person
	err := json.NewDecoder(r.Body).Decode(&people)
	if err != nil {
		log.Println("Error while decoding", err)
	}

	fmt.Println("People: ", people)
}
