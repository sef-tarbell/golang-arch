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
	/*
		p2 := person{
			First: "Marcus",
		}

		xp := []person{p1, p2}

		bs, err := json.Marshal(xp)
		if err != nil {
			log.Panic(err)
		}
		fmt.Println(string(bs))

		xp2 := []person{}

		err = json.Unmarshal(bs, &xp2)
		if err != nil {
			log.Panic(err)
		}
		fmt.Println("back into GO data", xp2)
	*/

	http.HandleFunc("/encode", encodeFunc)
	http.HandleFunc("/decode", decodeFunc)
	http.ListenAndServe(":8080", nil)
}

func encodeFunc(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		First: "Frida",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil {
		log.Println("Error while encoding", err)
	}
}

func decodeFunc(w http.ResponseWriter, r *http.Request) {
	var p1 person
	err := json.NewDecoder(r.Body).Decode(&p1)
	if err != nil {
		log.Println("Error while decoding", err)
	}

	fmt.Println("Person: ", p1)
}
