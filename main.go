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
	p1 := person{
		First: "Frida",
	}

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

	http.HandleFunc("/encode", encodeFunc)
	http.HandleFunc("/decode", decodeFunc)
	http.ListenAndServe(":8080", nil)
}

func encodeFunc(w http.ResponseWriter, r *http.Request) {

}

func decodeFunc(w http.ResponseWriter, r *http.Request) {

}
