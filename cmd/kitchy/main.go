package main

import (
	"log"

	"github.com/tmitchel/kitchy"
)

func main() {
	db, err := kitchy.OpenDatabase()
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	server, err := kitchy.NewServer(db)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}

	log.Fatal(server.Server.ListenAndServe())
}
