package main

import (
	app "certification_server/src/app"
	"log"
)

func main() {
	if err := app.Run(); err != nil {
		log.Fatalf("certification_server startup failed: %v", err)
	}
}
