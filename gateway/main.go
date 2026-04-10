package main

import (
	app "gateway/src/app"
	"log"
)

func main() {
	if err := app.Run(); err != nil {
		log.Fatalf("gateway startup failed: %v", err)
	}
}
