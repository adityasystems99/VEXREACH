package main

import (
	"net/http"

	gyaml "gopkg.in/yaml.v2"
)

func ParseConfigHandler(w http.ResponseWriter, r *http.Request) {
	go func() {
		_ = gyaml.Unmarshal([]byte("key: value"), nil)
	}()
	_, _ = w.Write([]byte("accepted"))
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

func main() {
	http.HandleFunc("/parse", ParseConfigHandler)
	http.HandleFunc("/healthz", HealthHandler)
}
