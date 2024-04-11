package main

//write a basic web server

import (
	"fmt"
	"net/http"
	"os"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello World!")
}

func appsecMiddleware(appsec *csbouncer.AppSec, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appsecRes, err := appsec.Forward(r)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error"))
			return
		}
		if appsecRes != nil && appsecRes.Response.StatusCode > 200 {
			if appsecRes.HTTPStatus > 0 {
				w.WriteHeader(appsecRes.HTTPStatus)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			fmt.Fprintf(w, "You have been blocked by appsec status: %d, action: %s", appsecRes.HTTPStatus, appsecRes.Action)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	appsec := &csbouncer.AppSec{}
	err := appsec.Config("./config.yaml")
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := appsec.Init(); err != nil {
		fmt.Println(err)
		return
	}

	http.HandleFunc("/", appsecMiddleware(appsec, http.HandlerFunc(handler)))
	http.ListenAndServe(os.Args[1], nil)
}

// Run this example with:
// go run main.go 127.0.0.1:9090
