package main

import (
	"fmt"
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {

	//You can pass parameters to the bouncer constructor
	//bouncer := &csbouncer.StreamBouncer{
	//	APIKey: "ebd4db481d51525fd0df924a69193921",
	//		APIUrl: "http://localhost:8080/",
	//	}

	//Or you can also use the Config() method with a path to a config file

	bouncer := &csbouncer.StreamBouncer{}

	err := bouncer.Config("./config.yaml")

	if err != nil {
		log.Fatal(err)
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	for streamDecision := range bouncer.Stream {
		for _, decision := range streamDecision.Deleted {
			fmt.Printf("expired decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
		for _, decision := range streamDecision.New {
			fmt.Printf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}
}
