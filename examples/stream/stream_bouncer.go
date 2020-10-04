package main

import (
	"fmt"
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         "ebd4db481d51525fd0df924a69193921",
		APIUrl:         "http://localhost:8080/",
		TickerInterval: "20s",
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	for {
		select {
		case decision := <-bouncer.NewDecision:
			// Do some stuff with new decisions
			fmt.Printf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		case decision := <-bouncer.ExpiredDecision:
			// do some stuff with expired decisions
			fmt.Printf("old decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}
}
