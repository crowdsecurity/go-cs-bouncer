package main

import (
	"fmt"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         "b7c192ded4cce750cc66dbf42c0dba19",
		APIUrl:         "http://localhost:8080/",
		TickerInterval: "2s",
		Opts: apiclient.DecisionsStreamOpts{
			Origins: "capi",
		},
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
