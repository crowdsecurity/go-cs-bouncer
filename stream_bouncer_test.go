package csbouncer_test

import (
	"context"
	"fmt"
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func ExampleStreamBouncer() {
	bouncer := &csbouncer.StreamBouncer{
		APIKey: "ebd4db481d51525fd0df924a69193921",
		APIUrl: "http://localhost:8080/",
	}

	if err := bouncer.Init(); err != nil {
		log.Fatal(err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		bouncer.Run(ctx)
		cancel()
	}()

	for streamDecision := range bouncer.Stream {
		for _, decision := range streamDecision.Deleted {
			fmt.Printf("expired decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
		for _, decision := range streamDecision.New {
			fmt.Printf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}
}

func ExampleStreamBouncer_Config() {
	bouncer := &csbouncer.StreamBouncer{}

	err := bouncer.Config("./config.yaml")

	if err != nil {
		log.Fatal(err)
	}

	if err := bouncer.Init(); err != nil {
		log.Fatal(err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		bouncer.Run(ctx)
		cancel()
	}()

	for streamDecision := range bouncer.Stream {
		for _, decision := range streamDecision.Deleted {
			fmt.Printf("expired decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
		for _, decision := range streamDecision.New {
			fmt.Printf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
		}
	}
}
