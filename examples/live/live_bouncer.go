package main

import (
	"fmt"
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {
	// You can pass parameters to the bouncer constructor
	// bouncer := &csbouncer.LiveBouncer{
	//	APIKey: "ebd4db481d51525fd0df924a69193921",
	//		APIUrl: "http://localhost:8080/",
	//	}

	// Or you can also use the Config() method with a path to a config file

	bouncer := &csbouncer.LiveBouncer{}

	err := bouncer.Config("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	ipToQuery := "1.2.3.4"
	response, err := bouncer.Get(ipToQuery)
	if err != nil {
		log.Fatalf("unable to get decision for ip '%s' : '%s'", ipToQuery, err)
	}
	if len(*response) == 0 {
		log.Printf("no decision for '%s'", ipToQuery)
	}

	for _, decision := range *response {
		fmt.Printf("decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
	}
}
