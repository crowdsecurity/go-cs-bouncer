package main

import (
	"fmt"
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func boolPtr(x bool) *bool {
	return &x
}

func main() {
	bouncer := &csbouncer.LiveBouncer{
		APIUrl:             "https://localhost:8081/",
		CertPath:           "/home/seb/cfssl/bouncer.pem",
		KeyPath:            "/home/seb/cfssl/bouncer-key.pem",
		CAPath:             "/home/seb/cfssl/ca.pem",
		InsecureSkipVerify: boolPtr(true),
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
