package main

import (
	"fmt"
	"github.com/Accelbyte/ic-go-sdk"
	"github.com/sirupsen/logrus"
)

/*
*
this is an example to use ic-go-sdk
*/
func main() {
	cfg := &ic.Config{
		BaseURL:      "{ic-address}/ic",
		ClientID:     "{client-id}",
		ClientSecret: "{client-secret}",
	}
	client := ic.NewDefaultClient(cfg)

	// check if ic-go-sdk works
	_, err := client.ClientToken()
	if err != nil {
		logrus.Fatalf("ic-go-sdk start err: %v \n", err)
	}

	//
	testToken := "{ic-access_token}"
	claim, err := client.ValidateAndParseClaims(testToken)
	fmt.Printf("assert nil check error: %v  \n", err)

	valid, err := client.ValidateAccessToken(testToken)
	fmt.Printf("assert nil validate error: : %v  \n", err)
	fmt.Printf("valid: %v  \n", valid)

	requiredP := ic.Permission{
		Resource: "ADMIN:ORG:{organizationId}:PROJ:{projectId}:*",
		Action:   2,
	}
	valid, err = client.ValidatePermission(claim, requiredP, map[string]string{"{organizationId}": "56305451c6b54e2d805e1e47ab2b98c4", "{projectId}": "028a281b05ea40d19f52573c97b1ede8"})
	fmt.Printf("assert nil permission check err: %v  \n", err)
	fmt.Printf("match permission check: %v  \n", valid)

	fmt.Printf("\n")
}
