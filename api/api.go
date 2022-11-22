// ts - golang ts api client
// api/api.go: structs for the API endpoint, and the request builder
//
// Copyright 2019-2022 F5 Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.

package tsapi

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/tent/hawk-go"
)

// Error is used to display errors
type Error struct {
	Errors []string `json:"errors"`
}

// Config configures the API object
type Config struct {
	User string
	Key  string
	Org  string
}

// Request is a generic API client for sending authenticated requests
// to the Threat Stack API
func Request(config Config, method string, url string, payload []byte) (*http.Request, error) {
	payloadBuffer := bytes.NewBuffer(payload)
	req, err := http.NewRequest(method, url, payloadBuffer)
	if err != nil {
		return req, fmt.Errorf("unable to create TSAPIRequest: %s", err)
	}

	hawkCreds := &hawk.Credentials{
		ID:   config.User,
		Key:  config.Key,
		Hash: sha256.New,
	}

	auth := hawk.NewRequestAuth(req, hawkCreds, 0)
	auth.Ext = config.Org
	if len(payload) > 0 {
		// Need to hash the payload we're sending up.
		payloadHash := auth.PayloadHash("application/json")
		payloadHash.Write(payload)
		auth.SetHash(payloadHash)
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", auth.RequestHeader())
	req.Header.Set("Accept", "application/json")
	return req, nil
}
