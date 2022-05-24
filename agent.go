// ts - golang ts api client
// agents.go: list all your agents, or just one of them
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	tsapi "github.com/threatstack/ts/api"
	"github.com/urfave/cli"
)

func getAgents(c *cli.Context, online bool) {
	var agents []tsapi.Agent
	var tokenString string
	client := &http.Client{}
	agentEndpoint := "/v2/agents?status=online"
	if !online {
		agentEndpoint = "/v2/agents?status=offline"
	}
	for {
		var response tsapi.AgentResponseRaw
		req, err := tsBuildHTTPReq(c, "GET", agentEndpoint+tokenString, nil)
		if err != nil {
			log.Fatalln(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalln(err)
			}
			if err := json.Unmarshal(body, &response); err != nil {
				log.Fatalln(err)
			}

			agents = append(agents, response.Agents...)

			if response.Token != "" {
				tokenString = fmt.Sprintf("&token=%s", response.Token)
			} else {
				break
			}
		} else {
			fmt.Printf("Unable to query %s - API responded with a %d", agentEndpoint+tokenString, resp.StatusCode)
			os.Exit(1)
		}
	}

	ser, err := json.Marshal(agents)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(ser))
}

func getAgent(c *cli.Context) {
	if c.Args().Get(0) == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Specify the Agent ID you want to look up as an argument.\n")
		os.Exit(1)
	}

	client := &http.Client{}
	agentEndpoint := fmt.Sprintf("/v2/agents/%s", c.Args().Get(0))
	req, err := tsBuildHTTPReq(c, "GET", agentEndpoint, nil)
	if err != nil {
		log.Fatalln(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%s\n", body)
	} else {
		fmt.Printf("Unable to query %s - API responded with an HTTP/%d", agentEndpoint, resp.StatusCode)
		os.Exit(1)
	}
}
