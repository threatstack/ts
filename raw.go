// ts - golang ts api client
// raw.go: send raw commands to the API
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

func raw(c *cli.Context) {
	if c.Args().Get(0) == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("ERROR: Specify endpoint as first argument\n")
		os.Exit(1)
	}

	if c.String("request") != "GET" && c.String("data") == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("ERROR: You specified a Write API call (not GET) and didn't specify a payload\n")
		os.Exit(1)
	}

	if c.String("request") == "GET" && c.String("data") != "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("ERROR: You specified a GET request... but you specified data too. Huh?\n")
		os.Exit(1)
	}

	payload := []byte(c.String("data"))

	client := &http.Client{}
	if c.Bool("debug") {
		fmt.Printf("* HTTP %s: %s\n", c.String("request"), c.GlobalString("endpoint")+c.Args().Get(0))
		if c.String("data") != "" {
			fmt.Printf("* Payload: %s\n", c.String("data"))
		}
	}
	req, err := tsBuildHTTPReq(c, c.String("request"), c.Args().Get(0), payload)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if resp.StatusCode == 200 {
		fmt.Printf("%s\n", body)
	} else {
		fmt.Printf("The API responded with an HTTP/%d.\n", resp.StatusCode)
		var errResponse tsapi.Error
		if err := json.Unmarshal(body, &errResponse); err != nil {
			log.Fatalln(err)
		} else {
			for _, v := range errResponse.Errors {
				fmt.Printf("* %s\n", v)
			}
		}
	}
}
