# api

The API is a library with some structs and a request wrapper. Also a work in
progress.

## Exported Functions and Types
The TS CLI exports a few Go functions and types - those are available under the api
directory.

Here's an example of how you could call the API on your own.
```
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	tsapi "github.com/threatstack/ts/api"
)

func main() {
	config := tsapi.Config{
		User: "USER_ID",
		Key:  "API_KEY",
		Org:  "ORG_ID",
	}
	client := &http.Client{}
	agentEndpoint := "/v2/agents/d1230d0f-392b-1ee9-b92a-5b6ae75feb22"
	req, err := tsapi.Request(config, "GET", agentEndpoint, nil)
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
		fmt.Printf("Unable to GET %s - API responded with an HTTP/%d", agentEndpoint, resp.StatusCode)
		os.Exit(1)
	}
}
```