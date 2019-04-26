// ts - golang ts api client
// agents.go: list all your agents, or just one of them
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	tsapi "github.com/threatstack/ts/api"
	"github.com/urfave/cli"
)

func getAlerts(c *cli.Context, active bool) {
	var alerts []tsapi.Alert
	var tokenString string
	client := &http.Client{}
	alertsEndpoint := "/v2/alerts?status=active"
	if !active {
		alertsEndpoint = "/v2/alerts?status=dismissed"
	}
	if c.String("severity") != "" {
		alertsEndpoint = alertsEndpoint + "&severity=" + c.String("severity")
	}
	if c.String("from") != "" {
		alertsEndpoint = alertsEndpoint + "&from=" + c.String("from")
	}
	if c.String("until") != "" {
		alertsEndpoint = alertsEndpoint + "&until=" + c.String("until")
	}
	for {
		var response tsapi.AlertResponseRaw
		req, err := tsBuildHTTPReq(c, "GET", alertsEndpoint+tokenString, nil)
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

			alerts = append(alerts, response.Alerts...)

			if response.Token != "" {
				tokenString = fmt.Sprintf("&token=%s", response.Token)
			} else {
				break
			}
		} else {
			fmt.Printf("Unable to query %s - API responded with a %d", alertsEndpoint+tokenString, resp.StatusCode)
			os.Exit(1)
		}
	}

	ser, err := json.Marshal(alerts)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(ser))
}

func getAlert(c *cli.Context) {
	if c.Args().Get(0) == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Specify the Alert ID you want to look up as an argument.\n")
		os.Exit(1)
	}

	client := &http.Client{}
	alertEndpoint := fmt.Sprintf("/v2/alerts/%s", c.Args().Get(0))
	req, err := tsBuildHTTPReq(c, "GET", alertEndpoint, nil)
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
		fmt.Printf("Unable to query %s - API responded with an HTTP/%d", alertEndpoint, resp.StatusCode)
		os.Exit(1)
	}
}

func countAlerts(c *cli.Context) {
	client := &http.Client{}
	alertsEndpoint := fmt.Sprintf("/v2/alerts/severity-counts")
	var first_param bool = true
	if c.String("from") != "" {
		alertsEndpoint = alertsEndpoint + "?from=" + c.String("from")
		first_param = false
	}
	if c.String("until") != "" {
		if first_param {
			alertsEndpoint = alertsEndpoint + "?until=" + c.String("until")
			first_param = false
		} else {
			alertsEndpoint = alertsEndpoint + "&until=" + c.String("until")
		}
	}
	req, err := tsBuildHTTPReq(c, "GET", alertsEndpoint, nil)
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
		fmt.Printf("Unable to query %s - API responded with an HTTP/%d", alertsEndpoint, resp.StatusCode)
	}
}

func getEvents(c *cli.Context) {
	if c.Args().Get(0) == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Specify the Alert ID you want to look up as an argument.\n")
		os.Exit(1)
	}
	client := &http.Client{}
	eventsEndpoint := fmt.Sprintf("/v2/alerts/%s/events", c.Args().Get(0))
	req, err := tsBuildHTTPReq(c, "GET", eventsEndpoint, nil)
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
		fmt.Printf("Unable to query %s - API responded with an HTTP/%d", eventsEndpoint, resp.StatusCode)
	}
}

func dismissAlertsByID(c *cli.Context) {
	client := &http.Client{}
	dismissAlertsEndpoint := "/v2/alerts/dismiss"
	validInput := true
	var errs []string

	if c.String("alertIDs") == "" {
		errs = append(errs, "Missing alert ID file")
		validInput = false
	}

	if c.String("dismissReason") == "" {
		errs = append(errs, "Missing dismiss reason")
		validInput = false
	}

	if c.String("dismissReasonText") == "" && c.String("dismissReason") == "OTHER"{
		errs = append(errs, "Dismiss reason OTHER entered, but no dismiss reason text provided")
		validInput = false
	}
	
	if c.String("dismissReasonText") != "" && c.String("dismissReason") != "OTHER"{
		errs = append(errs, "Dismiss reason text entered, but dismiss reason is not OTHER")
		validInput = false
	}

	if validInput == false {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Unable to create alert dismissal request.\n")
		for _, v := range errs {
			fmt.Printf("         * %s\n", v)
		}
		os.Exit(1)
	}

	file, err :=os.Open(c.String("alertIDs"))
	if err != nil {
		fmt.Printf("\nERROR: Unable to read alert IDs from %s", c.String("alertIDs"))
		os.Exit(1)
	}
	var alertIDs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		alertIDs = append(alertIDs, scanner.Text())
	}

	var inputDismissReason tsapi.DismissReason
	if c.String("dismissReason") == string(tsapi.DismissBusinessOp) {
		inputDismissReason = tsapi.DismissBusinessOp
	} else if c.String("dismissReason") == string(tsapi.DismissCompanyPolicy) {
		inputDismissReason = tsapi.DismissCompanyPolicy
	} else if c.String("dismissReason") == string(tsapi.DismissMaintenance) {
		inputDismissReason = tsapi.DismissMaintenance
	} else if c.String("dismissReason") == string(tsapi.DismissOther) {
		inputDismissReason = tsapi.DismissOther
	} else {
		fmt.Printf("\nERROR: Invalid dismiss reason: %s", c.String("dismissReason"))
		os.Exit(1)
	}


	alertsToDismiss := tsapi.DismissAlertsByID{
		IDs:                  alertIDs,
		DismissReason:        inputDismissReason,
		DismissReasonText:    c.String("dismissReasonText"),
	}

	reqJSON, err := json.Marshal(alertsToDismiss)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf(string(reqJSON))
	req, err := tsBuildHTTPReq(c, "POST", dismissAlertsEndpoint, reqJSON)
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
		fmt.Printf("Successfully dismissed alerts\n")
	} else {
		fmt.Printf("Unable to dismiss alerts. The API responded with an HTTP/%d.\n", resp.StatusCode)
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

func dismissAlertsByQueryParameters(c *cli.Context) {
	client := &http.Client{}
	dismissAlertsEndpoint := "/v2/alerts/dismiss"
	validInput := true
	var errs []string

	if c.String("from") == "" {
		errs = append(errs, "Missing \"from\" time parameter")
		validInput = false
	}

	if c.String("until") == "" {
		errs = append(errs, "Missing \"until\" time parameter")
		validInput = false
	}

	if c.String("severity") == "" && c.String("ruleID") == "" && c.String("agentID") == ""{
		errs = append(errs, "Must include at least one of severity, ruleID, or agentID")
		validInput = false
	}

	if c.String("dismissReason") == "" {
		errs = append(errs, "Missing dismiss reason")
		validInput = false
	}

	if c.String("dismissReasonText") == "" && c.String("dismissReason") == "OTHER"{
		errs = append(errs, "Dismiss reason OTHER entered, but no dismiss reason text provided")
		validInput = false
	}
	
	if c.String("dismissReasonText") != "" && c.String("dismissReason") != "OTHER"{
		errs = append(errs, "Dismiss reason text entered, but dismiss reason is not OTHER")
		validInput = false
	}

	if validInput == false {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Unable to create alert dismissal request.\n")
		for _, v := range errs {
			fmt.Printf("         * %s\n", v)
		}
		os.Exit(1)
	}

	var inputDismissReason tsapi.DismissReason
	if c.String("dismissReason") == string(tsapi.DismissBusinessOp) {
		inputDismissReason = tsapi.DismissBusinessOp
	} else if c.String("dismissReason") == string(tsapi.DismissCompanyPolicy) {
		inputDismissReason = tsapi.DismissCompanyPolicy
	} else if c.String("dismissReason") == string(tsapi.DismissMaintenance) {
		inputDismissReason = tsapi.DismissMaintenance
	} else if c.String("dismissReason") == string(tsapi.DismissOther) {
		inputDismissReason = tsapi.DismissOther
	} else {
		fmt.Printf("\nERROR: Invalid dismiss reason: %s", c.String("dismissReason"))
		os.Exit(1)
	}


	alertsToDismiss := tsapi.DismissAlertsByQueryParameters{
		From:                 c.String("from"),
		Until:                c.String("until"),
		Severity:             c.Int("severity"),
		RuleID:               c.String("ruleID"),
		AgentID:              c.String("agentID"),
		DismissReason:        inputDismissReason,
		DismissReasonText:    c.String("dismissReasonText"),
	}

	reqJSON, err := json.Marshal(alertsToDismiss)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf(string(reqJSON))
	req, err := tsBuildHTTPReq(c, "POST", dismissAlertsEndpoint, reqJSON)
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
		fmt.Printf("Successfully dismissed alerts\n")
	} else {
		fmt.Printf("Unable to dismiss alerts. The API responded with an HTTP/%d.\n", resp.StatusCode)
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
