// ts - golang ts api client
// s3export.go: data portability functionality
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

func inviteUser(c *cli.Context) {
	client := &http.Client{}
	inviteEndpoint := "/v2/organizations/invites"
	validInput := true
	roleUserInput := true
	roleReaderInput := true

	var errs []string

	if c.String("userrole") == "" {
		errs = append(errs, "Missing the role for the new user")
		validInput = false
	} 

	if c.String("userrole") != "user" {
		roleUserInput = false
	}

	if c.String("userrole") != "reader" {
		roleReaderInput = false
	} 

	if c.String("email") == "" {
		errs = append(errs, "Missing e-mail address for new user")
		validInput = false
	}

	if roleUserInput == false && roleReaderInput == false {
		errs = append(errs, "Role for the new user is not set 'user' or 'reader'")
		validInput = false
	}

	if !validInput {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Unable to create enrollment request.\n")
		for _, v := range errs {
			fmt.Printf("         * %s\n", v)
		}
		os.Exit(1)
	}

	integrationToCreate := tsapi.InvitePost{
		Role:  c.String("userrole"),
		Email: c.String("email"),
	}

	reqJSON, err := json.Marshal(integrationToCreate)
	if err != nil {
		log.Fatalln(err)
	}

	req, err := tsBuildHTTPReq(c, "PUT", inviteEndpoint, reqJSON)
	if err != nil {
		log.Fatalln(err)
	}
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
		var enrollmentResponse tsapi.InviteResponse
		if err := json.Unmarshal(body, &enrollmentResponse); err != nil {
			log.Fatalln(err)
		}

		fmt.Printf("Invite request sent\n")
		fmt.Printf("----------------------------------------------------------------------\n")
		fmt.Printf("Email Set to:         %t\n", enrollmentResponse.SentToEmail)
		fmt.Printf("Role: %s\n", enrollmentResponse.Role)
		fmt.Printf("Status:       %s\n", enrollmentResponse.Status)

	} else {
		fmt.Printf("Unable to send invite. The API responded with an HTTP/%d.\n", resp.StatusCode)
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

func getUsers(c *cli.Context) {
	var member []tsapi.Member
	client := &http.Client{}
	OrgMembersEndpoint := "/v2/organizations/members"
	req, err := tsBuildHTTPReq(c, "GET", OrgMembersEndpoint, nil)
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

		var enrollments tsapi.MembersResponseRaw

		if err := json.Unmarshal(body, &enrollments); err != nil {
			log.Fatalln(err)
		}
		member = append(member, enrollments.Members...)
	}
	ser, err := json.Marshal(member)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(ser))

}

func deleteUser(c *cli.Context) {
	client := &http.Client{}
	validInput := true
	var errs []string

	if c.String("userid") == "" {
		errs = append(errs, "the user id to delete")
		validInput = false
	}
	if !validInput {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Unable to do delete user request.\n")
		for _, v := range errs {
			fmt.Printf("         * %s\n", v)
		}
		os.Exit(1)
	}

	OrgMemberDeleteEndpoint := "/v2/organizations/members/"
	OrgMemberDeleteEndpoint += c.String("userid")
	fmt.Println(OrgMemberDeleteEndpoint)

	req, err := tsBuildHTTPReq(c, "DELETE", OrgMemberDeleteEndpoint, nil)
	if err != nil {
		log.Fatalln(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%s\n", body)
	}	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}


	fmt.Printf("%s\n", body)
}
