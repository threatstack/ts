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

func createS3Portability(c *cli.Context) {
	client := &http.Client{}
	s3PortabilityEndpoint := "/v2/integrations/s3export"
	validInput := true
	var errs []string

	if c.String("s3bucket") == "" {
		errs = append(errs, "Missing S3 Bucket Name")
		validInput = false
	}

	if c.String("arn") == "" {
		errs = append(errs, "Missing IAM Role ARN")
		validInput = false
	}

	if c.String("region") == "" {
		errs = append(errs, "Missing AWS Region")
		validInput = false
	}

	if validInput == false {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Unable to create enrollment request.\n")
		for _, v := range errs {
			fmt.Printf("         * %s\n", v)
		}
		os.Exit(1)
	}

	integrationToCreate := tsapi.S3ExportEnrollment{
		Enabled:              true,
		S3Bucket:             c.String("s3bucket"),
		IAMRoleARN:           c.String("arn"),
		IAMRoleARNExternalID: c.String("externalID"),
		Region:               c.String("region"),
		Prefix:               c.String("prefix"),
	}

	reqJSON, err := json.Marshal(integrationToCreate)
	if err != nil {
		log.Fatalln(err)
	}

	req, err := tsBuildHTTPReq(c, "PUT", s3PortabilityEndpoint, reqJSON)
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
		var enrollmentResponse tsapi.S3ExportEnrollmentResponse
		if err := json.Unmarshal(body, &enrollmentResponse); err != nil {
			log.Fatalln(err)
		}

		fmt.Printf("Created S3 Enrollment at %s\n", enrollmentResponse.EnrolledAt)
		fmt.Printf("----------------------------------------------------------------------\n")
		fmt.Printf("Enabled:         %t\n", enrollmentResponse.Enabled)
		fmt.Printf("Organization ID: %s\n", enrollmentResponse.OrganizationID)
		fmt.Printf("S3 Bucket:       %s\n", enrollmentResponse.S3Bucket)
		fmt.Printf("IAM Role ARN:    %s\n", enrollmentResponse.IAMRoleARN)
		fmt.Printf("IAM External ID: %s\n", enrollmentResponse.IAMRoleARNExternalID)
		fmt.Printf("Region:          %s\n", enrollmentResponse.Region)
		fmt.Printf("Prefix:          %s\n", enrollmentResponse.Prefix)
	} else {
		fmt.Printf("Unable to create S3 Enrollment. The API responded with an HTTP/%d.\n", resp.StatusCode)
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

func getS3Portability(c *cli.Context) {
	client := &http.Client{}
	s3PortabilityEndpoint := "/v2/integrations/s3export"
	req, err := tsBuildHTTPReq(c, "GET", s3PortabilityEndpoint, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	var enrollments []tsapi.S3ExportEnrollmentResponse

	if err := json.Unmarshal(body, &enrollments); err != nil {
		log.Fatalln(err)
	}

	if len(enrollments) == 0 {
		fmt.Println("No active S3 enrollments.")
	}

	for index, enrollment := range enrollments {
		enrollmentInfo := fmt.Sprintf("Enrollment %d ", index)
		if enrollment.Enabled {
			enrollmentInfo = enrollmentInfo + "(Enabled)"
		} else {
			enrollmentInfo = enrollmentInfo + "(Disabled)"
		}

		fmt.Printf("%s\n", enrollmentInfo)
		fmt.Printf("----------------------------------------------------------------------\n")
		fmt.Printf("S3 Bucket:       %s\n", enrollment.S3Bucket)
		fmt.Printf("IAM Role ARN:    %s\n", enrollment.IAMRoleARN)
		fmt.Printf("IAM External ID: %s\n", enrollment.IAMRoleARNExternalID)
		fmt.Printf("Region:          %s\n", enrollment.Region)
		fmt.Printf("Prefix:          %s\n", enrollment.Prefix)
	}
}

func deleteS3Portability(c *cli.Context) {
	if c.Args().Get(0) == "" {
		cli.ShowSubcommandHelp(c)
		fmt.Printf("\nERROR: Specify the S3 bucket you want to delete after the delete command.\n")
		os.Exit(1)
	}

	client := &http.Client{}
	s3PortabilityEndpoint := "/v2/integrations/s3export"

	integrationToDelete := tsapi.S3ExportDelete{
		S3Bucket: c.Args().Get(0),
	}

	reqJSON, err := json.Marshal(integrationToDelete)
	if err != nil {
		log.Fatalln(err)
	}

	req, err := tsBuildHTTPReq(c, "DELETE", s3PortabilityEndpoint, reqJSON)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("%s\n", body)
}
