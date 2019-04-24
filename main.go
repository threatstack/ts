// ts - golang ts api client
// main.go: CLI framework definition
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package main

import (
	"log"
	"net/http"
	"os"

	tsapi "github.com/threatstack/ts/api"
	"github.com/urfave/cli"
)

func main() {
	app := &cli.App{
		Name:    "ts",
		Version: "0.0.1",
		Usage:   "Query the TS API via your command line interface.",
		Authors: []cli.Author{
			{Name: "Patrick Cable", Email: "pat.cable@threatstack.com"},
		},
		Action: func(c *cli.Context) error {
			noArgs(c)
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:   "user, u",
				Usage:  "User ID",
				EnvVar: "TS_USER_ID",
			},
			&cli.StringFlag{
				Name:   "org, o",
				Usage:  "Organization ID",
				EnvVar: "TS_ORGANIZATION_ID",
			},
			&cli.StringFlag{
				Name:   "endpoint, e",
				Usage:  "API Endpoint",
				Value:  "https://api.threatstack.com",
				EnvVar: "TS_API_ENDPOINT",
			},
			&cli.StringFlag{
				Name:   "key, k",
				Usage:  "API Key",
				EnvVar: "TS_API_KEY",
			},
		},
		Commands: []cli.Command{
			{
				Name:  "agent",
				Usage: "Display information related to TS agents",
				Subcommands: []cli.Command{
					{
						Name:  "list",
						Usage: "request all agents",
						Subcommands: []cli.Command{
							{
								Name:  "online",
								Usage: "request all online agents",
								Action: func(c *cli.Context) error {
									getAgents(c, true)
									return nil
								},
							},
							{
								Name:  "offline",
								Usage: "request all offline agents",
								Action: func(c *cli.Context) error {
									getAgents(c, false)
									return nil
								},
							},
						},
					},
					{
						Name:  "show",
						Usage: "return information on a single agent",
						Action: func(c *cli.Context) error {
							getAgent(c)
							return nil
						},
					},
				},
			},
			{
				Name:  "portability",
				Usage: "Manage data portability settings",
				Subcommands: []cli.Command{
					{
						Name:  "s3",
						Usage: "display current S3 portability configuration",
						Subcommands: []cli.Command{
							{
								Name:  "create",
								Usage: "create an S3 portability configuration (see --help)",
								Flags: []cli.Flag{
									&cli.StringFlag{
										Name:  "s3bucket, s",
										Usage: "S3 Bucket Name",
									},
									&cli.StringFlag{
										Name:  "arn, a",
										Usage: "IAM Role Arn",
									},
									&cli.StringFlag{
										Name:  "externalID, i",
										Usage: "IAM Role External ID",
									},
									&cli.StringFlag{
										Name:  "region, r",
										Usage: "AWS Region (us-east-1, etc.)",
									},
									&cli.StringFlag{
										Name:  "prefix, p",
										Usage: "Bucket Prefix (folder)",
									},
								},
								Action: func(c *cli.Context) error {
									createS3Portability(c)
									return nil
								},
							},
							{
								Name:  "list",
								Usage: "show all S3 portability configurations",
								Action: func(c *cli.Context) error {
									getS3Portability(c)
									return nil
								},
							},
							{
								Name:  "delete",
								Usage: "delete an S3 portability configuration",
								Action: func(c *cli.Context) error {
									deleteS3Portability(c)
									return nil
								},
							},
						},
					},
				},
			},
			{
				Name:        "raw",
				Usage:       "send hawk-signed API requests",
				Description: "The 'Secret Menu' of the TS CLI. Perform any action on any endpoint! Get raw JSON back!",
				Hidden:      true,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "request, X",
						Usage: "Method to use. Try: PUT, POST, DELETE.",
						Value: "GET",
					},
					&cli.StringFlag{
						Name:  "data, d",
						Usage: "Raw JSON data to send",
					},
					&cli.BoolFlag{
						Name:  "debug, z",
						Usage: "Print request information along with output",
					},
				},
				Action: func(c *cli.Context) error {
					raw(c)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func noArgs(c *cli.Context) {
	cli.ShowAppHelp(c)
}

// tsBuildHTTPReq - function for using CLI context to build a HAWK request
func tsBuildHTTPReq(c *cli.Context, method string, endpoint string, payload []byte) (*http.Request, error) {
	config := tsapi.Config{
		User: c.GlobalString("user"),
		Key:  c.GlobalString("key"),
		Org:  c.GlobalString("org"),
	}

	req, err := tsapi.Request(config, method, c.GlobalString("endpoint")+endpoint, payload)
	if err != nil {
		return req, err
	}
	return req, nil
}
