// ts - golang ts api client
// api/portability.go: structs for the s3export endpoint
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package tsapi

// S3ExportEnrollmentResponse is the model for an S3 Enrollment GET
type S3ExportEnrollmentResponse struct {
	OrganizationID       string `json:"organization_id"`
	S3Bucket             string `json:"s3Bucket"`
	IAMRoleARN           string `json:"iamRoleArn"`
	IAMRoleARNExternalID string `json:"iamRoleArnExternalId"`
	Region               string `json:"region"`
	Prefix               string `json:"prefix"`
	EnrolledAt           string `json:"enrolledAt"`
	Enabled              bool   `json:"enabled"`
}

// S3ExportDelete is the model for an S3 Enrollment Delete
type S3ExportDelete struct {
	S3Bucket string `json:"s3Bucket"`
}

// S3ExportEnrollment is the model for sending a new enrollment up
type S3ExportEnrollment struct {
	S3Bucket             string `json:"s3Bucket"`
	IAMRoleARN           string `json:"iamRoleArn"`
	IAMRoleARNExternalID string `json:"iamRoleArnExternalId"`
	Region               string `json:"region"`
	Prefix               string `json:"prefix"`
	Enabled              bool   `json:"enabled"`
}
