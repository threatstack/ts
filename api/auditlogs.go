// ts - golang ts api client
// api/auditlogs.go: structs for the auditlogs endpoint
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package tsapi

// AuditResponseRaw is the raw result returned from the API
type AuditResponseRaw struct {
	Recs  []AuditRecord `json:"recs"`
	Token string        `json:"token"`
}

// AuditRecord is an actual audit record
type AuditRecord struct {
	ID              string      `json:"id"`
	UserEmail       string      `json:"userEmail"`
	UserID          string      `json:"userId"`
	OrgnanizationID string      `json:"organizationId"`
	Result          string      `json:"result"`
	CRUD            string      `json:"crud"`
	Action          string      `json:"action"`
	Source          string      `json:"source"`
	Description     string      `json:"description"`
	EventTime       string      `json:"eventTime"`
	Context         interface{} `json:"context"`
}
