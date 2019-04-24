// ts - golang ts api client
// api/alerts.go: structs for the alerts endpoint
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package tsapi

// DismissReason stores different reasons for dismissing an alert
type DismissReason string

const (
	// DismissBusinessOp - Required for Business Operations
	DismissBusinessOp DismissReason = "BUSINESS_OP"
	// DismissCompanyPolicy - Normal per Company Policy
	DismissCompanyPolicy DismissReason = "COMPANY_POLICY"
	// DismissMaintenance - Required Temporarily, for Testing and Maintenance
	DismissMaintenance DismissReason = "MAINTENANCE"
	// DismissOther - Other
	DismissOther DismissReason = "OTHER"
)

// AlertResponseRaw is the raw result returned from the API
type AlertResponseRaw struct {
	Alerts []Alert `json:"alerts"`
	Token  string  `json:"token"`
}

// Alert stores information related to an individual alert
type Alert struct {
	ID                string           `json:"id"`
	Title             string           `json:"title"`
	DataSource        string           `json:"dataSource"`
	CreatedAt         string           `json:"createdAt"`
	IsDismissed       bool             `json:"isDismissed"`
	DismissedAt       string           `json:"dismissedAt"`
	DismissReason     DismissReason    `json:"dismissReason"`
	DismissReasonText string           `json:"dismissReasonText"`
	DismissedBy       string           `json:"dismissedBy"`
	Severity          int              `json:"severity"`
	AgentID           string           `json:"agentId"`
	RuleID            string           `json:"ruleId"`
	RulesetID         string           `json:"rulesetId"`
	Aggregates        []AlertAggregate `json:"aggregates"`
}

// AlertAggregate is part of an Alert.
type AlertAggregate struct {
	FieldName string `json:"fieldName"`
}

// AlertSeverityCount is the data model for alerts by severity
type AlertSeverityCount struct {
	Severity int `json:"severity"`
	Count    int `json:"count"`
}

// DismissAlertByID is the data model for dismissing an alert or 512.
type DismissAlertByID struct {
	IDs               []string      `json:"ids"`
	DismissReason     DismissReason `json:"dismissReason"`
	DismissReasonText string        `json:"dismissReasonText"`
}

// DismissAlertByQueryParameters is the data model for dismissing an alert
// by a query vs. specific IDs.
type DismissAlertByQueryParameters struct {
	From              string        `json:"from"`
	Until             string        `json:"until"`
	Severity          int           `json:"severity"`
	RuleID            string        `json:"ruleID"`
	AgentID           string        `json:"agentID"`
	DismissReason     DismissReason `json:"dismissReason"`
	DismissReasonText string        `json:"dismissReasonText"`
}
