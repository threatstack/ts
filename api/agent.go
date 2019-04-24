// ts - golang ts api client
// api/agents.go: structs for the agents endpoint
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick T. Cable II <pat.cable@threatstack.com>

package tsapi

// AgentResponseRaw is the raw result returned from the API
type AgentResponseRaw struct {
	Agents []Agent `json:"agents"`
	Token  string  `json:"token"`
}

// Agent is the object for an actual agent.
type Agent struct {
	ID             string         `json:"id"`
	InstanceID     string         `json:"instanceId"`
	Status         string         `json:"status"`
	CreatedAt      string         `json:"createdAt"`
	LastReportedAt string         `json:"LastReportedAt"`
	Version        string         `json:"version"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Hostname       string         `json:"hostname"`
	IPAddresses    AgentIPInfo    `json:"ipAddresses"`
	Tags           []AgentTagInfo `json:"tags"`
	AgentType      string         `json:"agentType"`
	OSVersion      string         `json:"osVersion"`
	Kernel         string         `json:"kernel"`
}

// AgentIPInfo contains information about interfaces.
type AgentIPInfo struct {
	Private   []string `json:"private"`
	LinkLocal []string `json:"link_local"`
	Public    []string `json:"public"`
}

// AgentTagInfo contains information about cloud provider tags.
type AgentTagInfo struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
