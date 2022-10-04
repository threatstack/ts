// ts - golang ts api client
// api/members.go: structs for the members endpoint
//
// Copyright 2022 F5, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.

package tsapi

// invite Post
type InvitePost struct {
	Role  string `json:"role"`
	Email string `json:"email"`
}

type InviteResponse struct {
	SentToEmail string `json:"sentToEmail"`
	Role        string `json:"role"`
	Status      string `json:"status"`
}

type MembersResponseRaw struct {
	Members []Member `json:"members"`
}

// Members is the model response
type Member struct {
	Role                string `json:"role"`
	SSOEnabled          bool   `json:"ssoEnabled"`
	DisplayName         string `json:"displayName"`
	UserEnabled         bool   `json:"userEnabled"`
	LastAuthenticatedAt int    `json:"lastAuthenticatedAt"`
	MFAEnabled          bool   `json:"mfaEnabled"`
	ID                  string `json:"id"`
	Email               string `json:"email"`
}
