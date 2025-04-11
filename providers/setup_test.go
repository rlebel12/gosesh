package providers

import (
	"testing"

	"github.com/rlebel12/gosesh"
)

type testSetup struct {
	Sesh  *GosesherMock
	Creds *gosesh.OAuth2CredentialsMock
}

func setup(t *testing.T) testSetup {
	t.Helper()
	return testSetup{
		Sesh: &GosesherMock{
			SchemeFunc: func() string { return "http" },
			HostFunc:   func() string { return "localhost" },
		},
		Creds: &gosesh.OAuth2CredentialsMock{
			ClientIDFunc:     func() string { return "clientID" },
			ClientSecretFunc: func() string { return "clientSecret" },
		},
	}
}
