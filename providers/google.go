package providers

import (
	"context"
	"io"
	"net/http"

	"github.com/rlebel12/gosesh"
	"golang.org/x/oauth2/google"
)

// Google provides OAuth2 authentication using Google's OAuth2 service.
// It implements the basic OAuth2 flow for Google authentication.
type Google struct {
	Provider
}

// NewGoogle creates a new Google OAuth2 provider with the given configuration.
// The redirectPath parameter should have a leading slash.
func NewGoogle(sesh Gosesher, clientID, clientSecret, redirectPath string) *Google {
	google := &Google{
		Provider: newProvider(sesh, []string{
			"https://www.googleapis.com/auth/userinfo.email",
		}, google.Endpoint, clientID, clientSecret, redirectPath),
	}
	return google
}

// OAuth2Begin returns a handler that initiates the Google OAuth2 flow.
func (p *Google) OAuth2Begin() http.HandlerFunc {
	return p.Gosesh.OAuth2Begin(p.Config)
}

// OAuth2Callback returns a handler that completes the Google OAuth2 flow.
// The handler parameter is called when the flow completes, with any error that occurred.
func (p *Google) OAuth2Callback(handler gosesh.HandlerDoneFunc) http.HandlerFunc {
	return p.Gosesh.OAuth2Callback(p.Config, p.requestUser, unmarshalUser(p.NewUser), handler)
}

// requestUser makes a request to Google's userinfo endpoint to get the user's data.
func (p *Google) requestUser(ctx context.Context, accessToken string) (io.ReadCloser, error) {
	const url = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	return p.doRequest("GET", url+accessToken, nil)
}

// NewUser creates a new GoogleUser instance.
func (p *Google) NewUser() *GoogleUser {
	return &GoogleUser{}
}

// GoogleUser represents a user authenticated through Google's OAuth2 service.
// It contains the user's Google account information.
type GoogleUser struct {
	ID            string `json:"id"`             // The user's unique Google ID
	Email         string `json:"email"`          // The user's email address
	VerifiedEmail bool   `json:"verified_email"` // Whether the email is verified
	Picture       string `json:"picture"`        // URL to the user's profile picture
}

// String returns the user's email address as their unique identifier.
func (user *GoogleUser) String() string {
	return user.Email
}
