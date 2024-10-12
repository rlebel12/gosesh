package tests

import (
	"net/url"
	"testing"

	"github.com/rlebel12/gosesh"
	"github.com/stretchr/testify/assert"
)

func TestGoseshHost(t *testing.T) {
	sesh := gosesh.New(nil, nil)
	assert.Equal(t, "localhost", sesh.Host())
}

func TestGoseshScheme(t *testing.T) {
	sesh := gosesh.New(nil, nil)
	assert.Equal(t, "http", sesh.Scheme())
}

func TestWithCookieDomain(t *testing.T) {
	origin, _ := url.Parse("https://example.com")
	sesh := gosesh.New(nil, nil,
		gosesh.WithOrigin(origin),
		gosesh.WithCookieDomain(func(g *gosesh.Gosesh) func() string {
			return func() string {
				return "test." + g.Host()
			}
		}))
	assert.Equal(t, "test.example.com", sesh.CookieDomain())
}
