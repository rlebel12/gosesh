package tests

import (
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
	sesh := gosesh.New(nil, nil, gosesh.WithCookieDomain("example.com"))
	assert.Equal(t, "example.com", sesh.CookieDomain)
}
