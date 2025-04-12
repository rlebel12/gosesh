package gosesh

import (
	"log/slog"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoseshHost(t *testing.T) {
	sesh := New(nil, nil)
	assert.Equal(t, "localhost", sesh.Host())
}

func TestGoseshScheme(t *testing.T) {
	sesh := New(nil, nil)
	assert.Equal(t, "http", sesh.Scheme())
}

func TestWithCookieDomain(t *testing.T) {
	origin, _ := url.Parse("https://example.com")
	sesh := New(nil, nil,
		WithOrigin(origin),
		WithCookieDomain(func(g *Gosesh) func() string {
			return func() string {
				return "test." + g.Host()
			}
		}))
	assert.Equal(t, "test.example.com", sesh.CookieDomain())
}

func TestWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	sesh := New(nil, nil, WithLogger(logger))
	assert.Equal(t, logger, sesh.logger)
}
