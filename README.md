# gosesh
[![Go Reference](https://pkg.go.dev/badge/github.com/rlebel12/gosesh.svg)](https://pkg.go.dev/github.com/rlebel12/gosesh)
[![Test](https://github.com/rlebel12/gosesh/actions/workflows/test.yml/badge.svg)](https://github.com/rlebel12/gosesh/actions/workflows/test.yml)

An auth library that that abstracts away the OAuth2 flow.

## Installation
```bash
go get github.com/rlebel12/gosesh
```

## Usage
`gosesh` allows application developers to quickly add session-based authentication to their applications. This is achieved by requiring consumers to implement only their mechanisms for interfacing with their persistent data store (i.e. database) for performing CRUD operations on user data. Using that, the library can then provide a simple API for basic authentication (login, logout), guarded endpoints via middleware, automatic session refresh, and more.

See the `gosesh/examples` package for an example in-memory store that could be provided to `gosesh`.


### Providers
To use the `gosesh` public API, you must defined OAuth2 providers via `oauth2.Config` objects. These objects are what tell `gosesh` precicesly how to authenticate with a specific provider. Examples of common providers are Google, Facebook, and GitHub. Check the documentation for a given provider to see what details they expect in the `oauth2.Config` object.

This library also includes `gosesh/providers`, which allows clients to quickly integrate with common OAuth2 providers, needing only provide their application-specific credentials.

At present, the following providers are supported:
- Discord
- Google
