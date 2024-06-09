package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rlebel12/gosesh"
	mock_gosesh "github.com/rlebel12/gosesh/mocks"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/suite"
)

type TestPostgresSuite struct {
	suite.Suite
	pool             *dockertest.Pool
	postgresResource *dockertest.Resource
	db               *pgx.Conn
	store            *Store
}

func (s *TestPostgresSuite) SetupSuite() {
	var err error
	s.pool, err = dockertest.NewPool("")
	s.Require().NoError(err)
	s.Require().NoError(s.pool.Client.Ping())
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	s.pool.MaxWait = 10 * time.Second

	var url string
	s.postgresResource, url = s.runPostgres(s.pool)
	ctx := context.Background()
	s.NoError(s.pool.Retry(func() error {
		s.db, err = pgx.Connect(ctx, url)
		if err != nil {
			return err
		}
		return s.db.Ping(ctx)
	}))

	tx, err := s.db.Begin(ctx)
	s.NoError(err)
	defer tx.Rollback(ctx)

	schemaRaw, err := os.ReadFile("schema.sql")
	s.NoError(err)
	schema := string(schemaRaw)
	_, err = tx.Exec(ctx, schema)
	s.NoError(err)
	s.NoError(tx.Commit(ctx))

	s.store = New(s.db)
}

func (s *TestPostgresSuite) TearDownSuite() {
	s.Require().NoError(s.pool.Purge(s.postgresResource))
}

func (s *TestPostgresSuite) TestUpsertUser() {
	ctx := context.Background()
	user := mock_gosesh.NewOAuth2User(s.T())
	user.EXPECT().String().Return("test")

	// Test create
	newID, err := s.store.UpsertUser(ctx, user)
	s.Require().NoError(err)

	// Test update
	updateID, err := s.store.UpsertUser(ctx, user)
	s.Require().NoError(err)
	s.Equal(newID, updateID)
}

func (s *TestPostgresSuite) TestCreateSession() {
	s.Run("bad UUID", func() {
		ctx := context.Background()
		identifier := mock_gosesh.NewIdentifier(s.T())
		identifier.EXPECT().String().Return("bad")
		_, err := s.store.CreateSession(ctx, gosesh.CreateSessionRequest{
			UserID: identifier,
		})
		s.EqualError(err, "failed to parse identifier: invalid UUID length: 3")
	})

	s.Run("success", func() {
		ctx := context.Background()
		user := mock_gosesh.NewOAuth2User(s.T())
		user.EXPECT().String().Return("test")

		identifier, err := s.store.UpsertUser(ctx, user)
		s.Require().NoError(err)

		now := time.Now().Truncate(time.Microsecond).Local()
		idleAt := now
		expireAt := now.Add(time.Hour)
		session, err := s.store.CreateSession(ctx, gosesh.CreateSessionRequest{
			UserID:   identifier,
			IdleAt:   idleAt,
			ExpireAt: expireAt,
		})
		s.Require().NoError(err)
		s.Require().NotNil(session)
		s.Equal(identifier.String(), session.UserID.String())
		s.Equal(idleAt, session.IdleAt)
		s.Equal(expireAt, session.ExpireAt)
	})
}

func TestPostgres(t *testing.T) {
	suite.Run(t, new(TestPostgresSuite))
}

// Returns dockertest Resource and database URL
func (s *TestPostgresSuite) runPostgres(pool *dockertest.Pool) (*dockertest.Resource, string) {
	opts := dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "latest",
		Env: []string{
			"POSTGRES_USER=postgres",
			"POSTGRES_PASSWORD=root",
			"POSTGRES_DB=test",
			"listen_addresses = '*'",
		},
	}

	resource, err := pool.RunWithOptions(&opts, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
		if os.Getenv("CI_CLOUDBUILD") == "true" {
			config.NetworkMode = "cloudbuild"
		}
	})
	s.Require().NoError(err)

	network, found := resource.Container.NetworkSettings.Networks["cloudbuild"]
	var host, port string
	if found {
		host = network.IPAddress
		port = "5432"
	} else {
		host = "localhost"
		port = resource.GetPort("5432/tcp")
	}

	databaseURL := fmt.Sprintf(
		"postgres://postgres:root@%s:%s/test?sslmode=disable",
		host, port,
	)

	s.Require().NoError(resource.Expire(120))
	return resource, databaseURL
}
