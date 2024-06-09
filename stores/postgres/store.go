package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/stores/postgres/sqlc"
)

func New(db sqlc.DBTX) *Store {
	repo := NewPostgresRepository(db)
	return &Store{repo}
}

type (
	Store struct {
		repo *PostgresRepository
	}
)

func (s *Store) UpsertUser(ctx context.Context, gsUser gosesh.OAuth2User) (gosesh.Identifier, error) {
	return s.repo.UpsertUser(ctx, gsUser.String())
}

func (s *Store) CreateSession(ctx context.Context, r gosesh.CreateSessionRequest) (*gosesh.Session, error) {
	id, err := s.identifierToUUID(r.UserID)
	if err != nil {
		return nil, err
	}
	session, err := s.repo.CreateSession(ctx, CreateSessionRequest{
		UserID:   id,
		IdleAt:   r.IdleAt,
		ExpireAt: r.ExpireAt,
	})
	return s.sessionToGosesh(session), err
}

func (s *Store) GetSession(ctx context.Context, identifier gosesh.Identifier) (*gosesh.Session, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}
	session, err := s.repo.GetSession(ctx, id)
	return s.sessionToGosesh(session), err
}

func (s *Store) UpdateSession(ctx context.Context, identifier gosesh.Identifier, r gosesh.UpdateSessionValues) (*gosesh.Session, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}
	session, err := s.repo.UpdateSession(ctx, id, UpdateSessionValues{
		IdleAt:   r.IdleAt,
		ExpireAt: r.ExpireAt,
	})
	return s.sessionToGosesh(session), err
}

func (s *Store) DeleteSession(ctx context.Context, identifier gosesh.Identifier) error {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return err
	}
	return s.repo.DeleteSession(ctx, id)
}

func (s *Store) DeleteUserSessions(ctx context.Context, identifier gosesh.Identifier) (int, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return 0, err
	}
	return s.repo.DeleteUserSessions(ctx, id)
}

func (s *Store) sessionToGosesh(sess *sqlc.Session) *gosesh.Session {
	if sess == nil {
		return nil
	}

	return &gosesh.Session{
		ID:       uuidFromPGTYPE(sess.ID),
		UserID:   uuidFromPGTYPE(sess.UserID),
		IdleAt:   sess.IdleAt.Time,
		ExpireAt: sess.ExpireAt.Time,
	}
}

func (s *Store) identifierToUUID(identifier gosesh.Identifier) (uuid.UUID, error) {
	id, err := uuid.Parse(identifier.String())
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse identifier: %w", err)
	}
	return id, nil
}
