package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rlebel12/gosesh"
	"github.com/rlebel12/gosesh/stores/postgres/sqlc"
)

func New(db sqlc.DBTX) *Store {
	repo := &PostgresRepository{
		Queries: sqlc.New(db),
	}
	return &Store{repo, db}
}

type (
	Store struct {
		repo *PostgresRepository
		db   sqlc.DBTX
	}

	PostgresRepository struct {
		*sqlc.Queries
	}

	UUID struct {
		uuid.UUID
	}
)

func (u UUID) ID() string {
	return u.String()
}

func (s *Store) UpsertUser(ctx context.Context, user gosesh.OAuth2User) (gosesh.Identifier, error) {
	id, err := s.repo.UpsertUser(ctx, user.ID())
	return s.uuidFromPGTYPE(id), err
}

func (s *Store) CreateSession(ctx context.Context, r gosesh.CreateSessionRequest) (*gosesh.Session, error) {
	userID, err := s.identifierToUUID(r.User)
	if err != nil {
		return nil, err
	}

	params := sqlc.CreateSessionParams{
		UserID:   s.uuidToPGTYPE(userID),
		IdleAt:   s.timestampToPGTYPE(r.IdleAt),
		ExpireAt: s.timestampToPGTYPE(r.ExpireAt),
	}
	session, err := s.repo.CreateSession(ctx, params)
	return s.sessionToGosesh(session), err
}

func (s *Store) GetSession(ctx context.Context, identifier gosesh.Identifier) (*gosesh.Session, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}

	session, err := s.repo.GetSession(ctx, s.uuidToPGTYPE(id))
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return s.sessionToGosesh(session), nil
}

func (s *Store) UpdateSession(ctx context.Context, identifier gosesh.Identifier, r gosesh.UpdateSessionValues) (*gosesh.Session, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}

	params := sqlc.UpdateSessionParams{
		ID:       s.uuidToPGTYPE(id),
		IdleAt:   s.timestampToPGTYPE(r.IdleAt),
		ExpireAt: s.timestampToPGTYPE(r.ExpireAt),
	}
	session, err := s.repo.UpdateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return s.sessionToGosesh(session), nil
}

func (s *Store) DeleteSession(ctx context.Context, identifier gosesh.Identifier) error {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return err
	}
	count, err := s.repo.DeleteSession(ctx, s.uuidToPGTYPE(id))
	if count == 0 {
		return fmt.Errorf("failed to delete session: no rows in result set")
	}
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, identifier gosesh.Identifier) (int, error) {
	id, err := s.identifierToUUID(identifier)
	if err != nil {
		return 0, err
	}
	result, err := s.repo.DeleteUserSessions(ctx, s.uuidToPGTYPE(id))
	return int(result), err
}

func (s *Store) sessionToGosesh(sess sqlc.Session) *gosesh.Session {
	return &gosesh.Session{
		Identifier: s.uuidFromPGTYPE(sess.ID),
		User:       s.uuidFromPGTYPE(sess.UserID),
		IdleAt:     sess.IdleAt.Time,
		ExpireAt:   sess.ExpireAt.Time,
	}
}

func (s *Store) identifierToUUID(identifier gosesh.Identifier) (UUID, error) {
	id, err := uuid.Parse(identifier.ID())
	if err != nil {
		return UUID{}, fmt.Errorf("failed to parse identifier: %w", err)
	}
	return UUID{id}, nil
}

func (s *Store) uuidFromPGTYPE(id pgtype.UUID) UUID {
	return UUID{uuid.UUID(id.Bytes)}
}

func (s *Store) timestampToPGTYPE(ts time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  ts,
		Valid: true,
	}
}

func (s *Store) uuidToPGTYPE(id UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id.UUID,
		Valid: true,
	}
}
