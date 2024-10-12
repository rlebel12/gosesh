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
)

func (s *Store) UpsertUser(ctx context.Context, user gosesh.OAuth2User) (gosesh.Identifier, error) {
	id, err := s.repo.UpsertUser(ctx, user.String())
	return uuidFromPGTYPE(id), err
}

func (s *Store) CreateSession(ctx context.Context, r gosesh.CreateSessionRequest) (gosesh.Session, error) {
	userID, err := identifierToUUID(r.UserID)
	if err != nil {
		return nil, err
	}

	params := sqlc.CreateSessionParams{
		UserID:   uuidToPGTYPE(userID),
		IdleAt:   timestampToPGTYPE(r.IdleAt),
		ExpireAt: timestampToPGTYPE(r.ExpireAt),
	}
	session, err := s.repo.CreateSession(ctx, params)
	return sessionToGosesh(session), err
}

func (s *Store) GetSession(ctx context.Context, identifier gosesh.Identifier) (gosesh.Session, error) {
	id, err := identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}

	session, err := s.repo.GetSession(ctx, uuidToPGTYPE(id))
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return sessionToGosesh(session), nil
}

func (s *Store) UpdateSession(ctx context.Context, identifier gosesh.Identifier, r gosesh.UpdateSessionValues) (gosesh.Session, error) {
	id, err := identifierToUUID(identifier)
	if err != nil {
		return nil, err
	}

	params := sqlc.UpdateSessionParams{
		ID:       uuidToPGTYPE(id),
		IdleAt:   timestampToPGTYPE(r.IdleAt),
		ExpireAt: timestampToPGTYPE(r.ExpireAt),
	}
	session, err := s.repo.UpdateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return sessionToGosesh(session), nil
}

func (s *Store) DeleteSession(ctx context.Context, identifier gosesh.Identifier) error {
	id, err := identifierToUUID(identifier)
	if err != nil {
		return err
	}
	count, err := s.repo.DeleteSession(ctx, uuidToPGTYPE(id))
	if count == 0 {
		return fmt.Errorf("failed to delete session: no rows in result set")
	}
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, identifier gosesh.Identifier) (int, error) {
	id, err := identifierToUUID(identifier)
	if err != nil {
		return 0, err
	}
	result, err := s.repo.DeleteUserSessions(ctx, uuidToPGTYPE(id))
	return int(result), err
}

type Session struct {
	sqlc.Session
}

func (s Session) ID() gosesh.Identifier {
	return uuidFromPGTYPE(s.Session.ID)
}

func (s Session) UserID() gosesh.Identifier {
	return uuidFromPGTYPE(s.Session.UserID)
}

func (s Session) IdleAt() time.Time {
	return s.Session.IdleAt.Time
}

func (s Session) ExpireAt() time.Time {
	return s.Session.ExpireAt.Time
}

func sessionToGosesh(sess sqlc.Session) gosesh.Session {
	return Session{
		Session: sess,
	}
}

func identifierToUUID(identifier gosesh.Identifier) (uuid.UUID, error) {
	id, err := uuid.Parse(identifier.String())
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse identifier: %w", err)
	}
	return id, nil
}

func uuidFromPGTYPE(id pgtype.UUID) uuid.UUID {
	return uuid.UUID(id.Bytes)
}

func timestampToPGTYPE(ts time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  ts,
		Valid: true,
	}
}

func uuidToPGTYPE(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}
