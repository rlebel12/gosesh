package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rlebel12/gosesh/stores/postgres/sqlc"
)

type PostgresRepository struct {
	Q  *sqlc.Queries
	db sqlc.DBTX
}

func NewPostgresRepository(db sqlc.DBTX) *PostgresRepository {
	return &PostgresRepository{
		Q:  sqlc.New(db),
		db: db,
	}
}

func uuidFromPGTYPE(id pgtype.UUID) uuid.UUID {
	return uuid.UUID(id.Bytes)
}

func uuidToPGTYPE(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}

func (s *PostgresRepository) UpsertUser(ctx context.Context, args sqlc.UpsertUserParams) (uuid.UUID, error) {
	id, err := s.Q.UpsertUser(ctx, sqlc.UpsertUserParams{
		DiscordID: args.DiscordID,
		Name:      args.Name,
	})
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to upsert user: %w", err)
	}

	return uuidFromPGTYPE(id), nil
}

type CreateSessionRequest struct {
	UserID   uuid.UUID
	IdleAt   time.Time
	ExpireAt time.Time
}

func (s *PostgresRepository) CreateSession(ctx context.Context, r CreateSessionRequest) (*sqlc.Session, error) {
	params := sqlc.CreateSessionParams{
		UserID:   uuidToPGTYPE(r.UserID),
		IdleAt:   timestampToPGTYPE(r.IdleAt),
		ExpireAt: timestampToPGTYPE(r.ExpireAt),
	}
	sess, err := s.Q.CreateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &sess, nil
}

func (s *PostgresRepository) GetSession(ctx context.Context, id uuid.UUID) (*sqlc.Session, error) {
	sess, err := s.Q.GetSession(ctx, uuidToPGTYPE(id))
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &sess, nil
}

type UpdateSessionValues struct {
	IdleAt   time.Time
	ExpireAt time.Time
}

func (s *PostgresRepository) UpdateSession(ctx context.Context, id uuid.UUID, r UpdateSessionValues) (*sqlc.Session, error) {
	params := sqlc.UpdateSessionParams{
		ID:       uuidToPGTYPE(id),
		IdleAt:   timestampToPGTYPE(r.IdleAt),
		ExpireAt: timestampToPGTYPE(r.ExpireAt),
	}
	sess, err := s.Q.UpdateSession(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &sess, nil
}

func (s *PostgresRepository) DeleteSession(ctx context.Context, id uuid.UUID) error {
	return s.Q.DeleteSession(ctx, uuidToPGTYPE(id))
}

func (s *PostgresRepository) DeleteUserSessions(ctx context.Context, id uuid.UUID) (int, error) {
	result, err := s.Q.DeleteUserSessions(ctx, uuidToPGTYPE(id))
	return int(result), err
}

func timestampToPGTYPE(ts time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  ts,
		Valid: true,
	}
}
