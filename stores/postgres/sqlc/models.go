// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package sqlc

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type Session struct {
	ID       pgtype.UUID
	UserID   pgtype.UUID
	IdleAt   pgtype.Timestamptz
	ExpireAt pgtype.Timestamptz
}

type User struct {
	ID         pgtype.UUID
	Identifier pgtype.Text
}
