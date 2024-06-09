-- name: UpsertUser :one
INSERT INTO users (identifier)
VALUES ($1) ON CONFLICT (identifier) DO
UPDATE
SET identifier = EXCLUDED.identifier
RETURNING id;

-- name: GetUser :one
SELECT id,
    identifier
FROM users
WHERE id = $1;

-- name: CreateSession :one
INSERT INTO sessions (user_id, idle_at, expire_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSession :one
SELECT id,
    user_id,
    idle_at,
    expire_at
FROM sessions
WHERE id = $1;

-- name: UpdateSession :one
UPDATE sessions
SET idle_at = $1,
    expire_at = $2
WHERE id = $3
RETURNING *;

-- name: DeleteSession :execrows
DELETE FROM sessions
WHERE id = $1;

-- name: DeleteUserSessions :execrows
DELETE FROM sessions
WHERE user_id = $1;