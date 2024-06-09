-- name: UpsertUser :one
INSERT INTO users (discord_id, name)
VALUES ($1, $2) ON CONFLICT (discord_id) DO
UPDATE
SET discord_id = EXCLUDED.discord_id,
    name = $2
RETURNING id;
-- name: GetUser :one
SELECT id,
    discord_id,
    name
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
-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;
-- name: DeleteUserSessions :execrows
DELETE FROM sessions
WHERE user_id = $1;