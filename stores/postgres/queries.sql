-- name: UpsertUser :one
INSERT INTO users (key)
VALUES ($1) ON CONFLICT (key) DO
UPDATE
SET key = EXCLUDED.key
RETURNING id;

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