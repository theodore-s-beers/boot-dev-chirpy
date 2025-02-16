-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (created_at, updated_at, token, user_id, expires_at)
VALUES (
    now(),
    now(),
    $1,
    $2,
    $3
)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1 AND revoked_at IS NULL
RETURNING *;
