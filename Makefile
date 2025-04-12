up:
	@docker compose up -d

down:
	@docker compose down

coverage:
	@go test ./... -coverpkg=./... -coverprofile=./tmp/coverage.out
	@go tool cover -html=./tmp/coverage.out -o ./tmp/coverage.html
	@rm ./tmp/coverage.out

migrate:
	atlas migrate apply --dir "file://stores/postgres/migrations" --url "postgresql://postgres:root@localhost:16001/gosesh?sslmode=disable"

migration:
	atlas migrate diff --dir "file://stores/postgres/migrations" --to "file://stores/postgres/schema.sql" --dev-url "postgresql://postgres:root@localhost:16001/gosesh?search_path=public&sslmode=disable"

gen:
	@go generate ./...
	@sqlc generate
	@mockery
