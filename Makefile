up:
	@docker compose up -d

down:
	@docker compose down

cover:
	@go test -cover -coverpkg "." "./tests" -coverprofile=gosesh_coverage.out .
	@go tool cover -html=gosesh_coverage.out -o gosesh_coverage.html
	@rm gosesh_coverage.out

	@go test -cover "./providers" -coverprofile=providers_coverage.out ./providers
	@go tool cover -html=providers_coverage.out -o providers_coverage.html
	@rm providers_coverage.out

	@go test -cover "./stores/postgres" -coverprofile=postgres_coverage.out ./stores/postgres
	@go tool cover -html=postgres_coverage.out -o postgres_coverage.html
	@rm postgres_coverage.out

migrate:
	atlas migrate apply --dir "file://stores/postgres/migrations" --url "postgresql://postgres:root@localhost:16001/gosesh?sslmode=disable"

migration:
	atlas migrate diff --dir "file://stores/postgres/migrations" --to "file://stores/postgres/schema.sql" --dev-url "postgresql://postgres:root@localhost:16001/gosesh?search_path=public&sslmode=disable"

gen:
	@go generate ./...
	@sqlc generate
	@mockery
