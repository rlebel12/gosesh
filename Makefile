coverage:
	@go test ./... -coverpkg=./... -coverprofile=./tmp/coverage.out
	@go tool cover -html=./tmp/coverage.out -o ./tmp/coverage.html
	@rm ./tmp/coverage.out
