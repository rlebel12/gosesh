package identity

//go:generate go run -mod=mod github.com/rlebel12/identity/cmd/identityproto -p=vel/identity
//go:generate protoc -I=. --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative identity.proto
