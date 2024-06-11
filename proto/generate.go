package proto

//go:generate protoc -I=. --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative gosesh.proto
//go:generate protoc -I=. --ts_proto_opt=paths=source_relative --ts_proto_opt=oneof=unions --ts_proto_opt=useNullAsOptional=true --ts_proto_opt=initializeFieldsAsUndefined=false --plugin=../node_modules/.bin/protoc-gen-ts_proto --ts_proto_out=. gosesh.proto
