// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.4
// source: gosesh.proto

package grpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// GoseshClient is the client API for Gosesh service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type GoseshClient interface {
	GetSession(ctx context.Context, in *GetSessionRequest, opts ...grpc.CallOption) (*Session, error)
}

type goseshClient struct {
	cc grpc.ClientConnInterface
}

func NewGoseshClient(cc grpc.ClientConnInterface) GoseshClient {
	return &goseshClient{cc}
}

func (c *goseshClient) GetSession(ctx context.Context, in *GetSessionRequest, opts ...grpc.CallOption) (*Session, error) {
	out := new(Session)
	err := c.cc.Invoke(ctx, "/gosesh.Gosesh/GetSession", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GoseshServer is the server API for Gosesh service.
// All implementations must embed UnimplementedGoseshServer
// for forward compatibility
type GoseshServer interface {
	GetSession(context.Context, *GetSessionRequest) (*Session, error)
	mustEmbedUnimplementedGoseshServer()
}

// UnimplementedGoseshServer must be embedded to have forward compatible implementations.
type UnimplementedGoseshServer struct {
}

func (UnimplementedGoseshServer) GetSession(context.Context, *GetSessionRequest) (*Session, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSession not implemented")
}
func (UnimplementedGoseshServer) mustEmbedUnimplementedGoseshServer() {}

// UnsafeGoseshServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to GoseshServer will
// result in compilation errors.
type UnsafeGoseshServer interface {
	mustEmbedUnimplementedGoseshServer()
}

func RegisterGoseshServer(s grpc.ServiceRegistrar, srv GoseshServer) {
	s.RegisterService(&Gosesh_ServiceDesc, srv)
}

func _Gosesh_GetSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GoseshServer).GetSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gosesh.Gosesh/GetSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GoseshServer).GetSession(ctx, req.(*GetSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Gosesh_ServiceDesc is the grpc.ServiceDesc for Gosesh service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Gosesh_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "gosesh.Gosesh",
	HandlerType: (*GoseshServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetSession",
			Handler:    _Gosesh_GetSession_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "gosesh.proto",
}