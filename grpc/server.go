package grpc

import (
	context "context"
	"fmt"

	"github.com/rlebel12/gosesh"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	UnimplementedGoseshServer
	store gosesh.Storer
}

func NewServer(store gosesh.Storer) Server {
	return Server{store: store}
}

func (s Server) GetSession(ctx context.Context, in *ID) (*Session, error) {
	session, err := s.store.GetSession(ctx, &identifier{b: in.GetId()})
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &Session{
		Id:       []byte(session.ID.String()),
		UserId:   []byte(session.UserID.String()),
		IdleAt:   timestamppb.New(session.IdleAt),
		ExpireAt: timestamppb.New(session.ExpireAt),
	}, nil
}

func (s Server) DeleteSession(ctx context.Context, in *ID) (*emptypb.Empty, error) {
	err := s.store.DeleteSession(ctx, &identifier{b: in.GetId()})
	if err != nil {
		return nil, fmt.Errorf("failed to delete session: %w", err)
	}
	return &emptypb.Empty{}, nil

}

func (s Server) DeleteUserSessions(ctx context.Context, in *ID) (*DeleteUserSessionsResponse, error) {
	count, err := s.store.DeleteUserSessions(ctx, &identifier{b: in.GetId()})
	if err != nil {
		return nil, fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return &DeleteUserSessionsResponse{Count: int32(count)}, nil

}

type identifier struct {
	b []byte
}

func (i *identifier) String() string {
	return string(i.b)
}
