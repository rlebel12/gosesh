package proto

import (
	context "context"

	"github.com/google/uuid"
	"github.com/rlebel12/gosesh"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func NewServer(store gosesh.Storer) *Server {
	return &Server{store: store}
}

type Server struct {
	UnimplementedGoseshServer
	store gosesh.Storer
}

func (s *Server) GetSession(ctx context.Context, r *GetSessionRequest) (*GetSessionResponse, error) {
	id, err := uuid.ParseBytes(r.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id: %v", err)
	}
	session, err := s.store.GetSession(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "session not found: %v", err)
	}
	result := &GetSessionResponse{
		Session: &Session{
			Id: []byte(session.ID.String()),
			User: &User{
				Id: []byte(session.UserID.String()),
			},
			IdleAt:    timestamppb.New(session.IdleAt),
			ExpiresAt: timestamppb.New(session.ExpireAt),
		},
	}
	return result, nil
}

func (s *Server) DeleteSessionsForUser(ctx context.Context, r *DeleteSessionsForUserRequest) (*DeleteSessionsForUserResponse, error) {
	userID, err := uuid.ParseBytes(r.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user id: %v", err)
	}
	count, err := s.store.DeleteUserSessions(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user sessions: %v", err)
	}
	return &DeleteSessionsForUserResponse{Count: int32(count)}, nil
}
