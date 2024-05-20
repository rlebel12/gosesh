package grpc

import (
	context "context"

	"github.com/rlebel12/gosesh"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	UnimplementedGoseshServer
	store gosesh.Storer
}

func NewServer(store gosesh.Storer) Server {
	return Server{store: store}
}

func (s Server) GetSession(ctx context.Context, in *GetSessionRequest) (*Session, error) {
	session, err := s.store.GetSession(ctx, &identifier{b: in.GetId()})
	if err != nil {
		return nil, err
	}
	return &Session{
		Id:       []byte(session.ID.String()),
		UserId:   []byte(session.UserID.String()),
		IdleAt:   timestamppb.New(session.IdleAt),
		ExpireAt: timestamppb.New(session.ExpireAt),
	}, nil
}

type identifier struct {
	b []byte
}

func (i *identifier) String() string {
	return string(i.b)
}
