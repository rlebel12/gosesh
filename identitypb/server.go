package identitypb

import (
	context "context"
	"strconv"

	identity "github.com/rlebel12/identity"
)

type IdentityService struct {
	UnimplementedIdentityServiceServer
	identity *identity.Identity
}

func NewIdentityService(i *identity.Identity) *IdentityService {
	return &IdentityService{
		identity: i,
	}
}

func (s *IdentityService) GetExpireSessionCookie(ctx context.Context, req *GetExpireSessionCookieRequest) (*Cookie, error) {
	cookie := s.identity.ExpireSessionCookie()
	return &Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Domain:   cookie.Domain,
		Path:     cookie.Path,
		Expires:  cookie.Expires.Unix(),
		SameSite: strconv.Itoa(int(cookie.SameSite)),
		HttpOnly: cookie.HttpOnly,
		Secure:   cookie.Secure,
	}, nil
}

func Here() string {
	return "here"
}
