package examples

// func NewMemoryStore() *MemoryStore {
// 	return &MemoryStore{
// 		Users:    map[gosesh.Identifier]User{},
// 		Sessions: map[gosesh.Identifier]gosesh.Session{},
// 	}
// }

// type (
// 	User struct {
// 		id    uuid.UUID
// 		email string
// 	}
// )

// type MemoryStore struct {
// 	Users    map[gosesh.Identifier]User
// 	Sessions map[gosesh.Identifier]gosesh.Session
// }

// func (ms *MemoryStore) UpsertUser(ctx context.Context, udr gosesh.OAuthUser) (uuid.UUID, error) {
// 	switch d := udr.(type) {
// 	case providers.DiscordUser:
// 		slog.Info("Discord user", "id", d.ID, "username", d.Username, "email", d.Email, "verified", d.Verified)
// 	// case providers.GoogleUser:
// 	// 	slog.Info("Google user", "id", d.ID, "email", d.Email)
// 	default:
// 		slog.Info("Unknown user", "id", udr.String())
// 	}
// 	for _, user := range ms.Users {
// 		if user.email == udr.String() {
// 			return user.id, nil
// 		}
// 	}
// 	u := User{
// 		id: uuid.New(),
// 	}
// 	ms.Users[u.id] = u
// 	return u.id, nil
// }

// func (ms *MemoryStore) CreateSession(ctx context.Context, req gosesh.CreateSessionRequest) (*gosesh.Session, error) {
// 	s := &gosesh.Session{
// 		ID:       uuid.New(),
// 		UserID:   req.UserID,
// 		IdleAt:   req.IdleAt,
// 		ExpireAt: req.ExpireAt,
// 	}
// 	ms.Sessions[s.ID] = s
// 	return s, nil
// }

// func (ms *MemoryStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*gosesh.Session, error) {
// 	s, ok := ms.Sessions[sessionID]
// 	if !ok {
// 		return nil, errors.New("session not found")
// 	}
// 	return s, nil
// }

// func (ms *MemoryStore) UpdateSession(ctx context.Context, sessionID uuid.UUID, req gosesh.UpdateSessionValues) (*gosesh.Session, error) {
// 	s, ok := ms.Sessions[sessionID]
// 	if !ok {
// 		return nil, errors.New("session not found")
// 	}
// 	s.IdleAt = req.IdleAt
// 	s.ExpireAt = req.ExpireAt
// 	ms.Sessions[s.ID] = s
// 	return s, nil
// }

// func (ms *MemoryStore) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
// 	delete(ms.Sessions, sessionID)
// 	return nil
// }

// func (ms *MemoryStore) DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
// 	var count int
// 	for _, s := range ms.Sessions {
// 		if s.UserID == userID {
// 			delete(ms.Sessions, s.ID)
// 			count++
// 		}
// 	}
// 	return count, nil
// }
