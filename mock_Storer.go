// Code generated by mockery v2.40.1. DO NOT EDIT.

package gosesh

import (
	context "context"

	uuid "github.com/google/uuid"
	mock "github.com/stretchr/testify/mock"
)

// MockStorer is an autogenerated mock type for the Storer type
type MockStorer struct {
	mock.Mock
}

type MockStorer_Expecter struct {
	mock *mock.Mock
}

func (_m *MockStorer) EXPECT() *MockStorer_Expecter {
	return &MockStorer_Expecter{mock: &_m.Mock}
}

// CreateSession provides a mock function with given fields: ctx, req
func (_m *MockStorer) CreateSession(ctx context.Context, req CreateSessionRequest) (*Session, error) {
	ret := _m.Called(ctx, req)

	if len(ret) == 0 {
		panic("no return value specified for CreateSession")
	}

	var r0 *Session
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, CreateSessionRequest) (*Session, error)); ok {
		return rf(ctx, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, CreateSessionRequest) *Session); ok {
		r0 = rf(ctx, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Session)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, CreateSessionRequest) error); ok {
		r1 = rf(ctx, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_CreateSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateSession'
type MockStorer_CreateSession_Call struct {
	*mock.Call
}

// CreateSession is a helper method to define mock.On call
//   - ctx context.Context
//   - req CreateSessionRequest
func (_e *MockStorer_Expecter) CreateSession(ctx interface{}, req interface{}) *MockStorer_CreateSession_Call {
	return &MockStorer_CreateSession_Call{Call: _e.mock.On("CreateSession", ctx, req)}
}

func (_c *MockStorer_CreateSession_Call) Run(run func(ctx context.Context, req CreateSessionRequest)) *MockStorer_CreateSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(CreateSessionRequest))
	})
	return _c
}

func (_c *MockStorer_CreateSession_Call) Return(_a0 *Session, _a1 error) *MockStorer_CreateSession_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_CreateSession_Call) RunAndReturn(run func(context.Context, CreateSessionRequest) (*Session, error)) *MockStorer_CreateSession_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteSession provides a mock function with given fields: ctx, sessionID
func (_m *MockStorer) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	ret := _m.Called(ctx, sessionID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteSession")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) error); ok {
		r0 = rf(ctx, sessionID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockStorer_DeleteSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteSession'
type MockStorer_DeleteSession_Call struct {
	*mock.Call
}

// DeleteSession is a helper method to define mock.On call
//   - ctx context.Context
//   - sessionID uuid.UUID
func (_e *MockStorer_Expecter) DeleteSession(ctx interface{}, sessionID interface{}) *MockStorer_DeleteSession_Call {
	return &MockStorer_DeleteSession_Call{Call: _e.mock.On("DeleteSession", ctx, sessionID)}
}

func (_c *MockStorer_DeleteSession_Call) Run(run func(ctx context.Context, sessionID uuid.UUID)) *MockStorer_DeleteSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockStorer_DeleteSession_Call) Return(_a0 error) *MockStorer_DeleteSession_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockStorer_DeleteSession_Call) RunAndReturn(run func(context.Context, uuid.UUID) error) *MockStorer_DeleteSession_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteUserSessions provides a mock function with given fields: ctx, userID
func (_m *MockStorer) DeleteUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUserSessions")
	}

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (int, error)); ok {
		return rf(ctx, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) int); ok {
		r0 = rf(ctx, userID)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_DeleteUserSessions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteUserSessions'
type MockStorer_DeleteUserSessions_Call struct {
	*mock.Call
}

// DeleteUserSessions is a helper method to define mock.On call
//   - ctx context.Context
//   - userID uuid.UUID
func (_e *MockStorer_Expecter) DeleteUserSessions(ctx interface{}, userID interface{}) *MockStorer_DeleteUserSessions_Call {
	return &MockStorer_DeleteUserSessions_Call{Call: _e.mock.On("DeleteUserSessions", ctx, userID)}
}

func (_c *MockStorer_DeleteUserSessions_Call) Run(run func(ctx context.Context, userID uuid.UUID)) *MockStorer_DeleteUserSessions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockStorer_DeleteUserSessions_Call) Return(_a0 int, _a1 error) *MockStorer_DeleteUserSessions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_DeleteUserSessions_Call) RunAndReturn(run func(context.Context, uuid.UUID) (int, error)) *MockStorer_DeleteUserSessions_Call {
	_c.Call.Return(run)
	return _c
}

// GetSession provides a mock function with given fields: ctx, sessionID
func (_m *MockStorer) GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	ret := _m.Called(ctx, sessionID)

	if len(ret) == 0 {
		panic("no return value specified for GetSession")
	}

	var r0 *Session
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*Session, error)); ok {
		return rf(ctx, sessionID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *Session); ok {
		r0 = rf(ctx, sessionID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Session)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, sessionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_GetSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetSession'
type MockStorer_GetSession_Call struct {
	*mock.Call
}

// GetSession is a helper method to define mock.On call
//   - ctx context.Context
//   - sessionID uuid.UUID
func (_e *MockStorer_Expecter) GetSession(ctx interface{}, sessionID interface{}) *MockStorer_GetSession_Call {
	return &MockStorer_GetSession_Call{Call: _e.mock.On("GetSession", ctx, sessionID)}
}

func (_c *MockStorer_GetSession_Call) Run(run func(ctx context.Context, sessionID uuid.UUID)) *MockStorer_GetSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockStorer_GetSession_Call) Return(_a0 *Session, _a1 error) *MockStorer_GetSession_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_GetSession_Call) RunAndReturn(run func(context.Context, uuid.UUID) (*Session, error)) *MockStorer_GetSession_Call {
	_c.Call.Return(run)
	return _c
}

// GetUser provides a mock function with given fields: ctx, userID
func (_m *MockStorer) GetUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for GetUser")
	}

	var r0 *User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*User, error)); ok {
		return rf(ctx, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *User); ok {
		r0 = rf(ctx, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_GetUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUser'
type MockStorer_GetUser_Call struct {
	*mock.Call
}

// GetUser is a helper method to define mock.On call
//   - ctx context.Context
//   - userID uuid.UUID
func (_e *MockStorer_Expecter) GetUser(ctx interface{}, userID interface{}) *MockStorer_GetUser_Call {
	return &MockStorer_GetUser_Call{Call: _e.mock.On("GetUser", ctx, userID)}
}

func (_c *MockStorer_GetUser_Call) Run(run func(ctx context.Context, userID uuid.UUID)) *MockStorer_GetUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockStorer_GetUser_Call) Return(_a0 *User, _a1 error) *MockStorer_GetUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_GetUser_Call) RunAndReturn(run func(context.Context, uuid.UUID) (*User, error)) *MockStorer_GetUser_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateSession provides a mock function with given fields: ctx, sessionID, req
func (_m *MockStorer) UpdateSession(ctx context.Context, sessionID uuid.UUID, req UpdateSessionValues) (*Session, error) {
	ret := _m.Called(ctx, sessionID, req)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSession")
	}

	var r0 *Session
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, UpdateSessionValues) (*Session, error)); ok {
		return rf(ctx, sessionID, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, UpdateSessionValues) *Session); ok {
		r0 = rf(ctx, sessionID, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Session)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, UpdateSessionValues) error); ok {
		r1 = rf(ctx, sessionID, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_UpdateSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateSession'
type MockStorer_UpdateSession_Call struct {
	*mock.Call
}

// UpdateSession is a helper method to define mock.On call
//   - ctx context.Context
//   - sessionID uuid.UUID
//   - req UpdateSessionValues
func (_e *MockStorer_Expecter) UpdateSession(ctx interface{}, sessionID interface{}, req interface{}) *MockStorer_UpdateSession_Call {
	return &MockStorer_UpdateSession_Call{Call: _e.mock.On("UpdateSession", ctx, sessionID, req)}
}

func (_c *MockStorer_UpdateSession_Call) Run(run func(ctx context.Context, sessionID uuid.UUID, req UpdateSessionValues)) *MockStorer_UpdateSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID), args[2].(UpdateSessionValues))
	})
	return _c
}

func (_c *MockStorer_UpdateSession_Call) Return(_a0 *Session, _a1 error) *MockStorer_UpdateSession_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_UpdateSession_Call) RunAndReturn(run func(context.Context, uuid.UUID, UpdateSessionValues) (*Session, error)) *MockStorer_UpdateSession_Call {
	_c.Call.Return(run)
	return _c
}

// UpsertUser provides a mock function with given fields: ctx, req
func (_m *MockStorer) UpsertUser(ctx context.Context, req UpsertUserRequest) (uuid.UUID, error) {
	ret := _m.Called(ctx, req)

	if len(ret) == 0 {
		panic("no return value specified for UpsertUser")
	}

	var r0 uuid.UUID
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, UpsertUserRequest) (uuid.UUID, error)); ok {
		return rf(ctx, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, UpsertUserRequest) uuid.UUID); ok {
		r0 = rf(ctx, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(uuid.UUID)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, UpsertUserRequest) error); ok {
		r1 = rf(ctx, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStorer_UpsertUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpsertUser'
type MockStorer_UpsertUser_Call struct {
	*mock.Call
}

// UpsertUser is a helper method to define mock.On call
//   - ctx context.Context
//   - req UpsertUserRequest
func (_e *MockStorer_Expecter) UpsertUser(ctx interface{}, req interface{}) *MockStorer_UpsertUser_Call {
	return &MockStorer_UpsertUser_Call{Call: _e.mock.On("UpsertUser", ctx, req)}
}

func (_c *MockStorer_UpsertUser_Call) Run(run func(ctx context.Context, req UpsertUserRequest)) *MockStorer_UpsertUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(UpsertUserRequest))
	})
	return _c
}

func (_c *MockStorer_UpsertUser_Call) Return(_a0 uuid.UUID, _a1 error) *MockStorer_UpsertUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStorer_UpsertUser_Call) RunAndReturn(run func(context.Context, UpsertUserRequest) (uuid.UUID, error)) *MockStorer_UpsertUser_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockStorer creates a new instance of MockStorer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockStorer(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockStorer {
	mock := &MockStorer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
