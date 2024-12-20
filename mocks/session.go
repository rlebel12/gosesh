// Code generated by mockery v2.42.0. DO NOT EDIT.

package mock_gosesh

import (
	gosesh "github.com/rlebel12/gosesh"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// Session is an autogenerated mock type for the Session type
type Session struct {
	mock.Mock
}

type Session_Expecter struct {
	mock *mock.Mock
}

func (_m *Session) EXPECT() *Session_Expecter {
	return &Session_Expecter{mock: &_m.Mock}
}

// ExpireAt provides a mock function with given fields:
func (_m *Session) ExpireAt() time.Time {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ExpireAt")
	}

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// Session_ExpireAt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExpireAt'
type Session_ExpireAt_Call struct {
	*mock.Call
}

// ExpireAt is a helper method to define mock.On call
func (_e *Session_Expecter) ExpireAt() *Session_ExpireAt_Call {
	return &Session_ExpireAt_Call{Call: _e.mock.On("ExpireAt")}
}

func (_c *Session_ExpireAt_Call) Run(run func()) *Session_ExpireAt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Session_ExpireAt_Call) Return(_a0 time.Time) *Session_ExpireAt_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Session_ExpireAt_Call) RunAndReturn(run func() time.Time) *Session_ExpireAt_Call {
	_c.Call.Return(run)
	return _c
}

// ID provides a mock function with given fields:
func (_m *Session) ID() gosesh.Identifier {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ID")
	}

	var r0 gosesh.Identifier
	if rf, ok := ret.Get(0).(func() gosesh.Identifier); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(gosesh.Identifier)
		}
	}

	return r0
}

// Session_ID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ID'
type Session_ID_Call struct {
	*mock.Call
}

// ID is a helper method to define mock.On call
func (_e *Session_Expecter) ID() *Session_ID_Call {
	return &Session_ID_Call{Call: _e.mock.On("ID")}
}

func (_c *Session_ID_Call) Run(run func()) *Session_ID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Session_ID_Call) Return(_a0 gosesh.Identifier) *Session_ID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Session_ID_Call) RunAndReturn(run func() gosesh.Identifier) *Session_ID_Call {
	_c.Call.Return(run)
	return _c
}

// IdleAt provides a mock function with given fields:
func (_m *Session) IdleAt() time.Time {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IdleAt")
	}

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// Session_IdleAt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IdleAt'
type Session_IdleAt_Call struct {
	*mock.Call
}

// IdleAt is a helper method to define mock.On call
func (_e *Session_Expecter) IdleAt() *Session_IdleAt_Call {
	return &Session_IdleAt_Call{Call: _e.mock.On("IdleAt")}
}

func (_c *Session_IdleAt_Call) Run(run func()) *Session_IdleAt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Session_IdleAt_Call) Return(_a0 time.Time) *Session_IdleAt_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Session_IdleAt_Call) RunAndReturn(run func() time.Time) *Session_IdleAt_Call {
	_c.Call.Return(run)
	return _c
}

// UserID provides a mock function with given fields:
func (_m *Session) UserID() gosesh.Identifier {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for UserID")
	}

	var r0 gosesh.Identifier
	if rf, ok := ret.Get(0).(func() gosesh.Identifier); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(gosesh.Identifier)
		}
	}

	return r0
}

// Session_UserID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserID'
type Session_UserID_Call struct {
	*mock.Call
}

// UserID is a helper method to define mock.On call
func (_e *Session_Expecter) UserID() *Session_UserID_Call {
	return &Session_UserID_Call{Call: _e.mock.On("UserID")}
}

func (_c *Session_UserID_Call) Run(run func()) *Session_UserID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Session_UserID_Call) Return(_a0 gosesh.Identifier) *Session_UserID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Session_UserID_Call) RunAndReturn(run func() gosesh.Identifier) *Session_UserID_Call {
	_c.Call.Return(run)
	return _c
}

// NewSession creates a new instance of Session. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSession(t interface {
	mock.TestingT
	Cleanup(func())
}) *Session {
	mock := &Session{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
