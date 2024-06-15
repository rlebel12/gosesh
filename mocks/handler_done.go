// Code generated by mockery v2.42.0. DO NOT EDIT.

package mock_gosesh

import (
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// HandlerDone is an autogenerated mock type for the HandlerDone type
type HandlerDone struct {
	mock.Mock
}

type HandlerDone_Expecter struct {
	mock *mock.Mock
}

func (_m *HandlerDone) EXPECT() *HandlerDone_Expecter {
	return &HandlerDone_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: _a0, _a1, _a2
func (_m *HandlerDone) Execute(_a0 http.ResponseWriter, _a1 *http.Request, _a2 error) {
	_m.Called(_a0, _a1, _a2)
}

// HandlerDone_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type HandlerDone_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - _a0 http.ResponseWriter
//   - _a1 *http.Request
//   - _a2 error
func (_e *HandlerDone_Expecter) Execute(_a0 interface{}, _a1 interface{}, _a2 interface{}) *HandlerDone_Execute_Call {
	return &HandlerDone_Execute_Call{Call: _e.mock.On("Execute", _a0, _a1, _a2)}
}

func (_c *HandlerDone_Execute_Call) Run(run func(_a0 http.ResponseWriter, _a1 *http.Request, _a2 error)) *HandlerDone_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.ResponseWriter), args[1].(*http.Request), args[2].(error))
	})
	return _c
}

func (_c *HandlerDone_Execute_Call) Return() *HandlerDone_Execute_Call {
	_c.Call.Return()
	return _c
}

func (_c *HandlerDone_Execute_Call) RunAndReturn(run func(http.ResponseWriter, *http.Request, error)) *HandlerDone_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewHandlerDone creates a new instance of HandlerDone. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewHandlerDone(t interface {
	mock.TestingT
	Cleanup(func())
}) *HandlerDone {
	mock := &HandlerDone{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
