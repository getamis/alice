// Code generated by mockery v2.49.1. DO NOT EDIT.

package mocks

import (
	types "github.com/getamis/alice/types"
	mock "github.com/stretchr/testify/mock"
)

// Message is an autogenerated mock type for the Message type
type Message struct {
	mock.Mock
}

// GetId provides a mock function with given fields:
func (_m *Message) GetId() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetId")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetMessageType provides a mock function with given fields:
func (_m *Message) GetMessageType() types.MessageType {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetMessageType")
	}

	var r0 types.MessageType
	if rf, ok := ret.Get(0).(func() types.MessageType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(types.MessageType)
	}

	return r0
}

// IsValid provides a mock function with given fields:
func (_m *Message) IsValid() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IsValid")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// NewMessage creates a new instance of Message. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMessage(t interface {
	mock.TestingT
	Cleanup(func())
}) *Message {
	mock := &Message{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
