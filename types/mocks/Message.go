// Code generated by mockery v2.12.1. DO NOT EDIT.

package mocks

import (
	testing "testing"

	mock "github.com/stretchr/testify/mock"

	types "github.com/getamis/alice/types"
)

// Message is an autogenerated mock type for the Message type
type Message struct {
	mock.Mock
}

// GetId provides a mock function with given fields:
func (_m *Message) GetId() string {
	ret := _m.Called()

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

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// NewMessage creates a new instance of Message. It also registers the testing.TB interface on the mock and a cleanup function to assert the mocks expectations.
func NewMessage(t testing.TB) *Message {
	mock := &Message{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
