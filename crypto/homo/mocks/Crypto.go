// Code generated by mockery v2.49.1. DO NOT EDIT.

package mocks

import (
	big "math/big"

	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	elliptic "github.com/getamis/alice/crypto/elliptic"

	homo "github.com/getamis/alice/crypto/homo"

	mock "github.com/stretchr/testify/mock"
)

// Crypto is an autogenerated mock type for the Crypto type
type Crypto struct {
	mock.Mock
}

// Add provides a mock function with given fields: c1, c2
func (_m *Crypto) Add(c1 []byte, c2 []byte) ([]byte, error) {
	ret := _m.Called(c1, c2)

	if len(ret) == 0 {
		panic("no return value specified for Add")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, []byte) ([]byte, error)); ok {
		return rf(c1, c2)
	}
	if rf, ok := ret.Get(0).(func([]byte, []byte) []byte); ok {
		r0 = rf(c1, c2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, []byte) error); ok {
		r1 = rf(c1, c2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Decrypt provides a mock function with given fields: c
func (_m *Crypto) Decrypt(c []byte) ([]byte, error) {
	ret := _m.Called(c)

	if len(ret) == 0 {
		panic("no return value specified for Decrypt")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) ([]byte, error)); ok {
		return rf(c)
	}
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(c)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(c)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Encrypt provides a mock function with given fields: m
func (_m *Crypto) Encrypt(m []byte) ([]byte, error) {
	ret := _m.Called(m)

	if len(ret) == 0 {
		panic("no return value specified for Encrypt")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) ([]byte, error)); ok {
		return rf(m)
	}
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(m)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(m)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetMessageRange provides a mock function with given fields: fieldOrder
func (_m *Crypto) GetMessageRange(fieldOrder *big.Int) *big.Int {
	ret := _m.Called(fieldOrder)

	if len(ret) == 0 {
		panic("no return value specified for GetMessageRange")
	}

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*big.Int) *big.Int); ok {
		r0 = rf(fieldOrder)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	return r0
}

// GetMtaProof provides a mock function with given fields: curve, beta, a
func (_m *Crypto) GetMtaProof(curve elliptic.Curve, beta *big.Int, a *big.Int) ([]byte, error) {
	ret := _m.Called(curve, beta, a)

	if len(ret) == 0 {
		panic("no return value specified for GetMtaProof")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(elliptic.Curve, *big.Int, *big.Int) ([]byte, error)); ok {
		return rf(curve, beta, a)
	}
	if rf, ok := ret.Get(0).(func(elliptic.Curve, *big.Int, *big.Int) []byte); ok {
		r0 = rf(curve, beta, a)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(elliptic.Curve, *big.Int, *big.Int) error); ok {
		r1 = rf(curve, beta, a)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPubKey provides a mock function with given fields:
func (_m *Crypto) GetPubKey() homo.Pubkey {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetPubKey")
	}

	var r0 homo.Pubkey
	if rf, ok := ret.Get(0).(func() homo.Pubkey); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(homo.Pubkey)
		}
	}

	return r0
}

// MulConst provides a mock function with given fields: c, scalar
func (_m *Crypto) MulConst(c []byte, scalar *big.Int) ([]byte, error) {
	ret := _m.Called(c, scalar)

	if len(ret) == 0 {
		panic("no return value specified for MulConst")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, *big.Int) ([]byte, error)); ok {
		return rf(c, scalar)
	}
	if rf, ok := ret.Get(0).(func([]byte, *big.Int) []byte); ok {
		r0 = rf(c, scalar)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, *big.Int) error); ok {
		r1 = rf(c, scalar)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewPubKeyFromBytes provides a mock function with given fields: _a0
func (_m *Crypto) NewPubKeyFromBytes(_a0 []byte) (homo.Pubkey, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for NewPubKeyFromBytes")
	}

	var r0 homo.Pubkey
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) (homo.Pubkey, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func([]byte) homo.Pubkey); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(homo.Pubkey)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ToPubKeyBytes provides a mock function with given fields:
func (_m *Crypto) ToPubKeyBytes() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ToPubKeyBytes")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// VerifyEnc provides a mock function with given fields: _a0
func (_m *Crypto) VerifyEnc(_a0 []byte) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for VerifyEnc")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]byte) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VerifyMtaProof provides a mock function with given fields: msg, curve, alpha, k
func (_m *Crypto) VerifyMtaProof(msg []byte, curve elliptic.Curve, alpha *big.Int, k *big.Int) (*ecpointgrouplaw.ECPoint, error) {
	ret := _m.Called(msg, curve, alpha, k)

	if len(ret) == 0 {
		panic("no return value specified for VerifyMtaProof")
	}

	var r0 *ecpointgrouplaw.ECPoint
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, elliptic.Curve, *big.Int, *big.Int) (*ecpointgrouplaw.ECPoint, error)); ok {
		return rf(msg, curve, alpha, k)
	}
	if rf, ok := ret.Get(0).(func([]byte, elliptic.Curve, *big.Int, *big.Int) *ecpointgrouplaw.ECPoint); ok {
		r0 = rf(msg, curve, alpha, k)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ecpointgrouplaw.ECPoint)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, elliptic.Curve, *big.Int, *big.Int) error); ok {
		r1 = rf(msg, curve, alpha, k)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewCrypto creates a new instance of Crypto. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCrypto(t interface {
	mock.TestingT
	Cleanup(func())
}) *Crypto {
	mock := &Crypto{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
