// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ecpointgrouplaw

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Point", func() {
	Context("NewECPoint()", func() {
		It("Creates a new identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity, err := NewECPoint(curveList[i], nil, nil)
				Expect(err).To(Succeed())
				Expect(identity.curve).To(Equal(curveList[i]))
				Expect(identity.x).To(BeNil())
				Expect(identity.y).To(BeNil())
			}
		})

		It("Creates a new base point", func() {
			for i := 0; i < len(curveList); i++ {
				base, err := NewECPoint(curveList[i], curveList[i].Params().Gx, curveList[i].Params().Gy)
				Expect(err).To(Succeed())
				Expect(base.curve).To(Equal(curveList[i]))
				Expect(base.x).To(Equal(curveList[i].Params().Gx))
				Expect(base.y).To(Equal(curveList[i].Params().Gy))
			}
		})

		It("Not on curve", func() {
			for i := 0; i < len(curveList); i++ {
				base, err := NewECPoint(curveList[i], big.NewInt(1), big.NewInt(1))
				Expect(err).To(Equal(ErrInvalidPoint))
				Expect(base).To(BeNil())
			}
		})
	})

	Context("NewIdentity()", func() {
		It("Creates a new identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.x).To(BeNil())
				Expect(identity.y).To(BeNil())
			}
		})
	})

	Context("NewBase()", func() {
		It("Creates a new base point", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.x).To(Equal(curveList[i].Params().Gx))
				Expect(base.y).To(Equal(curveList[i].Params().Gy))
			}
		})
	})

	Context("IsIdentity()", func() {
		It("Point is an identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.IsIdentity()).To(BeTrue())
			}
		})

		It("Point is not an identity element", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.IsIdentity()).To(BeFalse())
			}
		})
	})

	Context("Neg()", func() {
		It("Point is the identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				result := identity.Neg()
				Expect(result.IsIdentity()).To(BeTrue())
			}
		})

		It("Negative of the base point", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				expected := base.ScalarMult(new(big.Int).Sub(base.curve.Params().N, big1))
				result := base.Neg()
				Expect(expected.Equal(result)).To(BeTrue())
			}
		})
	})

	Context("String()", func() {
		It("Returns the string format", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.String()).To(Equal(fmt.Sprintf("(x, y) =(%s, %s)", base.x, base.y)))
			}
		})
	})

	Context("Add()", func() {
		It("Verify 2 + (N-2) = identity element, where N is the order of a given elliptic curve group", func() {
			for i := 0; i < len(curveList); i++ {
				minus2 := big.NewInt(-2)
				ECPoint1 := ScalarBaseMult(curveList[i], new(big.Int).Mod(minus2, curveList[i].Params().N))
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(2))
				expected, err := NewECPoint(curveList[i], nil, nil)
				Expect(err).To(BeNil())

				result, err := ECPoint1.Add(ECPoint2)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify identity( N*G ) + 5566*G = 5566G", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint1 := ScalarBaseMult(curveList[i], new(big.Int).Set(curveList[i].Params().N))
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				expected := ScalarBaseMult(curveList[i], big.NewInt(5566))

				result, err := ECPoint1.Add(ECPoint2)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify 5566*G + identity(0*G) = 5566G", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint2 := ScalarBaseMult(curveList[i], new(big.Int).Set(curveList[i].Params().N))
				expected := ScalarBaseMult(curveList[i], big.NewInt(5566))

				result, err := ECPoint1.Add(ECPoint2)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify 5*G +5*G = 10*G", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5))
				expected := ScalarBaseMult(curveList[i], big.NewInt(10))

				result, err := ECPoint1.Add(ECPoint2)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify 3*G +5*G = 8*G", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(3))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5))
				expected := ScalarBaseMult(curveList[i], big.NewInt(8))

				result, err := ECPoint1.Add(ECPoint2)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expected))
			}
		})

		It("Verify 0*G +0*G = 0*G", func() {
			for i := 0; i < len(curveList); i++ {
				identity1 := NewIdentity(curveList[i])
				identity2 := NewIdentity(curveList[i])
				expected := ScalarBaseMult(curveList[i], big.NewInt(0))
				result, err := identity1.Add(identity2)
				Expect(err).To(BeNil())
				Expect(result.x).Should(BeNil())
				Expect(result.y).Should(BeNil())
				Expect(expected.x).Should(BeNil())
				Expect(expected.y).Should(BeNil())
			}
		})

		It("Verify different elliptic curves", func() {
			for i := 0; i < len(curveList); i++ {
				point1 := ScalarBaseMult(curveList[i], big.NewInt(3))
				point2 := ScalarBaseMult(curveList[(i+1)%len(curveList)], big.NewInt(5))

				result, err := point1.Add(point2)
				Expect(err).To(Equal(ErrDifferentCurve))
				Expect(result).To(BeNil())
			}
		})

		It("point1 not on curve", func() {
			for i := 0; i < len(curveList); i++ {
				point1 := &ECPoint{
					curve: curveList[i],
					x:     big.NewInt(1),
					y:     big.NewInt(1),
				}
				point2 := NewBase(curveList[i])

				result, err := point1.Add(point2)
				Expect(err).To(Equal(ErrInvalidPoint))
				Expect(result).To(BeNil())
			}
		})

		It("point2 not on curve", func() {
			for i := 0; i < len(curveList); i++ {
				point1 := NewBase(curveList[i])
				point2 := &ECPoint{
					curve: curveList[i],
					x:     big.NewInt(1),
					y:     big.NewInt(1),
				}

				result, err := point1.Add(point2)
				Expect(err).To(Equal(ErrInvalidPoint))
				Expect(result).To(BeNil())
			}
		})
	})

	Context("ScalarMult()", func() {
		It("Verify -3*(0*G))", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				result := identity.ScalarMult(big.NewInt(-3))
				Expect(result.x).To(BeNil())
				Expect(result.y).To(BeNil())
			}
		})
		It("Verify 0*(0*G))", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				result := identity.ScalarMult(big.NewInt(0))
				Expect(result.x).To(BeNil())
				Expect(result.y).To(BeNil())
			}
		})
	})

	Context("GetX()", func() {
		It("Point is an identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.GetX()).To(BeNil())
			}
		})

		It("Point is the base point", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.GetX()).To(Equal(curveList[i].Params().Gx))
			}
		})
	})

	Context("GetY()", func() {
		It("Point is an identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.GetY()).To(BeNil())
			}
		})

		It("Point is the base point", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.GetY()).To(Equal(curveList[i].Params().Gy))
			}
		})
	})

	Context("GetCurve()", func() {
		It("Get curve", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.GetCurve()).To(Equal(curveList[i]))
			}
		})
	})

	Context("IsSameCurve()", func() {
		It("Same curve", func() {
			for i := 0; i < len(curveList); i++ {
				point1 := NewIdentity(curveList[i])
				point2 := NewBase(curveList[i])
				Expect(point1.IsSameCurve(point2)).To(BeTrue())
			}
		})

		It("Different curve", func() {
			for i := 0; i < len(curveList); i++ {
				point1 := NewIdentity(curveList[i])
				point2 := NewBase(curveList[(i+1)%len(curveList)])
				Expect(point1.IsSameCurve(point2)).To(BeFalse())
			}
		})
	})

	Context("Copy()", func() {
		It("Point is an identity element", func() {
			for i := 0; i < len(curveList); i++ {
				identity := NewIdentity(curveList[i])
				Expect(identity.Copy()).To(Equal(identity))
			}
		})

		It("Point is the base point", func() {
			for i := 0; i < len(curveList); i++ {
				base := NewBase(curveList[i])
				Expect(base.Copy()).To(Equal(base))
			}
		})
	})

	Context("Equal()", func() {
		It("Verify identity element", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(0))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(0))

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeTrue())
			}
		})

		It("Verify two different point: one is the identity element and another is 2", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(0))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(2))

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeFalse())
			}
		})

		It("Verify two elements are equal", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeTrue())
			}
		})

		It("Verify N is different(i.e. different curve)", func() {
			for i := 1; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1 := ScalarBaseMult(curveList[0], big.NewInt(5566))

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeFalse())
			}
		})

		It("Verify Failure case for Point1: x is nil, y is not nil", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1.x = nil

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeFalse())
			}
		})

		It("Verify Failure case for Point2: x is nil, y is not nil", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint2.x = nil

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeFalse())
			}
		})

		It("Verify Failure case for Point1: x is not nil, y is nil", func() {
			for i := 0; i < len(curveList); i++ {
				ECPoint2 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1 := ScalarBaseMult(curveList[i], big.NewInt(5566))
				ECPoint1.y = nil

				result := ECPoint1.Equal(ECPoint2)
				Expect(result).To(BeFalse())
			}
		})
	})

	Context("ToEcPointMessage()/ToPoint()", func() {
		DescribeTable("Successful conversion", func(curveType EcPointMessage_Curve, curve elliptic.Curve) {
			x := curve.Params().Gx
			y := curve.Params().Gy
			p, err := NewECPoint(curve, x, y)
			Expect(err).Should(BeNil())
			gotP, err := p.ToEcPointMessage()
			Expect(err).Should(BeNil())
			Expect(gotP).Should(Equal(&EcPointMessage{
				Curve: curveType,
				X:     x.Bytes(),
				Y:     y.Bytes(),
			}))
			gotPt, err := gotP.ToPoint()
			Expect(err).Should(BeNil())
			Expect(p).Should(Equal(gotPt))
		},
			Entry("P224", EcPointMessage_P224, elliptic.P224()),
			Entry("P256", EcPointMessage_P256, elliptic.P256()),
			Entry("P384", EcPointMessage_P384, elliptic.P384()),
			Entry("S256", EcPointMessage_S256, btcec.S256()),
		)

		DescribeTable("Point is the identity element", func(curveType EcPointMessage_Curve, curve elliptic.Curve) {
			p := NewIdentity(curve)
			gotP, err := p.ToEcPointMessage()
			Expect(err).Should(BeNil())
			Expect(gotP).Should(Equal(&EcPointMessage{
				Curve: curveType,
			}))
			gotPt, err := gotP.ToPoint()
			Expect(err).Should(BeNil())
			Expect(p).Should(Equal(gotPt))
		},
			Entry("P224", EcPointMessage_P224, elliptic.P224()),
			Entry("P256", EcPointMessage_P256, elliptic.P256()),
			Entry("P384", EcPointMessage_P384, elliptic.P384()),
			Entry("S256", EcPointMessage_S256, btcec.S256()),
		)

		Context("Invalid curve", func() {
			It("ToEcPointMessage()", func() {
				// We don't support P521
				p := NewIdentity(elliptic.P521())
				gotP, err := p.ToEcPointMessage()
				Expect(err).Should(Equal(ErrInvalidCurve))
				Expect(gotP).Should(BeNil())
			})

			It("ToPoint()", func() {
				const UnSupportedEcPointMessage EcPointMessage_Curve = 4
				msg := &EcPointMessage{
					Curve: UnSupportedEcPointMessage,
				}
				p, err := msg.ToPoint()
				Expect(err).Should(Equal(ErrInvalidCurve))
				Expect(p).Should(BeNil())
			})
		})

		It("Invalid point", func() {
			var msg *EcPointMessage
			p, err := msg.ToPoint()
			Expect(err).Should(Equal(ErrInvalidPoint))
			Expect(p).Should(BeNil())
		})
	})
})
