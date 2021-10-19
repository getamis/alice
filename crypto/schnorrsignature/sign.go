// Copyright © 2021 AMIS Technologies
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

package schnorrsignature

import (
	"errors"
	//"crypto/elliptic"
	"crypto/sha512"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/schnorrsignature/edwards25519"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/crypto/zkproof"
	"github.com/golang/protobuf/ptypes/any"
)

const (
	// maxRetry defines the max retries to generate proof
	maxRetry = 100
)

var (
	bit254 = new(big.Int).Lsh(big.NewInt(1), 253)

	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
)

// ECPoint is the struct for an elliptic curve point.
type Participant struct {
	threshold uint32
	message   []byte
	share     *big.Int
	bk        *birkhoffinterpolation.BkParameter
	pubKey    *ecpointgrouplaw.ECPoint

	Y     *ecpointgrouplaw.ECPoint
	YList map[*big.Int]*ecpointgrouplaw.ECPoint

	allbks            birkhoffinterpolation.BkParameters
	allbksCoefficient map[*big.Int]*big.Int

	e *big.Int
	d *big.Int

	ellList map[*big.Int]*big.Int
	riList  map[*big.Int]*ecpointgrouplaw.ECPoint
	r       *ecpointgrouplaw.ECPoint

	c *big.Int
}

// TODO: should check all values
func NewParticipant(threshold uint32, share *big.Int, message []byte, ownbk *birkhoffinterpolation.BkParameter, pubKey *ecpointgrouplaw.ECPoint, allbks birkhoffinterpolation.BkParameters) *Participant {
	return &Participant{
		threshold: threshold,
		message:   message,
		share:     share,
		bk:        ownbk,
		pubKey:    pubKey,
		allbks:    allbks,
	}
}

func (p *Participant) Round0() (*CommitmentMsg, error) {
	curve := p.pubKey.GetCurve()
	e, err := utils.RandomPositiveInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	d, err := utils.RandomPositiveInt(curve.Params().N)
	if err != nil {
		return nil, err
	}
	D := ecpointgrouplaw.ScalarBaseMult(curve, d)
	msgD, err := D.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	E := ecpointgrouplaw.ScalarBaseMult(curve, e)
	msgE, err := E.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	Y, err := zkproof.NewBaseSchorrMessage(curve, p.share)
	if err != nil {
		return nil, err
	}
	p.Y, err = Y.V.ToPoint()
	if err != nil {
		return nil, err
	}
	p.e = e
	p.d = d
	return &CommitmentMsg{
		// TODO: Should Replace x to bk or any identifier.
		X:  p.bk.GetX().Bytes(),
		D:  msgD,
		E:  msgE,
		SG: Y,
	}, nil
}

func (p *Participant) Round1(allMsg0s []*CommitmentMsg) (*PartialSignatureMsg, error) {
	identify := ecpointgrouplaw.NewIdentity(p.pubKey.GetCurve())
	curveN := identify.GetCurve().Params().N
	bk, err := p.allbks.ComputeBkCoefficient(p.threshold, curveN)
	if err != nil {
		return nil, err
	}

	// Establish the list of Di, Ei, Yi, Bk-Coefficient
	DList := make(map[*big.Int]*ecpointgrouplaw.ECPoint)
	EList := make(map[*big.Int]*ecpointgrouplaw.ECPoint)
	sGList := make(map[*big.Int]*ecpointgrouplaw.ECPoint)
	allBkCoefficient := make(map[*big.Int]*big.Int)
	G := ecpointgrouplaw.NewBase(p.pubKey.GetCurve())
	for i := 0; i < len(allMsg0s); i++ {
		x := new(big.Int).SetBytes(allMsg0s[i].X)
		tempD, err := allMsg0s[i].D.ToPoint()
		if err != nil {
			return nil, err
		}
		DList[x] = tempD
		tempE, err := allMsg0s[i].E.ToPoint()
		if err != nil {
			return nil, err
		}
		EList[x] = tempE
		err = allMsg0s[i].SG.Verify(G)
		if err != nil {
			return nil, err
		}
		tempsG, err := allMsg0s[i].SG.GetV().ToPoint()
		if err != nil {
			return nil, err
		}
		sGList[x] = tempsG
		for i := 0; i < len(p.allbks); i++ {
			if p.allbks[i].GetX().Cmp(x) == 0 {
				allBkCoefficient[x] = bk[i]
				break
			}
		}
	}
	p.allbksCoefficient = allBkCoefficient
	p.YList = sGList

	B := computeBList(p.allbks, DList, EList)
	ellList, err := computeElli(EList, p.message, B, curveN)
	if err != nil {
		return nil, err
	}
	// Compute ell_i*E_i+D_i
	RiList, err := computeRiList(DList, EList, ellList)
	if err != nil {
		return nil, err
	}

	R := identify.Copy()
	for k, _ := range RiList {
		//fmt.Println(" RiList:", RiList[k])
		R, err = R.Add(RiList[k])
		if err != nil {
			return nil, err
		}
	}

	//fmt.Println(" R:", R)

	c := SHAPoints(p.pubKey, R, p.message)

	// Compute own si = di+ ei*li + c bi xi
	xCoord := p.bk.GetX()
	var s *big.Int
	for x, _ := range ellList {
		if x.Cmp(xCoord) == 0 {
			s = new(big.Int).Mul(p.e, ellList[x])
			temp := new(big.Int).Mul(c, p.allbksCoefficient[x])
			temp = temp.Mul(temp, p.share)
			s.Add(s, temp)
			s.Add(s, p.d)
			s.Mod(s, curveN)
			break
		}
	}

	p.ellList = ellList
	p.riList = RiList
	p.c = c
	p.r = R
	return &PartialSignatureMsg{
		X:  xCoord.Bytes(),
		Si: s.Bytes(),
	}, nil
}

// TODO: This part can be an aggregator.
func (p *Participant) Round2(parSigMsg []*PartialSignatureMsg) (*ecpointgrouplaw.ECPoint, *big.Int, error) {
	siList := make(map[*big.Int]*big.Int)
	s := big.NewInt(0)

	for x, _ := range p.riList {
		for i := 0; i < len(parSigMsg); i++ {
			if x.Cmp(new(big.Int).SetBytes(parSigMsg[i].X)) == 0 {
				si := new(big.Int).SetBytes(parSigMsg[i].Si)
				siList[x] = si
				s.Add(s, si)
				break
			}
		}
	}

	G := ecpointgrouplaw.NewBase(p.pubKey.GetCurve())

	for x, _ := range siList {
		siG := G.ScalarMult(siList[x])
		ri := p.riList[x]
		cbi := new(big.Int).Mul(p.allbksCoefficient[x], p.c)
		cbi.Mod(cbi, p.pubKey.GetCurve().Params().N)

		comparePart, err := p.YList[x].ScalarMult(cbi).Add(ri)
		if err != nil {
			return nil, nil, err
		}
		if !comparePart.Equal(siG) {
			// fmt.Println("p.allbksCoefficient[x]:", p.allbksCoefficient[x])
			// fmt.Println("siList[x]:", siList[x])
			// fmt.Println("p.riList[[x]:", p.riList[x])

			return nil, nil, ErrVerifyFailure
		}
	}
	return p.r, s, nil
}

func SHAPoints(pubKey, R *ecpointgrouplaw.ECPoint, message []byte) *big.Int {
	encodedR := ecpointEncoding(R)
	encodedPubKey := ecpointEncoding(pubKey)
	h := sha512.New()
	h.Write(encodedR[:])

	h.Write(encodedPubKey[:])
	h.Write(message)
	digest := h.Sum(nil)
	result := new(big.Int).SetBytes(utils.ReverseByte(digest))
	return result.Mod(result, R.GetCurve().Params().N)
}

func ecpointEncoding(pt *ecpointgrouplaw.ECPoint) *[32]byte {
	var result, X, Y [32]byte
	var x, y edwards25519.FieldElement
	if pt.Equal(ecpointgrouplaw.NewIdentity(pt.GetCurve())) {
		// TODO: We need to check this
		Y[0] = 1
	} else {
		tempX := pt.GetX().Bytes()
		tempY := pt.GetY().Bytes()

		for i := 0; i < len(tempX); i++ {
			index := len(tempX) - 1 - i
			X[index] = tempX[i]
			Y[index] = tempY[i]
		}
	}
	edwards25519.FeFromBytes(&x, &X)
	edwards25519.FeFromBytes(&y, &Y)
	edwards25519.FeToBytes(&result, &y)
	result[31] ^= edwards25519.FeIsNegative(&x) << 7
	return &result
}

// Get xi,Di,Ei,.......
func computeBList(bks birkhoffinterpolation.BkParameters, DList, EList map[*big.Int]*ecpointgrouplaw.ECPoint) []byte {
	result := make([]byte, len(DList))
	separationSign := []byte(",")
	for i := 0; i < len(bks); i++ {
		for x, _ := range EList {
			if bks[i].GetX().Cmp(x) == 0 {
				result = append(result, x.Bytes()...)
				result = append(result, separationSign...)
				result = append(result, DList[x].GetX().Bytes()...)
				result = append(result, separationSign...)
				result = append(result, DList[x].GetY().Bytes()...)
				result = append(result, separationSign...)
				break
			}
		}
	}
	return result
}

func computeRiList(DList, EList map[*big.Int]*ecpointgrouplaw.ECPoint, ellList map[*big.Int]*big.Int) (map[*big.Int]*ecpointgrouplaw.ECPoint, error) {
	var err error
	result := make(map[*big.Int]*ecpointgrouplaw.ECPoint)
	// Compute ell_i*E_i+D_i
	for k, _ := range EList {
		temp := EList[k].ScalarMult(ellList[k])
		temp, err = temp.Add(DList[k])
		if err != nil {
			return nil, err
		}
		result[k] = temp
	}
	return result, nil
}

func computeElli(EList map[*big.Int]*ecpointgrouplaw.ECPoint, message []byte, B []byte, fieldOrder *big.Int) (map[*big.Int]*big.Int, error) {
	result := make(map[*big.Int]*big.Int, len(EList))
	for x, _ := range EList {
		temp, err := utils.HashProtosToInt(x.Bytes(), &any.Any{
			Value: message,
		}, &any.Any{
			Value: B,
		})
		if err != nil {
			return nil, err
		}
		tempMod := new(big.Int).Mod(temp, bit254)
		if tempMod.Cmp(fieldOrder) > 0 {
			for j := 0; j < maxRetry; j++ {
				if j == maxRetry {
					return nil, ErrExceedMaxRetry
				}
				temp, err = utils.HashProtosToInt(temp.Bytes(), &any.Any{
					Value: temp.Bytes(),
				}, &any.Any{
					Value: B,
				})
				tempMod = new(big.Int).Mod(temp, bit254)
				if err != nil {
					return nil, err
				}
				if tempMod.Cmp(fieldOrder) < 0 {
					result[x] = temp
					break
				}
			}
			continue
		}
		result[x] = temp
	}
	return result, nil
}
