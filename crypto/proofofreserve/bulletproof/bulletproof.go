// Copyright © 2022 AMIS Technologies
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

package bulletproof

import (
	"errors"
	"math"

	"math/big"

	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	bls12381 "github.com/kilic/bls12-381"
)

const (
	// SaltSize is based on blake2b256
	SaltSize = 32
	// maxGenHashValue defines the max retries to generate hash value by reject sampling
	maxGenNHashValue = 100
)

var (
	blsEngine = bls12381.NewEngine()
	g2        = bls12381.NewG2()
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	// Base Point
	G2 = blsEngine.G2.One()

	SEPARATION1 = []byte("lak2u93u!")
	SEPARATION2 = []byte("kl3fj;s")
	SEPARATION3 = []byte("la923@")

	//ErrVerifyFailure is returned if the verification is failure.
	ErrVerifyFailure = errors.New("the verification is failure")
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")
)

type PublicParameter struct {
	UpperBoundOfRange *big.Int
	boldG             []*bls12381.PointG2
	boldH             []*bls12381.PointG2
	G                 *bls12381.PointG2
	H                 *bls12381.PointG2
	boldGHAndGHVByte  []byte
}

type Prover struct {
	v     *big.Int
	gamma *big.Int
	V     *bls12381.PointG2

	PublicParameter *PublicParameter
	aL              []int
	aR              []int
	A               *bls12381.PointG2
}

func NewPublicParameter(G, H *bls12381.PointG2, n uint) (*PublicParameter, error) {
	boldG := make([]*bls12381.PointG2, n)
	boldH := make([]*bls12381.PointG2, n)
	groupOrder := g2.Q()

	for i := 0; i < len(boldG); i++ {
		randomValue, err := utils.RandomPositiveInt(groupOrder)
		if err != nil {
			return nil, err
		}
		boldG[i] = g2.MulScalarBig(blsEngine.G2.New(), G, randomValue)
		randomValue, err = utils.RandomPositiveInt(groupOrder)
		if err != nil {
			return nil, err
		}
		boldH[i] = g2.MulScalarBig(blsEngine.G2.New(), H, randomValue)
	}
	return &PublicParameter{
		UpperBoundOfRange: new(big.Int).Lsh(big1, n),
		boldG:             boldG,
		boldH:             boldH,
		G:                 G,
		H:                 H,
	}, nil
}

// C = v*G+gamma*H
func NewProver(PublicParameter *PublicParameter, secret, gamma *big.Int, C *bls12381.PointG2) *Prover {

	msg := computeBasicParameter(PublicParameter.boldG, PublicParameter.boldH, PublicParameter.G, PublicParameter.H, C)
	PublicParameter.boldGHAndGHVByte = msg
	return &Prover{
		v:               secret,
		gamma:           gamma,
		V:               C,
		PublicParameter: PublicParameter,
	}
}

func (p *Prover) InitialProveData() (*ProverMessage, error) {
	n := len(p.PublicParameter.boldG)
	aL := make([]int, n)
	aR := make([]int, n)
	order := g2.Q()
	A := g2.Zero()
	temp := g2.Zero()
	// compute A = g^{aL}h^{aR}h^\alpha
	for i := 0; i < p.v.BitLen(); i++ {
		if p.v.Bit(i) == 1 {
			aL[i] = 1
			g2.Add(A, A, p.PublicParameter.boldG[i])
			continue
		}
		g2.Add(temp, temp, p.PublicParameter.boldH[i])
		aR[i] = -1
	}
	for i := p.v.BitLen(); i < len(aL); i++ {
		g2.Add(temp, temp, p.PublicParameter.boldH[i])
		aR[i] = -1
	}

	g2.Neg(temp, temp)
	alpha, err := utils.RandomInt(order)
	if err != nil {
		return nil, err
	}
	Halpha := g2.MulScalarBig(blsEngine.G2.New(), p.PublicParameter.H, alpha)
	g2.Add(A, A, Halpha)
	g2.Add(A, A, temp)

	// Generate challenge y, z
	y, saltY, z, saltZ, err := computeChallengeRangeProof(p.PublicParameter.boldGHAndGHVByte, A, order)
	if err != nil {
		return nil, err
	}

	aLHat := computeALHat(aL, z)
	ARHat, yPowerSlice, alphaHat := computeARHatAndalphaHat(aR, y, z, alpha, p.gamma)
	Ahat := computeAHat(p.PublicParameter.boldG, p.PublicParameter.boldH, A, p.PublicParameter.G, p.V, y, z, yPowerSlice)
	saltInner, salt, L, R, AWIP, BWIP, r, s, delta, err := p.zkWIP(Ahat, aLHat, ARHat, yPowerSlice[1:len(yPowerSlice)-1], alphaHat)
	if err != nil {
		return nil, err
	}
	return &ProverMessage{
		Lpoints:        L,
		Rpoints:        R,
		WIPA:           AWIP,
		WIPB:           BWIP,
		R:              r.Bytes(),
		S:              s.Bytes(),
		Delta:          delta.Bytes(),
		A:              g2.ToBytes(A),
		SaltY:          saltY,
		SaltZ:          saltZ,
		SaltInnerZKWIP: saltInner,
		SaltFinalZKWIP: salt,
	}, nil
}

func computeChallengeRangeProof(basicParameter []byte, A *bls12381.PointG2, order *big.Int) (*big.Int, []byte, *big.Int, []byte, error) {
	msg := append(basicParameter, SEPARATION2...)
	msg = append(msg, g2.ToBytes(A)...)
	proofMsg := &any.Any{
		Value: []byte(msg),
	}
	// Assume that the result of hash function is uniformly distribution in [0,2^256).
	ySalt, y, err := HashToIntForBLSCurveByRejectSampling(order, proofMsg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	zSalt, z, err := HashToIntForBLSCurveByRejectSampling(order, proofMsg, &any.Any{
		Value: y.Bytes(),
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return y, ySalt, z, zSalt, nil
}

func HashToIntForBLSCurveByRejectSampling(order *big.Int, msgs ...proto.Message) ([]byte, *big.Int, error) {
	for i := 0; i < maxGenNHashValue; i++ {
		salt, err := utils.GenRandomBytes(SaltSize)
		if err != nil {
			return nil, nil, err
		}
		// Assume that the result of hash function is uniformly distribution in [0,2^256).
		result, err := utils.HashProtosToInt(salt, msgs...)
		if err != nil {
			return nil, nil, err
		}
		// because order < 2^255
		result.Rsh(result, 1)
		err = utils.InRange(result, big1, order)
		if err == nil {
			return salt, result, nil
		}
	}
	return nil, nil, ErrExceedMaxRetry
}

func HashToIntForBLSCurve(salt []byte, msgs ...proto.Message) (*big.Int, error) {
	result, err := utils.HashProtosToInt(salt, msgs...)
	if err != nil {
		return nil, err
	}
	result.Rsh(result, 1)
	return result, nil
}

func computeBasicParameter(boldG, boldH []*bls12381.PointG2, G, H, C *bls12381.PointG2) []byte {
	msg := g2.ToBytes(G)
	msg = append(msg, SEPARATION1...)
	msg = append(msg, g2.ToBytes(H)...)
	msg = append(msg, SEPARATION1...)
	msg = append(msg, g2.ToBytes(C)...)
	for i := 0; i < len(boldG); i++ {
		msg = append(msg, SEPARATION1...)
		msg = append(msg, g2.ToBytes(boldG[i])...)
		msg = append(msg, SEPARATION1...)
		msg = append(msg, g2.ToBytes(boldH[i])...)
	}
	return msg
}

func (zkMsg *ProverMessage) Verify(publicParameter *PublicParameter, C *bls12381.PointG2) error {
	boldG := publicParameter.boldG
	boldH := publicParameter.boldH
	G := publicParameter.G
	H := publicParameter.H

	n := len(boldG)
	order := g2.Q()
	A, err := g2.FromBytes(zkMsg.A)
	if err != nil {
		return err
	}

	basicParameter := computeBasicParameter(boldG, boldH, G, H, C)
	msg := append(basicParameter, SEPARATION2...)
	msg = append(msg, g2.ToBytes(A)...)
	y, err := HashToIntForBLSCurve(zkMsg.SaltY, &any.Any{
		Value: []byte(msg),
	})
	if err != nil {
		return err
	}
	err = utils.InRange(y, big1, order)
	if err != nil {
		return err
	}
	z, err := HashToIntForBLSCurve(zkMsg.SaltZ, &any.Any{
		Value: []byte(msg),
	}, &any.Any{
		Value: y.Bytes(),
	})
	if err != nil {
		return err
	}
	err = utils.InRange(z, big1, order)
	if err != nil {
		return err
	}
	yPowerSlice := make([]*big.Int, n+2)
	yPowerSlice[0] = big.NewInt(1)
	yclone := new(big.Int).Set(y)
	yPowerSlice[1] = y
	for i := 2; i < len(yPowerSlice); i++ {
		yclone.Mul(yclone, y)
		yclone.Mod(yclone, order)
		yPowerSlice[i] = new(big.Int).Set(yclone)
	}

	P := computeAHat(boldG, boldH, A, G, C, y, z, yPowerSlice)

	// Fast Verification
	numberOfe := int(math.Log2(float64(n)))
	eSlice := make([]*big.Int, numberOfe)
	eInverseSlice := make([]*big.Int, numberOfe)
	LPoints := make([]*bls12381.PointG2, numberOfe)
	RPoints := make([]*bls12381.PointG2, numberOfe)
	// Establish all basic data
	for i := 0; i < len(eInverseSlice); i++ {
		LPoint, err := g2.FromBytes(zkMsg.Lpoints[i])
		if err != nil {
			return err
		}
		RPoint, err := g2.FromBytes(zkMsg.Rpoints[i])
		if err != nil {
			return err
		}
		msg := computePointMessage(basicParameter, LPoint, RPoint)
		e, err := HashToIntForBLSCurve(zkMsg.SaltInnerZKWIP[i], &any.Any{
			Value: []byte(msg),
		})
		if err != nil {
			return err
		}
		err = utils.InRange(e, big1, order)
		if err != nil {
			return err
		}
		eInverseSlice[i] = new(big.Int).ModInverse(e, order)
		eSlice[i] = e
		LPoints[i] = LPoint
		RPoints[i] = RPoint
	}

	yInverse := new(big.Int).ModInverse(y, order)

	// WARN: Paper has typo. This version is correct!
	s := make([]*big.Int, n)
	spai := make([]*big.Int, n)
	yInversePower := big.NewInt(1)
	for i := 0; i < len(s); i++ {
		si := new(big.Int).Set(yInversePower)
		sipai := big.NewInt(1)
		bigiMinusOne := big.NewInt(int64(i))
		for j := 0; j < bigiMinusOne.BitLen(); j++ {
			index := numberOfe - 1 - j
			if bigiMinusOne.Bit(j) == 1 {
				si.Mul(si, eSlice[index])
				si.Mod(si, order)
				sipai.Mul(sipai, eInverseSlice[index])
				sipai.Mod(sipai, order)
				continue
			}
			si.Mul(si, eInverseSlice[index])
			si.Mod(si, order)
			sipai.Mul(sipai, eSlice[index])
			sipai.Mod(sipai, order)
		}
		for j := bigiMinusOne.BitLen(); j < numberOfe; j++ {
			index := numberOfe - 1 - j
			si.Mul(si, eInverseSlice[index])
			si.Mod(si, order)
			sipai.Mul(sipai, eSlice[index])
			sipai.Mod(sipai, order)
		}
		s[i] = si
		spai[i] = sipai
		yInversePower.Mul(yInversePower, yInverse)
		yInversePower.Mod(yInversePower, order)
	}

	WIPA, err := g2.FromBytes(zkMsg.WIPA)
	if err != nil {
		return err
	}
	WIPB, err := g2.FromBytes(zkMsg.WIPB)
	if err != nil {
		return err
	}
	msg = computePointMessage(basicParameter, WIPA, WIPB)
	e, err := HashToIntForBLSCurve(zkMsg.SaltFinalZKWIP, &any.Any{
		Value: []byte(msg),
	})
	if err != nil {
		return err
	}

	err = utils.InRange(e, big1, order)
	if err != nil {
		return err
	}
	R := new(big.Int).SetBytes(zkMsg.R)
	S := new(big.Int).SetBytes(zkMsg.S)
	delta := new(big.Int).SetBytes(zkMsg.Delta)

	compare := InnerProductPoint(s, boldG)
	tempValue := new(big.Int).Mul(R, e)
	tempValue.Mod(tempValue, order)
	g2.MulScalarBig(compare, compare, tempValue)

	tempPoint := InnerProductPoint(spai, boldH)
	tempValue = new(big.Int).Mul(S, e)
	tempValue.Mod(tempValue, order)
	g2.MulScalarBig(tempPoint, tempPoint, tempValue)
	g2.Add(compare, compare, tempPoint)

	tempValue = new(big.Int).Mul(R, S)
	tempValue.Mod(tempValue, order)
	tempValue.Mul(tempValue, y)
	tempValue.Mod(tempValue, order)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), G, tempValue)
	g2.Add(compare, compare, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), H, delta)
	g2.Add(compare, compare, tempPoint)

	anotherPart := g2.New().Set(P)
	for i := 0; i < numberOfe; i++ {
		eSquare := new(big.Int).Mul(eSlice[i], eSlice[i])
		eSquare.Mod(eSquare, order)
		eInverseSquare := new(big.Int).Mul(eInverseSlice[i], eInverseSlice[i])
		eInverseSquare.Mod(eInverseSquare, order)
		temp := g2.MulScalarBig(blsEngine.G2.New(), LPoints[i], eSquare)
		g2.Add(anotherPart, anotherPart, temp)
		temp = g2.MulScalarBig(blsEngine.G2.New(), RPoints[i], eInverseSquare)
		g2.Add(anotherPart, anotherPart, temp)
	}

	eSquare := new(big.Int).Mul(e, e)
	eSquare.Mod(eSquare, order)
	g2.MulScalarBig(anotherPart, anotherPart, eSquare)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), WIPA, e)
	g2.Add(anotherPart, anotherPart, tempPoint)
	g2.Add(anotherPart, anotherPart, WIPB)
	if !g2.Equal(compare, anotherPart) {
		return ErrVerifyFailure
	}
	return nil
}

func computeALHat(aL []int, z *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))
	for i := 0; i < len(result); i++ {
		temp := new(big.Int).Neg(z)
		if aL[i] == 0 {
			result[i] = temp
			continue
		}
		result[i] = temp.Add(temp, big1)
	}
	return result
}

func computeAHat(boldG, boldH []*bls12381.PointG2, A, G, V *bls12381.PointG2, y, z *big.Int, yPower []*big.Int) *bls12381.PointG2 {
	// Compute g^{-1^n z}*A
	n := len(boldG)
	order := g2.Q()
	zSquare := new(big.Int).Mul(z, z)
	zSquare.Mod(zSquare, order)
	result := g2.MulScalarBig(blsEngine.G2.New(), boldG[0], z)
	for i := 1; i < len(boldG); i++ {
		temp := g2.MulScalarBig(blsEngine.G2.New(), boldG[i], z)
		g2.Add(result, result, temp)
	}
	g2.Neg(result, result)
	g2.Add(result, result, A)

	// compute h^{2^n leftArrow{y}^n}
	for i := 0; i < len(boldH); i++ {
		tempValue := new(big.Int).Lsh(yPower[n-i], uint(i))
		tempValue.Add(tempValue, z)
		temp := g2.MulScalarBig(blsEngine.G2.New(), boldH[i], tempValue)
		g2.Add(result, result, temp)
	}

	// compute V^{n+1}
	g2.Add(result, result, g2.MulScalarBig(blsEngine.G2.New(), V, yPower[n+1]))

	exponent := new(big.Int).Sub(yPower[n+1], yPower[1])
	exponent.Mul(exponent, new(big.Int).Sub(z, zSquare))
	exponent.Mod(exponent, order)

	yMinus1Inverse := new(big.Int).Sub(yPower[1], big1)
	if yMinus1Inverse.Cmp(big0) != 0 {
		yMinus1Inverse.ModInverse(yMinus1Inverse, order)
		exponent.Mul(exponent, yMinus1Inverse)
		exponent.Mod(exponent, order)
	}

	yNPowerz := new(big.Int).Mul(yPower[n+1], z)
	yNPowerz.Mod(yNPowerz, order)
	temp := new(big.Int).Lsh(yNPowerz, uint(n))
	temp.Sub(temp, yNPowerz)
	exponent.Sub(exponent, temp)
	exponent.Mod(exponent, order)
	g2.Add(result, result, g2.MulScalarBig(blsEngine.G2.New(), G, exponent))
	return result
}

func computeARHatAndalphaHat(aR []int, y, z, alpha, gamma *big.Int) ([]*big.Int, []*big.Int, *big.Int) {
	result := make([]*big.Int, len(aR))
	order := g2.Q()
	yPowerSlice := make([]*big.Int, len(aR)+2)
	yPower := new(big.Int).Set(y)
	yPowerSlice[0] = big.NewInt(1)
	yPowerSlice[1] = new(big.Int).Set(y)
	index := 2
	up := len(result) - 1
	for i := up; i >= 0; i-- {
		temp := new(big.Int).Lsh(yPower, uint(i))
		temp.Add(temp, z)
		temp.Mod(temp, order)
		yPower.Mul(yPower, y)
		yPower.Mod(yPower, order)
		yPowerSlice[index] = new(big.Int).Set(yPower)
		index++
		if aR[i] == 0 {
			result[i] = temp
			continue
		}
		temp.Sub(temp, big1)
		result[i] = new(big.Int).Mod(temp, order)
	}

	alphaHat := new(big.Int).Mul(yPower, gamma)
	alphaHat.Add(alphaHat, alpha)
	return result, yPowerSlice, alphaHat.Mod(alphaHat, order)
}

func (p *Prover) zkWIP(PInput *bls12381.PointG2, aInput, bInput, y []*big.Int, alphaInput *big.Int) ([][]byte, []byte, [][]byte, [][]byte, []byte, []byte, *big.Int, *big.Int, *big.Int, error) {
	n := len(p.PublicParameter.boldG)
	order := g2.Q()
	boldG := p.PublicParameter.boldG
	boldH := p.PublicParameter.boldH
	a := aInput
	b := bInput
	alpha := alphaInput
	P := PInput
	numberOfTime := int(math.Log2(float64(n)))
	LSlice := make([][]byte, numberOfTime)
	RSlice := make([][]byte, numberOfTime)
	count := 0
	saltInner := make([][]byte, numberOfTime)

	for n > 1 {
		n = n >> 1
		dL, err := utils.RandomInt(order)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
		}
		dR, err := utils.RandomInt(order)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
		}

		cL := CircleDotProduct(a[:n], b[n:], y[:n], order)
		temp := ScalarProduct(y[n-1], a[n:], order)
		cR := CircleDotProduct(temp, b[:n], y[:n], order)
		ynPowerInverse := new(big.Int).ModInverse(y[n-1], order)
		L, R := computeLAndR(n, cL, cR, dL, dR, order, y[n-1], ynPowerInverse, a, b, boldG, boldH, p.PublicParameter.G, p.PublicParameter.H)

		// challenge
		salt, e, err := computeZKWIPChallenge(p.PublicParameter.boldGHAndGHVByte, L, R, order)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
		}

		saltInner[count] = salt
		LSlice[count] = g2.ToBytes(L)
		RSlice[count] = g2.ToBytes(R)
		count++

		eSquare := new(big.Int).Mul(e, e)
		eInverse := new(big.Int).ModInverse(e, order)
		eInverseSquare := new(big.Int).Mul(eInverse, eInverse)
		eInverseSquare.Mod(eInverseSquare, order)
		boldG, boldH, P = computeGhatHhatPhat(n, boldG, boldH, P, L, R, e, eInverse, eSquare, ynPowerInverse, order)

		ahat := ScalarProduct(e, a[:n], order)
		tempValue := new(big.Int).Mul(eInverse, y[n-1])
		tempValue.Mod(tempValue, order)
		ahat = Add(ahat, ScalarProduct(tempValue, a[n:], order), order)
		bhat := ScalarProduct(eInverse, b[:n], order)
		bhat = Add(bhat, ScalarProduct(e, b[n:], order), order)
		alphahat := new(big.Int).Mul(dL, eSquare)
		tempValue = new(big.Int).Mul(eInverseSquare, dR)
		alphahat.Add(alphahat, alpha)
		alphahat.Add(alphahat, tempValue)
		alphahat.Mod(alphahat, order)
		a = ahat
		b = bhat
		alpha = alphahat
	}
	r, err := utils.RandomInt(order)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	s, err := utils.RandomInt(order)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	delta, err := utils.RandomInt(order)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	eta, err := utils.RandomInt(order)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}

	A := g2.MulScalarBig(blsEngine.G2.New(), boldG[0], r)
	tempPoint := g2.MulScalarBig(blsEngine.G2.New(), boldH[0], s)
	g2.Add(A, A, tempPoint)
	rybAddsya := new(big.Int).Mul(y[0], b[0])
	rybAddsya.Mul(rybAddsya, r)
	rybAddsya.Mod(rybAddsya, order)
	tempValue := new(big.Int).Mul(y[0], a[0])
	tempValue.Mul(tempValue, s)
	tempValue.Mod(tempValue, order)
	rybAddsya.Add(rybAddsya, tempValue)
	rybAddsya.Mod(rybAddsya, order)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), p.PublicParameter.G, rybAddsya)
	g2.Add(A, A, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), p.PublicParameter.H, delta)
	g2.Add(A, A, tempPoint)

	B := g2.MulScalarBig(blsEngine.G2.New(), p.PublicParameter.H, eta)
	rys := new(big.Int).Mul(y[0], s)
	rys.Mul(rys, r)
	rys.Mod(rys, order)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), p.PublicParameter.G, rys)
	g2.Add(B, B, tempPoint)

	// compute e
	salt, e, err := computeZKWIPChallenge(p.PublicParameter.boldGHAndGHVByte, A, B, order)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}

	rpai := new(big.Int).Mul(a[0], e)
	rpai.Add(rpai, r)
	rpai.Mod(rpai, order)

	spai := new(big.Int).Mul(b[0], e)
	spai.Add(spai, s)
	spai.Mod(spai, order)

	// δ′ =η+δ·e+α·e2
	deltapai := new(big.Int).Mul(delta, e)
	tempValue = new(big.Int).Mul(e, e)
	tempValue.Mul(tempValue, alpha)
	tempValue.Mod(tempValue, order)
	deltapai.Add(deltapai, tempValue)
	deltapai.Add(deltapai, eta)
	deltapai.Mod(deltapai, order)

	return saltInner, salt, LSlice, RSlice, g2.ToBytes(A), g2.ToBytes(B), rpai, spai, deltapai, nil
}

func computePointMessage(basicParameter []byte, A, B *bls12381.PointG2) []byte {
	msg := append(basicParameter, SEPARATION3...)
	msg = append(msg, g2.ToBytes(A)...)
	msg = append(msg, SEPARATION3...)
	msg = append(msg, g2.ToBytes(B)...)
	return msg
}

func computeZKWIPChallenge(basicParameter []byte, A, B *bls12381.PointG2, order *big.Int) ([]byte, *big.Int, error) {
	msg := computePointMessage(basicParameter, A, B)
	proofMsg := &any.Any{
		Value: []byte(msg),
	}
	salt, result, err := HashToIntForBLSCurveByRejectSampling(order, proofMsg)
	if err != nil {
		return nil, nil, err
	}
	return salt, result, nil
}

func computeLAndR(n int, cL, cR, dL, dR, order, ynPower, ynPowerInverse *big.Int, a, b []*big.Int, boldG, boldH []*bls12381.PointG2, g, h *bls12381.PointG2) (*bls12381.PointG2, *bls12381.PointG2) {
	L := InnerProductPoint(ScalarProduct(ynPowerInverse, a[:n], order), boldG[n:])
	tempPoint := InnerProductPoint(b[n:], boldH[:n])
	g2.Add(L, L, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), g, cL)
	g2.Add(L, L, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), h, dL)
	g2.Add(L, L, tempPoint)

	R := InnerProductPoint(ScalarProduct(ynPower, a[n:], order), boldG[:n])
	tempPoint = InnerProductPoint(b[:n], boldH[n:])
	g2.Add(R, R, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), g, cR)
	g2.Add(R, R, tempPoint)
	tempPoint = g2.MulScalarBig(blsEngine.G2.New(), h, dR)
	g2.Add(R, R, tempPoint)
	return L, R
}

func computeGhatHhatPhat(n int, boldG, boldH []*bls12381.PointG2, P, L, R *bls12381.PointG2, e, eInverse, eSquare, ynPowerInverse, order *big.Int) ([]*bls12381.PointG2, []*bls12381.PointG2, *bls12381.PointG2) {
	eyMinus1nPower := new(big.Int).Mul(ynPowerInverse, e)
	eyMinus1nPower.Mod(eyMinus1nPower, order)
	boldGhat := HadamardProductGroup(ScalarProductPoint(eInverse, boldG[:n]), ScalarProductPoint(eyMinus1nPower, boldG[n:]))
	boldHHat := HadamardProductGroup(ScalarProductPoint(e, boldH[:n]), ScalarProductPoint(eInverse, boldH[n:]))
	Phat := g2.Neg(blsEngine.G2.New(), R)
	g2.Add(Phat, Phat, L)
	g2.MulScalarBig(Phat, Phat, eSquare)
	g2.Add(Phat, Phat, P)
	return boldGhat, boldHHat, Phat
}

func ScalarProductPoint(c *big.Int, points []*bls12381.PointG2) []*bls12381.PointG2 {
	result := make([]*bls12381.PointG2, len(points))
	for i := 0; i < len(result); i++ {
		temp := g2.MulScalarBig(blsEngine.G2.New(), points[i], c)
		result[i] = temp
	}
	return result
}

func InnerProductPoint(c []*big.Int, points []*bls12381.PointG2) *bls12381.PointG2 {
	result := g2.Zero()
	for i := 0; i < len(points); i++ {
		temp := g2.MulScalarBig(blsEngine.G2.New(), points[i], c[i])
		g2.Add(result, result, temp)
	}
	return result
}

func HadamardProductGroup(a, b []*bls12381.PointG2) []*bls12381.PointG2 {
	result := make([]*bls12381.PointG2, len(a))
	for i := 0; i < len(result); i++ {
		temp := g2.Add(blsEngine.G2.New(), a[i], b[i])
		result[i] = temp
	}
	return result
}
