package recovery

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/utils"
)

var (
	ErrNotEnoughPeers = errors.New("not enough input peers, need at least 2")
	ErrAbsentCurve    = errors.New("curve is nil")
	ErrPubKeyMismatch = errors.New("pubkey derived from recovered privkey is not equal to pubkey provided")
)

type RecoveryPeer struct {
	share *big.Int
	bk    *birkhoffinterpolation.BkParameter
}

func RecoverPrivateKey(curve elliptic.Curve, threshold uint32, pubKey *ecpointgrouplaw.ECPoint, peers []RecoveryPeer) (*ecdsa.PrivateKey, error) {
	peerNum := len(peers)
	if peerNum < 2 {
		return nil, ErrNotEnoughPeers
	}
	if curve == nil {
		return nil, ErrAbsentCurve
	}
	if err := utils.EnsureThreshold(threshold, uint32(peerNum)); err != nil {
		return nil, err
	}

	bks := make([]*birkhoffinterpolation.BkParameter, 0, peerNum)
	shares := make([]*big.Int, 0, peerNum)
	for _, peer := range peers {
		shares = append(shares, peer.share)
		bks = append(bks, peer.bk)
	}

	fieldOrder := curve.Params().N
	bksInterface := birkhoffinterpolation.BkParameters(bks)

	if err := bksInterface.CheckValid(threshold, fieldOrder); err != nil {
		return nil, fmt.Errorf("BKS are incorrect: %w", err)
	}
	coefs, err := bksInterface.ComputeBkCoefficient(threshold, fieldOrder)
	if err != nil {
		return nil, err
	}

	privKeyBigInt := big.NewInt(0)
	for i, coef := range coefs {
		privKeyBigInt.Add(privKeyBigInt, new(big.Int).Mul(coef, shares[i]))
	}
	privKeyBigInt.Mod(privKeyBigInt, fieldOrder)

	derivedPubKey := ecpointgrouplaw.NewBase(curve).ScalarMult(privKeyBigInt)
	if !derivedPubKey.Equal(pubKey) {
		return nil, ErrPubKeyMismatch
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: *derivedPubKey.ToPubKey(),
		D:         privKeyBigInt,
	}

	return privKey, nil
}
