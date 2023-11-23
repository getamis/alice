package recovery

import (
	"math/big"
	"testing"

	"crypto/ecdsa"
	"crypto/rand"

	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Private Key Recovery", func() {

	Context("validation", func() {
		It("should fail on 0 peers provided", func() {
			result, err := RecoverPrivateKey(elliptic.Secp256k1(), 2, nil, []RecoveryPeer{})
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(ErrNotEnoughPeers))
		})
		It("should fail on 1 peer provided", func() {
			result, err := RecoverPrivateKey(elliptic.Secp256k1(), 2, nil, []RecoveryPeer{{}})
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(ErrNotEnoughPeers))
		})
		It("should fail if no curve provided", func() {
			result, err := RecoverPrivateKey(nil, 2, nil, []RecoveryPeer{{}, {}, {}})
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(ErrAbsentCurve))
		})
		It("should fail on invalid threshold provided", func() {
			result, err := RecoverPrivateKey(elliptic.Secp256k1(), 3, nil, []RecoveryPeer{{}, {}})
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(utils.ErrLargeThreshold))
			result, err = RecoverPrivateKey(elliptic.Secp256k1(), 1, nil, []RecoveryPeer{{}, {}})
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(utils.ErrSmallThreshold))
		})
		It("should fail on invalid BKs", func() {
			result, err := RecoverPrivateKey(elliptic.Secp256k1(), 2, nil, []RecoveryPeer{
				{
					share: nil,
					bk:    birkhoffinterpolation.NewBkParameter(nil, 0),
				},
				{
					share: nil,
					bk:    birkhoffinterpolation.NewBkParameter(nil, 0),
				},
				{
					share: nil,
					bk:    birkhoffinterpolation.NewBkParameter(nil, 0),
				},
			})
			Expect(result).Should(BeNil())
			Expect(err.Error()).Should(ContainSubstring("BKS are incorrect: invalid bks"))
		})
		It("should fail on invalid pubkey to match", func() {
			result, err := RecoverPrivateKey(elliptic.Secp256k1(), 2, nil, MakeRecoveryPeers(
				[]string{
					"104609342634350601677472000055166148093040084008779475605306409018125790763384",
					"24163161798290927046425102830821018901476566166011270959061926968896994036828",
					"63066954971367271319238473967771679083666721823457348774233036722916669993451",
				},
				[]string{
					"112236885864076099358310462008741642913349768825204638119688077310570757734766",
					"20713194488405082366064300662102750959499818497887478230897041769232303982022",
					"28909585968450592089400243672753269836965419090880450440411327286593499063726",
				},
			))
			Expect(result).Should(BeNil())
			Expect(err).Should(MatchError(ErrPubKeyMismatch))
		})
	})

	DescribeTable(
		"RecoverPrivateKey() ecdsa",
		func(curve elliptic.Curve, threshold int, testDkgData []RecoveryPeer, pubKey *ecpointgrouplaw.ECPoint) {
			privKey, err := RecoverPrivateKey(curve, uint32(threshold), pubKey, testDkgData)
			if err != nil {
				Expect(err).Should(BeNil())
			}

			data := []byte("some tx hash to sign")
			r, s, err := ecdsa.Sign(rand.Reader, privKey, data)
			Expect(err).Should(BeNil())

			Expect(ecdsa.Verify(&privKey.PublicKey, data, r, s)).Should(BeTrue())
		},
		Entry(
			"3/3 quorum",
			elliptic.Secp256k1(),
			2,
			MakeRecoveryPeers(
				[]string{
					"104609342634350601677472000055166148093040084008779475605306409018125790763384",
					"24163161798290927046425102830821018901476566166011270959061926968896994036828",
					"63066954971367271319238473967771679083666721823457348774233036722916669993451",
				},
				[]string{
					"112236885864076099358310462008741642913349768825204638119688077310570757734766",
					"20713194488405082366064300662102750959499818497887478230897041769232303982022",
					"28909585968450592089400243672753269836965419090880450440411327286593499063726",
				},
			),
			MakePubKey(
				"24951056819363353476818025996777971284120929729704886050366724870604080939790",
				"47651179196288923110559855714961823695288337160431011508811998037385251801902",
				elliptic.Secp256k1(),
			),
		),
		Entry(
			"2/3 quorum",
			elliptic.Secp256k1(),
			2,
			MakeRecoveryPeers(
				[]string{
					"104609342634350601677472000055166148093040084008779475605306409018125790763384",
					"63066954971367271319238473967771679083666721823457348774233036722916669993451",
				},
				[]string{
					"112236885864076099358310462008741642913349768825204638119688077310570757734766",
					"28909585968450592089400243672753269836965419090880450440411327286593499063726",
				},
			),
			MakePubKey(
				"24951056819363353476818025996777971284120929729704886050366724870604080939790",
				"47651179196288923110559855714961823695288337160431011508811998037385251801902",
				elliptic.Secp256k1(),
			),
		),
	)

	DescribeTable(
		"RecoverPrivateKey() eddsa",
		func(curve elliptic.Curve, threshold int, testDkgData []RecoveryPeer, pubKey *ecpointgrouplaw.ECPoint) {
			privKey, err := RecoverPrivateKey(curve, uint32(threshold), pubKey, testDkgData)
			if err != nil {
				Expect(err).Should(BeNil())
			}

			data := []byte("some tx hash to sign")

			priv, pub, err := edwards.PrivKeyFromScalar(edwards.Edwards(), privKey.D.Bytes())
			Expect(err).Should(BeNil())
			Expect(pub.X.Cmp(pubKey.GetX())).Should(BeZero())
			Expect(pub.Y.Cmp(pubKey.GetY())).Should(BeZero())

			r, s, err := edwards.Sign(edwards.Edwards(), priv, data)
			Expect(err).Should(BeNil())

			Expect(edwards.Verify(edwards.NewPublicKey(edwards.Edwards(), pubKey.GetX(), pubKey.GetY()), data, r, s)).Should(BeTrue())
		},
		Entry(
			"3/3 quorum",
			elliptic.Ed25519(),
			2,
			MakeRecoveryPeers(
				[]string{
					"3502109557042490544838324442604034236999785614721987641956076911051160401944",
					"1103861929415814231586749933547278014778471148545711715092471976804157872704",
					"3399052917932924022114908121544556052008108447896375201293210781395183567243",
				},
				[]string{
					"7230155880034998276592769027360707810284675615875867582236795781241695079804",
					"5272874863729098099670216622703886559502263393787069547616689911708461775143",
					"3925249267150905323417733485189576433991970087669974755241055176173816181663",
				},
			),
			MakePubKey(
				"38485518761780627407120390846860597853897888230510522807636948334195936489504",
				"10129321156846869276162967126585445016496573486379629538155569021664335120579",
				elliptic.Ed25519(),
			),
		),
		Entry(
			"2/3 quorum",
			elliptic.Ed25519(),
			2,
			MakeRecoveryPeers(
				[]string{
					"3502109557042490544838324442604034236999785614721987641956076911051160401944",
					"3399052917932924022114908121544556052008108447896375201293210781395183567243",
				},
				[]string{
					"7230155880034998276592769027360707810284675615875867582236795781241695079804",
					"3925249267150905323417733485189576433991970087669974755241055176173816181663",
				},
			),
			MakePubKey(
				"38485518761780627407120390846860597853897888230510522807636948334195936489504",
				"10129321156846869276162967126585445016496573486379629538155569021664335120579",
				elliptic.Ed25519(),
			),
		),
	)

})

func TestBinaryField(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Privaate Key Recovery Test")
}

func MakeRecoveryPeers(shares, bkxs []string) []RecoveryPeer {
	recPeers := make([]RecoveryPeer, 0, len(shares))
	for index, share := range shares {
		share, _ := big.NewInt(0).SetString(share, 10)
		bkx, _ := new(big.Int).SetString(bkxs[index], 10)
		recPeers = append(recPeers, RecoveryPeer{
			share: share,
			bk:    birkhoffinterpolation.NewBkParameter(bkx, 0),
			// TODO: 0 its a rank, test it with different ranks
		})
	}
	return recPeers
}

func MakePubKey(x, y string, curve elliptic.Curve) *ecpointgrouplaw.ECPoint {
	pubX, _ := big.NewInt(0).SetString(x, 10)
	pubY, _ := big.NewInt(0).SetString(y, 10)
	pubKey, _ := ecpointgrouplaw.NewECPoint(curve, pubX, pubY)
	return pubKey
}
