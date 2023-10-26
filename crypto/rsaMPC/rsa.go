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

package mpcrsa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mathRandom "math/rand"

	"github.com/getamis/alice/crypto/utils"
)

const (
	maxRetry = 100
)

var (
	// ErrNonPrime is returned if N is nonprime
	ErrNonPrime = errors.New("N is nonprime")
	// ErrQNotPrime is returned if Q is nonprime
	ErrQNotPrime = errors.New("Q is nonprime")
	//ErrExceedMaxRetry is returned if we retried over times
	ErrExceedMaxRetry = errors.New("exceed max retries")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big4 = big.NewInt(4)

	// 16294579238595022365 = 3 * primeProducts[0]
	primeList = []int64{
		4, 3,
		5,
		7,
		11,
		13,
		17,
		19,
		23,
		29,
		31,
		37,
		41,
		43,
		47,
		53,
		59,
		61,
		67,
		71,
		73,
		79,
		83,
		89,
		97,
		101,
		103,
		107,
		109,
		113,
		127,
		131,
		137,
		139,
		149,
		151,
		157,
		163,
		167,
		173,
		179,
		181,
		191,
		193,
		197,
		199,
		211,
		223,
		227,
		229,
		233,
		239,
		241,
		251,
		257,
		263,
		269,
		271,
		277,
		281,
		283,
		293,
		307,
		311,
		313,
		317,
		331,
		337,
		347,
		349,
		353,
		359,
		367,
		373,
		379,
		383,
		389,
		397,
		401,
		409,
		419,
		421,
		431,
		433,
		439,
		443,
		449,
		457,
		461,
		463,
		467,
		479,
		487,
		491,
		499,
		503,
		509,
		521,
		523,
		541,
		547,
		557,
		563,
		569,
		571,
		577,
		587,
		593,
		599,
		601,
		607,
		613,
		617,
		619,
		631,
		641,
		643,
		647,
		653,
		659,
		661,
		673,
		677,
		683,
		691,
		701,
		709,
		719,
		727,
		733,
		739,
		743,
		751,
	}
	// without prime 3
	primes = [][]uint64{
		{
			5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
		},
		{
			59, 61, 67, 71, 73, 79, 83, 89, 97,
		},
		{
			101, 103, 107, 109, 113, 127, 131, 137, 139,
		},
		{
			149, 151, 157, 163, 167, 173, 179, 181,
		},
		{
			191, 193, 197, 199, 211, 223, 227, 229,
		},
		{
			233, 239, 241, 251, 257, 263, 269,
		},
		{
			271, 277, 281, 283, 293, 307, 311,
		},
		{
			317, 331, 337, 347, 349, 353, 359,
		},
		{
			367, 373, 379, 383, 389, 397, 401,
		},
		{
			409, 419, 421, 431, 433, 439, 443,
		},
		{
			449, 457, 461, 463, 467, 479, 487,
		},
		{
			491, 499, 503, 509, 521, 523, 541,
		},
		{
			557, 563, 569, 571, 577, 587,
		},
		{
			593, 599, 601, 607, 613, 617,
		},
		{
			619, 631, 641, 643, 647, 653,
		},
		{
			659, 661, 673, 677, 683, 691,
		},
		{
			701, 709, 719, 727, 733, 739,
		},
		{
			743, 751, 757, 761, 769, 773,
		},
		{
			787, 797, 809, 811, 821, 823,
		},
		{
			827, 829, 839, 853, 857, 859,
		},
		{
			863, 877, 881, 883, 887, 907,
		},
		{
			911, 919, 929, 937, 941, 947,
		},
		{
			953, 967, 971, 977, 983, 991,
		},
		{
			997, 1009, 1013, 1019, 1021, 1031,
		},
		{
			1033, 1039, 1049, 1051, 1061, 1063,
		},
		{
			1069, 1087, 1091, 1093, 1097, 1103,
		},
		{
			1109, 1117, 1123, 1129, 1151, 1153,
		},
		{
			1163, 1171, 1181, 1187, 1193, 1201,
		},
		{
			1213, 1217, 1223, 1229, 1231, 1237,
		},
		{
			1249, 1259, 1277, 1279, 1283, 1289,
		},
		{
			1291, 1297, 1301, 1303, 1307, 1319,
		},
		{
			1321, 1327, 1361, 1367, 1373, 1381,
		},
		{
			1399, 1409, 1423, 1427, 1429, 1433,
		},
		{
			1439, 1447, 1451, 1453, 1459,
		},
		{
			1471, 1481, 1483, 1487, 1489,
		},
		{
			1493, 1499, 1511, 1523, 1531,
		},
		{
			1543, 1549, 1553, 1559, 1567,
		},
		{
			1571, 1579, 1583, 1597, 1601,
		},
		{
			1607, 1609, 1613, 1619, 1621,
		},
		{
			1627, 1637, 1657, 1663, 1667,
		},
		{
			1669, 1693, 1697, 1699, 1709,
		},
		{
			1721, 1723, 1733, 1741, 1747,
		},
		{
			1753, 1759, 1777, 1783, 1787,
		},
		{
			1789, 1801, 1811, 1823, 1831,
		},
		{
			1847, 1861, 1867, 1871, 1873,
		},
		{
			1877, 1879, 1889, 1901, 1907,
		},
		{
			1913, 1931, 1933, 1949, 1951,
		},
		{
			1973, 1979, 1987, 1993, 1997,
		},
		{
			1999, 2003, 2011, 2017, 2027,
		},
		{
			2029, 2039, 2053, 2063, 2069,
		},
		{
			2081, 2083, 2087, 2089, 2099,
		},
		{
			2111, 2113, 2129, 2131, 2137,
		},
		{
			2141, 2143, 2153, 2161, 2179,
		},
		{
			2203, 2207, 2213, 2221, 2237,
		},
		{
			2239, 2243, 2251, 2267, 2269,
		},
		{
			2273, 2281, 2287, 2293, 2297,
		},
		{
			2309, 2311, 2333, 2339, 2341,
		},
		{
			2347, 2351, 2357, 2371, 2377,
		},
		{
			2381, 2383, 2389, 2393, 2399,
		},
		{
			2411, 2417, 2423, 2437, 2441,
		},
		{
			2447, 2459, 2467, 2473, 2477,
		},
		{
			2503, 2521, 2531, 2539, 2543,
		},
		{
			2549, 2551, 2557, 2579, 2591,
		},
		{
			2593, 2609, 2617, 2621, 2633,
		},
		{
			2647, 2657, 2659, 2663, 2671,
		},
		{
			2677, 2683, 2687, 2689, 2693,
		},
		{
			2699, 2707, 2711, 2713, 2719,
		},
		{
			2729, 2731, 2741, 2749, 2753,
		},
		{
			2767, 2777, 2789, 2791, 2797,
		},
		{
			2801, 2803, 2819, 2833, 2837,
		},
		{
			2843, 2851, 2857, 2861, 2879,
		},
		{
			2887, 2897, 2903, 2909, 2917,
		},
		{
			2927, 2939, 2953, 2957, 2963,
		},
		{
			2969, 2971, 2999, 3001, 3011,
		},

		{
			3019, 3023, 3037, 3041, 3049,
		},
		{
			3061, 3067, 3079, 3083, 3089,
		},
		{
			3109, 3119, 3121, 3137, 3163,
		},
	}

	primeProducts = []*big.Int{
		new(big.Int).SetUint64(5431526412865007455),
		new(big.Int).SetUint64(6437928885641249269),
		new(big.Int).SetUint64(4343678784233766587),
		new(big.Int).SetUint64(538945254996352681),
		new(big.Int).SetUint64(3534749459194562711),
		new(big.Int).SetUint64(61247129307885343),
		new(big.Int).SetUint64(166996819598798201),
		new(big.Int).SetUint64(542676746453092519),
		new(big.Int).SetUint64(1230544604996048471),
		new(big.Int).SetUint64(2618501576975440661),
		new(big.Int).SetUint64(4771180125133726009),
		new(big.Int).SetUint64(9247077179230889629),
		new(big.Int).SetUint64(34508483876655991),
		new(big.Int).SetUint64(49010633640532829),
		new(big.Int).SetUint64(68015277240951437),
		new(big.Int).SetUint64(93667592535644987),
		new(big.Int).SetUint64(140726526226538479),
		new(big.Int).SetUint64(191079950785756457),
		new(big.Int).SetUint64(278064420037666463),
		new(big.Int).SetUint64(361197734649700343),
		new(big.Int).SetUint64(473672212426732757),
		new(big.Int).SetUint64(649424689916978839),
		new(big.Int).SetUint64(851648411420003101),
		new(big.Int).SetUint64(1093086073730188481),
		new(big.Int).SetUint64(1334574190510722559),
		new(big.Int).SetUint64(1676618685090439499),
		new(big.Int).SetUint64(2084313533279411653),
		new(big.Int).SetUint64(2735398959845680783),
		new(big.Int).SetUint64(3378760991971399829),
		new(big.Int).SetUint64(4247458888134038011),
		new(big.Int).SetUint64(4893372914349907373),
		new(big.Int).SetUint64(6183930444176970977),
		new(big.Int).SetUint64(8196642621256302527),
		new(big.Int).SetUint64(6404978019593941),
		new(big.Int).SetUint64(7153433571594019),
		new(big.Int).SetUint64(7884987314162401),
		new(big.Int).SetUint64(9067841309452963),
		new(big.Int).SetUint64(10040040806957459),
		new(big.Int).SetUint64(10945513774549181),
		new(big.Int).SetUint64(12234510269119603),
		new(big.Int).SetUint64(13922928045827959),
		new(big.Int).SetUint64(15629906736275353),
		new(big.Int).SetUint64(17458666901566859),
		new(big.Int).SetUint64(19476796052781127),
		new(big.Int).SetUint64(22488948577034287),
		new(big.Int).SetUint64(24152151295246309),
		new(big.Int).SetUint64(27151773765189701),
		new(big.Int).SetUint64(30878493949287209),
		new(big.Int).SetUint64(32920427094522853),
		new(big.Int).SetUint64(36253333051614221),
		new(big.Int).SetUint64(39667486059740711),
		new(big.Int).SetUint64(43246539683747509),
		new(big.Int).SetUint64(46515197072747041),
		new(big.Int).SetUint64(53458009874846321),
		new(big.Int).SetUint64(58149351831015121),
		new(big.Int).SetUint64(62453378275688251),
		new(big.Int).SetUint64(68166383366586233),
		new(big.Int).SetUint64(73296972548922643),
		new(big.Int).SetUint64(77816650636431929),
		new(big.Int).SetUint64(83994448620536617),
		new(big.Int).SetUint64(90930958821031211),
		new(big.Int).SetUint64(103118099799487681),
		new(big.Int).SetUint64(111104021081325227),
		new(big.Int).SetUint64(122179459219437197),
		new(big.Int).SetUint64(133017532553346253),
		new(big.Int).SetUint64(139753877375059309),
		new(big.Int).SetUint64(146109905295575281),
		new(big.Int).SetUint64(154602040846123523),
		new(big.Int).SetUint64(167296115097530977),
		new(big.Int).SetUint64(177884125374126797),
		new(big.Int).SetUint64(190740905520325019),
		new(big.Int).SetUint64(206026206127386401),
		new(big.Int).SetUint64(222571079133381019),
		new(big.Int).SetUint64(239037515441273111),
		new(big.Int).SetUint64(256992173027870521),
		new(big.Int).SetUint64(275282261541569851),
		new(big.Int).SetUint64(300291871149290521),
	}
)

type BiPrimeManage struct {
	pij        []int64
	qij        []int64
	Nj         []int64
	pi         *big.Int
	qi         *big.Int
	N          *big.Int
	modpi4     *big.Int
	modqi4     *big.Int
	epsilonP   *big.Int
	epsilonQ   *big.Int
	epsilonN   *big.Int
	isPartyOne bool
	ell        int64
}

func NewBFSampling(n int, numberOfPrime int, isOdd bool) (*BiPrimeManage, error) {
	pij := make([]int64, numberOfPrime)
	qij := make([]int64, numberOfPrime)
	for i := 1; i < len(pij); i++ {
		pij[i] = mathRandom.Int63n(primeList[i])
		qij[i] = mathRandom.Int63n(primeList[i])
	}
	if isOdd {
		pij[0] = (mathRandom.Int63n(2) * 2) + 1
		qij[0] = (mathRandom.Int63n(2) * 2) + 1
	} else {
		pij[0] = (mathRandom.Int63n(2) * 2)
		qij[0] = (mathRandom.Int63n(2) * 2)
	}
	Nj := make([]int64, len(primeList))

	return &BiPrimeManage{
		pij:        pij,
		qij:        qij,
		Nj:         Nj,
		modpi4:     big.NewInt(pij[0]),
		modqi4:     big.NewInt(qij[0]),
		isPartyOne: isOdd,
		ell:        int64(numberOfPrime),
	}, nil
}

func chineseRecover(numberOfPrime int) ([]*big.Int, *big.Int) {
	product := big.NewInt(4)
	for i := 1; i < numberOfPrime; i++ {
		product.Mul(product, big.NewInt(primeList[i]))
	}
	result := make([]*big.Int, numberOfPrime)

	for i := 0; i < numberOfPrime; i++ {
		mj := big.NewInt(primeList[i])
		xi := new(big.Int).Div(product, mj)
		bi := new(big.Int).ModInverse(xi, mj)
		result[i] = new(big.Int).Mul(bi, xi)
		result[i].Mod(result[i], product)
	}
	return result, product
}

func checkDivisible(x *big.Int, numberOfPrime int) bool {
	for i := 17; i < len(primes); i++ {
		residue := new(big.Int).Mod(x, primeProducts[i]).Uint64()
		for j := 0; j < len(primes[i]); j++ {
			if residue%primes[i][j] == 0 {
				return true
			}
		}
	}
	return false
}

// (a+b\sqrt{D})^2 ---> (u,v) where u+v\sqrt{D}
func specialSquare(a, b, D, N *big.Int) (*big.Int, *big.Int) {
	u := new(big.Int).Exp(b, big2, N)
	u.Mul(u, D)
	u.Mod(u, N)
	u.Add(u, new(big.Int).Exp(a, big2, N))

	v := new(big.Int).Mul(a, b)
	v.Lsh(v, 1)
	v.Mod(v, N)
	return u, v
}

func specialMul(a1, b1, a2, b2, D, N *big.Int) (*big.Int, *big.Int) {
	u := new(big.Int).Mul(a1, a2)
	u.Mod(u, N)
	temp := new(big.Int).Mul(b1, b2)
	temp.Mod(temp, N)
	temp.Mul(temp, D)
	temp.Mod(temp, N)
	u.Add(u, temp)
	u.Mod(u, N)

	v := new(big.Int).Mul(a1, b2)
	v.Mod(v, N)
	temp = new(big.Int).Mul(a2, b1)
	temp.Mod(temp, N)
	v.Add(v, temp)
	v.Mod(v, N)
	return u, v
}

func shuffleElement(u, v, D, N *big.Int, n int) ([]*big.Int, []*big.Int) {
	uList := make([]*big.Int, n)
	vList := make([]*big.Int, n)
	totalU, totalV := big.NewInt(1), big.NewInt(0)
	upperBound := n - 1
	for i := 0; i < upperBound; i++ {
		tempU, _ := utils.RandomCoprimeInt(N)
		tempV, _ := utils.RandomCoprimeInt(N)
		uList[i] = tempU
		vList[i] = tempV
		totalU, totalV = specialMul(totalU, totalV, tempU, tempV, D, N)
	}
	totalU, totalV = specialInverse(totalU, totalV, D, N)
	totalU, totalV = specialMul(totalU, totalV, u, v, D, N)
	return uList, vList
}

func specialInverse(a, b, D, N *big.Int) (*big.Int, *big.Int) {
	aSquare := new(big.Int).Exp(a, big2, N)
	bDSquare := new(big.Int).Exp(b, big2, N)
	bDSquare.Mul(bDSquare, D)
	bDSquare.Mod(bDSquare, N)

	lowerPart := new(big.Int).Sub(aSquare, bDSquare)
	lowerPart.ModInverse(lowerPart, N)

	resultU := new(big.Int).Mul(a, lowerPart)
	resultU.Mod(resultU, N)

	resultV := new(big.Int).Neg(b)
	resultV.Mul(resultV, lowerPart)
	resultV.Mod(resultV, N)
	return resultU, resultV
}

func specialExp(a, b, D, N, exp *big.Int) (*big.Int, *big.Int) {
	// PSquare := new(big.Int).Exp(P, big2, N)
	// PSquare2AddD := new(big.Int).Add(PSquare, D)
	// PSquare2AddD.Mod(PSquare2AddD, N)

	// PSquare2SubD := new(big.Int).Sub(PSquare, D)
	// PSquare2SubD.ModInverse(PSquare2SubD, N)

	// u := new(big.Int).Mul(PSquare2AddD, PSquare2SubD)
	// u.Mod(u, N)

	// v := new(big.Int).Mul(P, PSquare2SubD)
	// v.Lsh(v, 1)
	// v.Mod(v, N)

	u, v := new(big.Int).Set(a), new(big.Int).Set(b)
	DmodN := new(big.Int).Mod(D, N)

	resultalphaU, resultalphaV := big.NewInt(1), big.NewInt(0)
	absM := new(big.Int).Abs(exp)
	for i := 0; i < absM.BitLen(); i++ {
		if absM.Bit(i) == 1 {
			resultalphaU, resultalphaV = specialMul(resultalphaU, resultalphaV, u, v, DmodN, N)
		}
		u, v = specialSquare(u, v, D, N)
	}

	if exp.Sign() < 0 {
		return specialInverse(resultalphaU, resultalphaV, DmodN, N)
	}
	return resultalphaU, resultalphaV
}

func randomPolynomial(constantTerm int64, degree int, prime int64) []int64 {
	result := make([]int64, degree+1)
	for i := 1; i < len(result); i++ {
		result[i] = mathRandom.Int63n(prime)
	}
	result[0] = constantTerm
	return result
}

func polynomialEvaluate(poly []int64, x int64, prime int64) int64 {
	if x == 0 {
		return poly[0]
	}
	// Compute the polynomial value using Horner's method.
	result := poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		result = result * x
		result = result + poly[i]
		result = result % prime
	}
	return result
}

// lowBitLength -> 2N, upBitLength -> 4N
func generateRamdonDandP(bitLength int, epsilonP int, sSquareP, N *big.Int) (*big.Int, *big.Int, int, error) {
	inverse4 := new(big.Int).ModInverse(big4, N)
	count := 0
	for i := 0; i < maxRetry; i++ {
		// for k := 0; k < len(primes[i]); k++ {
		// 	D = new(big.Int).SetUint64(primes[i][k])
		// 	negD := new(big.Int).Neg(D)
		// 	if big.Jacobi(negD, N) == -1 {

		// 		continue
		// 	}
		// 	count++
		// 	if big.Jacobi(negD, sSquareP) == -1 {
		// 		P, err := utils.RandomInt(N)
		// 		if err != nil {
		// 			return nil, nil, 0, err
		// 		}
		// 		Q := new(big.Int).Exp(P, big2, N)
		// 		Q = Q.Sub(Q, D)
		// 		if utils.Gcd(Q, N).Cmp(big1) == 0 {
		// 			Q.Mul(Q, inverse4)
		// 			Q.Mod(Q, N)
		// 			return P, D, count, nil
		// 		}
		// 	}
		// }

		D, err := rand.Prime(rand.Reader, bitLength)
		if err != nil {
			return nil, nil, 0, err
		}
		
		// D, err := utils.RandomCoprimeInt(N)
		// if err != nil {
		// 	return nil, nil, 0, err
		// }
		negD := new(big.Int).Neg(D)
		if big.Jacobi(negD, N) == -1 {

			continue
		}
		fmt.Println("D:", D)
		count++
		if big.Jacobi(negD, sSquareP) == -1 {
			P, err := utils.RandomInt(N)
			if err != nil {
				return nil, nil, 0, err
			}
			Q := new(big.Int).Exp(P, big2, N)
			Q = Q.Sub(Q, D)
			if utils.Gcd(Q, N).Cmp(big1) == 0 {
				Q.Mul(Q, inverse4)
				Q.Mod(Q, N)
				return P, D, count, nil
			}
		}
	}
	return nil, nil, 0, ErrExceedMaxRetry
}

func (m *BiPrimeManage) computeLucasMatrice(D, P *big.Int) (*big.Int, *big.Int) {
	exp := new(big.Int).Mul(m.pi, m.epsilonQ)
	exp.Add(exp, new(big.Int).Mul(m.qi, m.epsilonP))

	exp.Neg(exp)
	if m.isPartyOne {
		exp.Add(exp, m.N)
		exp.Add(exp, m.epsilonN)
	}
	exp.Rsh(exp, 1)

	// alpha*beta^(-1)
	u, v := specialInverse(P, big.NewInt(-1), D, m.N)
	u, v = specialMul(P, big.NewInt(1), u, v, D, m.N)

	u, v = specialExp(u, v, D, m.N, exp)

	return u, v
}

func (m *BiPrimeManage) CheckLucasCongruence(uList []*big.Int, vList []*big.Int, D *big.Int) error {
	u, v := new(big.Int).Set(uList[0]), new(big.Int).Set(vList[0])
	for i := 1; i < len(uList); i++ {
		u, v = specialMul(u, v, uList[i], vList[i], D, m.N)
	}

	if u.Cmp(big1) == 0 && v.Cmp(big0) == 0 {
		return nil
	}
	return ErrNonPrime
}

// MPC Mul
// func (m *BiPrimeManage) computeLucasMatrice(D, P *big.Int) (*matrix.Matrix, error) {
// 	inverse2 := new(big.Int).ModInverse(big2, m.N)
// 	inverse2.Mod(inverse2, m.N)
// 	exp := new(big.Int).Mul(m.pi, m.epsilonQ)
// 	exp.Add(exp, new(big.Int).Mul(m.qi, m.epsilonP))
// 	exp.Neg(exp)
// 	if m.isPartyOne {
// 		exp.Add(exp, m.N)
// 		exp.Add(exp, m.epsilonN)
// 	}
// 	exp.Div(exp, big2)

// 	Pover2 := new(big.Int).Mul(P, inverse2)
// 	Pover2.Mod(Pover2, m.N)
// 	Dover2 := new(big.Int).Mul(D, inverse2)
// 	Dover2.Mod(Dover2, m.N)

// 	lucasMatrix, err := matrix.NewMatrix(m.N, [][]*big.Int{
// 		{new(big.Int).Set(Pover2), new(big.Int).Set(inverse2)},
// 		{new(big.Int).Set(Dover2), new(big.Int).Set(Pover2)},
// 	})

// 	if err != nil {
// 		return nil, err
// 	}
// 	result, err := lucasMatrix.Exp(exp)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return result, nil
// }

// func (m *BiPrimeManage) CheckLucasCongruence(allLucasMatrix []*matrix.Matrix) error {
// 	LucasMatrix := allLucasMatrix[0].Copy()
// 	var err error
// 	for i := 1; i < len(allLucasMatrix); i++ {
// 		temp := allLucasMatrix[i].Copy()
// 		LucasMatrix, err = LucasMatrix.Multiply(temp)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	//fmt.Println(LucasMatrix.GetMatrix())
// 	multiplyMatrix, err := matrix.NewMatrix(m.N, [][]*big.Int{
// 		{big.NewInt(0)},
// 		{big.NewInt(2)},
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	result, err := LucasMatrix.Multiply(multiplyMatrix)
// 	if err != nil {
// 		return err
// 	}
// 	temp := result.GetMatrix()[0][0]
// 	if temp.Mod(temp, m.N).Cmp(big0) == 0 {
// 		return nil
// 	}
// 	return ErrNonPrime
// }
