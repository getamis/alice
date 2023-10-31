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
	"math/big"
	mathRandom "math/rand"

	dbns "github.com/getamis/alice/crypto/dbnssystem"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/utils"
)

const (
	maxRetry = 500
	deepTree = 1
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
		4, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
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
		757,
		761,
		769,
		773,
		787,
		797,
		809,
		811,
		821,
		823,
		827,
		829,
		839,
		853,
		857,
		859,
		863,
		877,
		881,
		883,
		887,
		907,
		911,
		919,
		929,
		937,
		941,
		947,
		953,
		967,
		971,
		977,
		983,
		991,
		997,
		1009,
		1013,
		1019,
		1021,
		1031,
		1033,
		1039,
		1049,
		1051,
		1061,
		1063,
		1069,
		1087,
		1091,
		1093,
		1097,
		1103,
		1109,
		1117,
		1123,
		1129,
		1151,
		1153,
		1163,
		1171,
		1181,
		1187,
		1193,
		1201,
		1213,
		1217,
		1223,
		1229,
		1231,
		1237,
		1249,
		1259,
		1277,
		1279,
		1283,
		1289,
		1291,
		1297,
		1301,
		1303,
		1307,
		1319,
		1321,
		1327,
		1361,
		1367,
		1373,
		1381,
		1399,
		1409,
		1423,
		1427,
		1429,
		1433,
		1439,
		1447,
		1451,
		1453,
		1459,
		1471,
		1481,
		1483,
		1487,
		1489,
		1493,
		1499,
		1511,
		1523,
		1531,
		1543,
		1549,
		1553,
		1559,
		1567,
		1571,
		1579,
		1583,
		1597,
		1601,
		1607,
		1609,
		1613,
		1619,
		1621,
		1627,
		1637,
		1657,
		1663,
		1667,
		1669,
		1693,
		1697,
		1699,
		1709,
		1721,
		1723,
		1733,
		1741,
		1747,
		1753,
		1759,
		1777,
		1783,
		1787,
		1789,
		1801,
		1811,
		1823,
		1831,
		1847,
		1861,
		1867,
		1871,
		1873,
		1877,
		1879,
		1889,
		1901,
		1907,
		1913,
		1931,
		1933,
		1949,
		1951,
		1973,
		1979,
		1987,
		1993,
		1997,
		1999,
		2003,
		2011,
		2017,
		2027,
		2029,
		2039,
		2053,
		2063,
		2069,
		2081,
		2083,
		2087,
		2089,
		2099,
		2111,
		2113,
		2129,
		2131,
		2137,
		2141,
		2143,
		2153,
		2161,
		2179,
		2203,
		2207,
		2213,
		2221,
		2237,
		2239,
		2243,
		2251,
		2267,
		2269,
		2273,
		2281,
		2287,
		2293,
		2297,
		2309,
		2311,
		2333,
		2339,
		2341,
		2347,
		2351,
		2357,
		2371,
		2377,
		2381,
		2383,
		2389,
		2393,
		2399,
		2411,
		2417,
		2423,
		2437,
		2441,
		2447,
		2459,
		2467,
		2473,
		2477,
		2503,
		2521,
		2531,
		2539,
		2543,
		2549,
		2551,
		2557,
		2579,
		2591,
		2593,
		2609,
		2617,
		2621,
		2633,
		2647,
		2657,
		2659,
		2663,
		2671,
		2677,
		2683,
		2687,
		2689,
		2693,
		2699,
		2707,
		2711,
		2713,
		2719,
		2729,
		2731,
		2741,
	}
	// without prime 3
	primes = [][]uint64{
		{
			5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, // 0
		},
		{
			59, 61, 67, 71, 73, 79, 83, 89, 97, // 1
		},
		{
			101, 103, 107, 109, 113, 127, 131, 137, 139, // 2
		},
		{
			149, 151, 157, 163, 167, 173, 179, 181, // 3
		},
		{
			191, 193, 197, 199, 211, 223, 227, 229, // 4
		},
		{
			233, 239, 241, 251, 257, 263, 269, // 5
		},
		{
			271, 277, 281, 283, 293, 307, 311, // 6
		},
		{
			317, 331, 337, 347, 349, 353, 359, // 7
		},
		{
			367, 373, 379, 383, 389, 397, 401, // 8
		},
		{
			409, 419, 421, 431, 433, 439, 443, // 9
		},
		{
			449, 457, 461, 463, 467, 479, 487, // 10
		},
		{
			491, 499, 503, 509, 521, 523, 541, // 11
		},
		{
			557, 563, 569, 571, 577, 587, // 12
		},
		{
			593, 599, 601, 607, 613, 617, // 13
		},
		{
			619, 631, 641, 643, 647, 653, // 14
		},
		{
			659, 661, 673, 677, 683, 691, // 15
		},
		{
			701, 709, 719, 727, 733, 739, // 16
		},
		{
			743, 751, 757, 761, 769, 773, // 17
		},
		{
			787, 797, 809, 811, 821, 823, // 18
		},
		{
			827, 829, 839, 853, 857, 859, // 19
		},
		{
			863, 877, 881, 883, 887, 907, // 20
		},
		{
			911, 919, 929, 937, 941, 947, // 21
		},
		{
			953, 967, 971, 977, 983, 991, // 22
		},
		{
			997, 1009, 1013, 1019, 1021, 1031, // 23
		},
		{
			1033, 1039, 1049, 1051, 1061, 1063, // 24
		},
		{
			1069, 1087, 1091, 1093, 1097, 1103, // 25
		},
		{
			1109, 1117, 1123, 1129, 1151, 1153, // 26
		},
		{
			1163, 1171, 1181, 1187, 1193, 1201, // 27
		},
		{
			1213, 1217, 1223, 1229, 1231, 1237, // 28
		},
		{
			1249, 1259, 1277, 1279, 1283, 1289, // 29
		},
		{
			1291, 1297, 1301, 1303, 1307, 1319, // 30
		},
		{
			1321, 1327, 1361, 1367, 1373, 1381, // 31
		},
		{
			1399, 1409, 1423, 1427, 1429, 1433, // 32
		},
		{
			1439, 1447, 1451, 1453, 1459, // 33
		},
		{
			1471, 1481, 1483, 1487, 1489, // 34
		},
		{
			1493, 1499, 1511, 1523, 1531, // 35
		},
		{
			1543, 1549, 1553, 1559, 1567, // 36
		},
		{
			1571, 1579, 1583, 1597, 1601, // 37
		},
		{
			1607, 1609, 1613, 1619, 1621, // 38
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
		{
			3167, 3169, 3181, 3187, 3191,
		},
		{
			3203, 3209, 3217, 3221, 3229,
		},
		{
			3251, 3253, 3257, 3259, 3271,
		},
		{
			3299, 3301, 3307, 3313, 3319,
		},
		{
			3323, 3329, 3331, 3343, 3347,
		},
		{
			3359, 3361, 3371, 3373, 3389,
		},
		{
			3391, 3407, 3413, 3433, 3449,
		},
		{
			3457, 3461, 3463, 3467, 3469,
		},
		{
			3491, 3499, 3511, 3517, 3527,
		},
		{
			3529, 3533, 3539, 3541, 3547,
		},
		{
			3557, 3559, 3571, 3581, 3583,
		},
		{
			3593, 3607, 3613, 3617, 3623,
		},
		{
			3631, 3637, 3643, 3659, 3671,
		},
		{
			3673, 3677, 3691, 3697, 3701,
		},
		{
			3709, 3719, 3727, 3733, 3739,
		},
		{
			3761, 3767, 3769, 3779, 3793,
		},
		{
			3797, 3803, 3821, 3823, 3833,
		},
		{
			3847, 3851, 3853, 3863, 3877,
		},
		{
			3881, 3889, 3907, 3911, 3917,
		},
		{
			3919, 3923, 3929, 3931, 3943,
		},
		{
			3947, 3967, 3989, 4001, 4003,
		},
		{
			4007, 4013, 4019, 4021, 4027,
		},
		{
			4049, 4051, 4057, 4073, 4079,
		},
		{
			4091, 4093, 4099, 4111, 4127,
		},
		{
			4129, 4133, 4139, 4153, 4157,
		},
		{
			4159, 4177, 4201, 4211, 4217,
		},
		{
			4219, 4229, 4231, 4241, 4243,
		},
		{
			4253, 4259, 4261, 4271, 4273,
		},
		{
			4283, 4289, 4297, 4327, 4337,
		},
		{
			4339, 4349, 4357, 4363, 4373,
		},
		{
			4391, 4397, 4409, 4421, 4423,
		},
		{
			4441, 4447, 4451, 4457, 4463,
		},
		{
			4481, 4483, 4493, 4507, 4513,
		},
		{
			4517, 4519, 4523, 4547, 4549,
		},
		{
			4561, 4567, 4583, 4591, 4597,
		},
		{
			4603, 4621, 4637, 4639, 4643,
		},
		{
			4649, 4651, 4657, 4663, 4673,
		},
		{
			4679, 4691, 4703, 4721, 4723,
		},
		{
			4729, 4733, 4751, 4759, 4783,
		},
		{
			4787, 4789, 4793, 4799, 4801,
		},
		{
			4813, 4817, 4831, 4861, 4871,
		},
		{
			4877, 4889, 4903, 4909, 4919,
		},
		{
			4931, 4933, 4937, 4943, 4951,
		},
		{
			4957, 4967, 4969, 4973, 4987,
		},
		{
			4993, 4999, 5003, 5009, 5011,
		},
		{
			5021, 5023, 5039, 5051, 5059,
		},
		{
			5077, 5081, 5087, 5099, 5101,
		},
		{
			5107, 5113, 5119, 5147, 5153,
		},
		{
			5167, 5171, 5179, 5189, 5197,
		},
		{
			5209, 5227, 5231, 5233, 5237,
		},
		{
			5261, 5273, 5279, 5281, 5297,
		},
		{
			5303, 5309, 5323, 5333, 5347,
		},
		{
			5351, 5381, 5387, 5393, 5399,
		},
		{
			5407, 5413, 5417, 5419, 5431,
		},
		{
			5437, 5441, 5443, 5449, 5471,
		},
		{
			5477, 5479, 5483, 5501, 5503,
		},
		{
			5507, 5519, 5521, 5527, 5531,
		},
		{
			5557, 5563, 5569, 5573, 5581,
		},
		{
			5591, 5623, 5639, 5641, 5647,
		},
		{
			5651, 5653, 5657, 5659, 5669,
		},
		{
			5683, 5689, 5693, 5701, 5711,
		},
		{
			5717, 5737, 5741, 5743, 5749,
		},
		{
			5779, 5783, 5791, 5801, 5807,
		},
		{
			5813, 5821, 5827, 5839, 5843,
		},
		{
			5849, 5851, 5857, 5861, 5867,
		},
		{
			5869, 5879, 5881, 5897, 5903,
		},
		{
			5923, 5927, 5939, 5953, 5981,
		},
		{
			5987, 6007, 6011, 6029, 6037,
		},
		{
			6043, 6047, 6053, 6067, 6073,
		},
		{
			6079, 6089, 6091, 6101, 6113,
		},
		{
			6121, 6131, 6133, 6143, 6151,
		},
		{
			6163, 6173, 6197, 6199, 6203,
		},
		{
			6211, 6217, 6221, 6229, 6247,
		},
		{
			6257, 6263, 6269, 6271, 6277,
		},
		{
			6287, 6299, 6301, 6311, 6317,
		},
		{
			6323, 6329, 6337, 6343, 6353,
		},
		{
			6389, 6397, 6421, 6427, 6449,
		},
		{
			6451, 6469, 6473, 6481, 6491,
		},
		{
			6521, 6529, 6547, 6551, 6553,
		},
		{
			6563, 6569, 6571, 6577, 6581,
		},
		{
			6599, 6607, 6619, 6637, 6653,
		},
		{
			6659, 6661, 6673, 6679, 6689,
		},
		{
			6691, 6701, 6703, 6709, 6719,
		},
		{
			6733, 6737, 6761, 6763, 6779,
		},
		{
			6781, 6791, 6793, 6803, 6823,
		},
		{
			6827, 6829, 6833, 6841, 6857,
		},
		{
			6863, 6869, 6871, 6883, 6899,
		},
		{
			6907, 6911, 6917, 6947, 6949,
		},
		{
			6959, 6961, 6967, 6971, 6977,
		},
		{
			6983, 6991, 6997, 7001, 7013,
		},
		{
			7019, 7027, 7039, 7043, 7057,
		},
		{
			7069, 7079, 7103, 7109, 7121,
		},
		{
			7127, 7129, 7151, 7159,
		},
		{
			7177, 7187, 7193, 7207,
		},
		{
			7211, 7213, 7219, 7229,
		},
		{
			7237, 7243, 7247, 7253,
		},
		{
			7283, 7297, 7307, 7309,
		},
		{
			7321, 7331, 7333, 7349,
		},
		{
			7351, 7369, 7393, 7411,
		},
		{
			7417, 7433, 7451, 7457,
		},
		{
			7459, 7477, 7481, 7487,
		},
		{
			7489, 7499, 7507, 7517,
		},
		{
			7523, 7529, 7537, 7541,
		},
		{
			7547, 7549, 7559, 7561,
		},
		{
			7573, 7577, 7583, 7589,
		},
		{
			7591, 7603, 7607, 7621,
		},
		{
			7639, 7643, 7649, 7669,
		},
		{
			7673, 7681, 7687, 7691,
		},
		{
			7699, 7703, 7717, 7723,
		},
		{
			7727, 7741, 7753, 7757,
		},
		{
			7759, 7789, 7793, 7817,
		},
		{
			7823, 7829, 7841, 7853,
		},
		{
			7867, 7873, 7877, 7879,
		},
		{
			7883, 7901, 7907, 7919,
		},
		{
			7927, 7933, 7937, 7949,
		},
		{
			7951, 7963, 7993, 8009,
		},
		{
			8011, 8017, 8039, 8053,
		},
		{
			8059, 8069, 8081, 8087,
		},
		{
			8089, 8093, 8101, 8111,
		},
		{
			8117, 8123, 8147, 8161,
		},
		{
			8167, 8171, 8179, 8191,
		},
		{
			8209, 8219, 8221, 8231,
		},
		{
			8233, 8237, 8243, 8263,
		},
		{
			8269, 8273, 8287, 8291,
		},
		{
			8293, 8297, 8311, 8317,
		},
		{
			8329, 8353, 8363, 8369,
		},
		{
			8377, 8387, 8389, 8419,
		},
		{
			8423, 8429, 8431, 8443,
		},
		{
			8447, 8461, 8467, 8501,
		},
		{
			8513, 8521, 8527, 8537,
		},
		{
			8539, 8543, 8563, 8573,
		},
		{
			8581, 8597, 8599, 8609,
		},
		{
			8623, 8627, 8629, 8641,
		},
		{
			8647, 8663, 8669, 8677,
		},
		{
			8681, 8689, 8693, 8699,
		},
		{
			8707, 8713, 8719, 8731,
		},
		{
			8737, 8741, 8747, 8753,
		},
		{
			8761, 8779, 8783, 8803,
		},
		{
			8807, 8819, 8821, 8831,
		},
		{
			8837, 8839, 8849, 8861,
		},
		{
			8863, 8867, 8887, 8893,
		},
		{
			8923, 8929, 8933, 8941,
		},
		{
			8951, 8963, 8969, 8971,
		},
		{
			8999, 9001, 9007, 9011,
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
		new(big.Int).SetUint64(324670507102932271),
		new(big.Int).SetUint64(343903413464692331),
		new(big.Int).SetUint64(367183955462968219),
		new(big.Int).SetUint64(395995930692543971),
		new(big.Int).SetUint64(412297648713891917),
		new(big.Int).SetUint64(435035981747807213),
		new(big.Int).SetUint64(466877784586234277),
		new(big.Int).SetUint64(498323779650735373),
		new(big.Int).SetUint64(531988750499534941),
		new(big.Int).SetUint64(554195472717592921),
		new(big.Int).SetUint64(580033173413742379),
		new(big.Int).SetUint64(613603974329610533),
		new(big.Int).SetUint64(646212739069942069),
		new(big.Int).SetUint64(682067158973227267),
		new(big.Int).SetUint64(717556097950932179),
		new(big.Int).SetUint64(765393598654089341),
		new(big.Int).SetUint64(808513130757919549),
		new(big.Int).SetUint64(854899814989143691),
		new(big.Int).SetUint64(903371498965443881),
		new(big.Int).SetUint64(936279299021229409),
		new(big.Int).SetUint64(1000339699724458283),
		new(big.Int).SetUint64(1046458984601176343),
		new(big.Int).SetUint64(1105562102321344781),
		new(big.Int).SetUint64(1164477464047264189),
		new(big.Int).SetUint64(1219404154070653283),
		new(big.Int).SetUint64(1295969914350799741),
		new(big.Int).SetUint64(1358412095962030003),
		new(big.Int).SetUint64(1408565416393194701),
		new(big.Int).SetUint64(1481309444012047061),
		new(big.Int).SetUint64(1568668978130198773),
		new(big.Int).SetUint64(1664552340807820969),
		new(big.Int).SetUint64(1748537769722094707),
		new(big.Int).SetUint64(1835832242133266749),
		new(big.Int).SetUint64(1909676969895325487),
		new(big.Int).SetUint64(2014757298134756267),
		new(big.Int).SetUint64(2124403926726966487),
		new(big.Int).SetUint64(2194185395698560757),
		new(big.Int).SetUint64(2301682431977649361),
		new(big.Int).SetUint64(2420510297429231779),
		new(big.Int).SetUint64(2531617851569708201),
		new(big.Int).SetUint64(2651998634547334081),
		new(big.Int).SetUint64(2822958806037647489),
		new(big.Int).SetUint64(2938953955210826543),
		new(big.Int).SetUint64(3034169951757484861),
		new(big.Int).SetUint64(3134372729643687079),
		new(big.Int).SetUint64(3247430055350985533),
		new(big.Int).SetUint64(3413174021444732381),
		new(big.Int).SetUint64(3545202858819508039),
		new(big.Int).SetUint64(3731601834029562799),
		new(big.Int).SetUint64(3903236678808572593),
		new(big.Int).SetUint64(4096602970278237259),
		new(big.Int).SetUint64(4273390561024158071),
		new(big.Int).SetUint64(4516361185410971879),
		new(big.Int).SetUint64(4666080059661839783),
		new(big.Int).SetUint64(4800206447189755249),
		new(big.Int).SetUint64(4980849793622144867),
		new(big.Int).SetUint64(5129633545067581241),
		new(big.Int).SetUint64(5354608711114156727),
		new(big.Int).SetUint64(5647205057334685729),
		new(big.Int).SetUint64(5797444802698601441),
		new(big.Int).SetUint64(5992637046902444101),
		new(big.Int).SetUint64(6216868967792134723),
		new(big.Int).SetUint64(6519497801401273709),
		new(big.Int).SetUint64(6726936093923589367),
		new(big.Int).SetUint64(6892467914899223141),
		new(big.Int).SetUint64(7063544086261780421),
		new(big.Int).SetUint64(7423345431777701267),
		new(big.Int).SetUint64(7868284918663763927),
		new(big.Int).SetUint64(8149679183363495683),
		new(big.Int).SetUint64(8408569879136923073),
		new(big.Int).SetUint64(8696668234142593519),
		new(big.Int).SetUint64(9065533317738533591),
		new(big.Int).SetUint64(9347434589503129901),
		new(big.Int).SetUint64(9670206894766911593),
		new(big.Int).SetUint64(9947950266053377531),
		new(big.Int).SetUint64(10219168293344643341),
		new(big.Int).SetUint64(10469973707184986711),
		new(big.Int).SetUint64(10877086583697332839),
		new(big.Int).SetUint64(11363796048692061277),
		new(big.Int).SetUint64(11966054516402166469),
		new(big.Int).SetUint64(12261761540607787469),
		new(big.Int).SetUint64(12742779182251915387),
		new(big.Int).SetUint64(13223371912735702537),
		new(big.Int).SetUint64(13547597965659782083),
		new(big.Int).SetUint64(14060187720913352237),
		new(big.Int).SetUint64(14519943674995684207),
		new(big.Int).SetUint64(14943494779191094943),
		new(big.Int).SetUint64(15381241048853617829),
		new(big.Int).SetUint64(15939244597920254327),
		new(big.Int).SetUint64(16414516185229883411),
		new(big.Int).SetUint64(16770929551478033033),
		new(big.Int).SetUint64(17255755040693136157),
		new(big.Int).SetUint64(17993730379326818617),
		new(big.Int).SetUint64(2601084816577447),
		new(big.Int).SetUint64(2673961644686149),
		new(big.Int).SetUint64(2714355297352393),
		new(big.Int).SetUint64(2755199155179181),
		new(big.Int).SetUint64(2838257051022013),
		new(big.Int).SetUint64(2892301472834467),
		new(big.Int).SetUint64(2967922107149437),
		new(big.Int).SetUint64(3063170129252027),
		new(big.Int).SetUint64(3123744292852921),
		new(big.Int).SetUint64(3169116103771309),
		new(big.Int).SetUint64(3219258232836839),
		new(big.Int).SetUint64(3256172159768497),
		new(big.Int).SetUint64(3302104802987327),
		new(big.Int).SetUint64(3345872287067231),
		new(big.Int).SetUint64(3424867452482737),
		new(big.Int).SetUint64(3484357081896421),
		new(big.Int).SetUint64(3534506238816227),
		new(big.Int).SetUint64(3597257735088847),
		new(big.Int).SetUint64(3681563061470731),
		new(big.Int).SetUint64(3771261735382591),
		new(big.Int).SetUint64(3843982019516753),
		new(big.Int).SetUint64(3899919746694739),
		new(big.Int).SetUint64(3967484052562783),
		new(big.Int).SetUint64(4053093064237781),
		new(big.Int).SetUint64(4157749721026529),
		new(big.Int).SetUint64(4249652524240337),
		new(big.Int).SetUint64(4301475061801447),
		new(big.Int).SetUint64(4383823832655797),
		new(big.Int).SetUint64(4470693536111273),
		new(big.Int).SetUint64(4565480435215321),
		new(big.Int).SetUint64(4619024161566889),
		new(big.Int).SetUint64(4700242555637929),
		new(big.Int).SetUint64(4756119295283327),
		new(big.Int).SetUint64(4869350181306739),
		new(big.Int).SetUint64(4962104000351909),
		new(big.Int).SetUint64(5053807936630711),
		new(big.Int).SetUint64(5144270124013789),
		new(big.Int).SetUint64(5280496305495727),
		new(big.Int).SetUint64(5355206074827523),
		new(big.Int).SetUint64(5461167354743887),
		new(big.Int).SetUint64(5546801933450369),
		new(big.Int).SetUint64(5634720438301393),
		new(big.Int).SetUint64(5703987484268063),
		new(big.Int).SetUint64(5775198611324599),
		new(big.Int).SetUint64(5847086395481447),
		new(big.Int).SetUint64(5946649121505431),
		new(big.Int).SetUint64(6050274037736183),
		new(big.Int).SetUint64(6124701404660327),
		new(big.Int).SetUint64(6210991433600111),
		new(big.Int).SetUint64(6363516064637051),
		new(big.Int).SetUint64(6455201958783887),
		new(big.Int).SetUint64(6574128155837923),
	}
)

type BiPrimeManage struct {
	n          int
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
	pMod4      int64
	qMod4      int64
	isPartyOne bool
	ell        int64

	UsendShuffle []*big.Int
	VsendShuffle []*big.Int
	allSShares   []*big.Int

	u *big.Int
	v *big.Int
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
		n:          n,
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

func checkDivisible(x *big.Int, startIndex int) bool {
	for i := startIndex; i < len(primes); i++ {
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

func (m *BiPrimeManage) shuffleElement(u, v, D, N *big.Int) {
	uList := make([]*big.Int, m.n)
	vList := make([]*big.Int, m.n)
	totalU, totalV := big.NewInt(1), big.NewInt(0)
	upperBound := m.n - 1
	for i := 0; i < upperBound; i++ {
		tempU, _ := utils.RandomCoprimeInt(N)
		tempV, _ := utils.RandomCoprimeInt(N)
		uList[i] = tempU
		vList[i] = tempV
		totalU, totalV = specialMul(totalU, totalV, tempU, tempV, D, N)
	}
	totalU, totalV = specialInverse(totalU, totalV, D, N)
	uList[upperBound], vList[upperBound] = specialMul(totalU, totalV, u, v, D, N)
	m.UsendShuffle = uList
	m.VsendShuffle = vList
	return
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

func cubic(a, b, D, N *big.Int) (*big.Int, *big.Int) {
	aSquare := new(big.Int).Exp(a, big2, N)
	bSquareD := new(big.Int).Exp(b, big2, N)
	bSquareD.Mul(bSquareD, D)
	bSquareD.Mod(bSquareD, N)

	temp := new(big.Int).Add(aSquare, bSquareD)
	u := new(big.Int).Add(temp, new(big.Int).Lsh(bSquareD, 1))
	u.Mul(u, a)
	u.Mod(u, N)

	v := new(big.Int).Add(temp, new(big.Int).Lsh(aSquare, 1))
	v.Mul(v, b)
	v.Mod(v, N)
	return u, v
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func Exp(u, v, D, N, exp *big.Int) (*big.Int, *big.Int) {
	resultU, resultV := big.NewInt(1), big.NewInt(0)
	uCopy, vCopy := new(big.Int).Set(u), new(big.Int).Set(v)

	if exp.Sign() == 0 {
		return resultU, resultV
	}
	k := 8
	windowsize := 1 << k
	windowsLength := (windowsize >> 1) + 1
	winU := make([]*big.Int, windowsLength)
	winV := make([]*big.Int, windowsLength)
	winU[0] = big.NewInt(1)
	winU[1] = uCopy
	winV[0] = big.NewInt(0)
	winV[1] = vCopy
	squareU, squareV := specialSquare(uCopy, vCopy, D, N)

	for i := 2; i < len(winU); i++ {
		winU[i], winV[i] = specialMul(squareU, squareV, winU[i-1], winV[i-1], D, N)
	}
	bitString := Reverse(exp.Text(2))
	upBd := 0
	for i := len(bitString) - 1; i >= 0; i-- {
		if bitString[i] == 48 {
			resultU, resultV = specialSquare(resultU, resultV, D, N)
			continue
		}
		s := 0
		upBd = i - k + 1
		if upBd > 0 {
			s = upBd
		}
		for bitString[s] == 48 {
			s += 1
		}
		for j := 1; j <= i-s+1; j++ {
			resultU, resultV = specialSquare(resultU, resultV, D, N)
		}
		u := bitArrayToInt(bitString, s, i+1)

		resultU, resultV = specialMul(resultU, resultV, winU[(u>>1)+1], winV[(u>>1)+1], D, N)
		i = s
	}
	if exp.Sign() < 0 {
		resultU, resultV = specialInverse(resultU, resultV, D, N)
	}
	return resultU, resultV

}

func bitArrayToInt(exp string, startIndex int, endIndex int) int {
	result := 0
	sqr := 1
	for i := 0; i < endIndex-startIndex; i++ {
		if exp[i+startIndex] == 49 {
			result += sqr
		}
		sqr <<= 1
	}
	return result
}

func ExpSquareCubic(u, v, D, N, exp *big.Int) (*big.Int, *big.Int) {
	resultU, resultV := big.NewInt(1), big.NewInt(0)
	uCopy, vCopy := new(big.Int).Set(u), new(big.Int).Set(v)

	if exp.Sign() == 0 {
		return resultU, resultV
	}

	dbnsMentor := dbns.NewDBNS(deepTree)
	expansion, _ := dbnsMentor.ExpansionBase2And3(exp)

	a, b, index := 0, 0, 0
	for index < len(expansion) {
		exp2 := expansion[index].GetExp2()
		for a < exp2 {
			uCopy, vCopy = specialSquare(uCopy, vCopy, D, N)
			a++
		}
		exp3 := expansion[index].GetExp3()
		for b < exp3 {
			uCopy, vCopy = cubic(uCopy, vCopy, D, N)
			b++
		}
		sign := expansion[index].GetSign()
		if sign == 1 {
			resultU, resultV = specialMul(resultU, resultV, uCopy, vCopy, D, N)
		} else {
			inverU, inverV := specialInverse(uCopy, vCopy, D, N)
			resultU, resultV = specialMul(resultU, resultV, inverU, inverV, D, N)
		}
		index++
	}
	return resultU, resultV

}

func specialExp(a, b, D, N, exp *big.Int) (*big.Int, *big.Int) {
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

func PerformMPCMultiply(share1List, share2List, LagrangeCoefficient []*big.Int, D *big.Int) []*big.Int {
	// Generate all shares
	n := len(share1List)
	allShareList := make([][]*big.Int, n)
	for x := 0; x < n; x++ {
		allShareList[x] = make([]*big.Int, n)
	}

	for x := 0; x < n; x++ {
		for y := 0; y <= x; y++ {
			if x == y {
				if allShareList[x][x] == nil {
					allShareList[x][x] = new(big.Int).Mul(share1List[x], share2List[x])
					allShareList[x][x].Mod(allShareList[x][x], D)
				}

				continue
			}
			// x -> y
			shareX := generateAllMulShares(share1List[x], share2List[y], D)
			ownShare := new(big.Int).Mul(shareX[0], LagrangeCoefficient[0])
			ownShare.Mod(ownShare, D)
			otherShare := new(big.Int).Mul(shareX[1], LagrangeCoefficient[1])
			otherShare.Add(otherShare, new(big.Int).Mul(shareX[2], LagrangeCoefficient[2]))
			otherShare.Mod(otherShare, D)

			// y -> x
			shareY := generateAllMulShares(share1List[y], share2List[x], D)
			ownShareY := new(big.Int).Mul(shareY[0], LagrangeCoefficient[0])
			ownShareY.Mod(ownShareY, D)
			otherShareY := new(big.Int).Mul(shareY[1], LagrangeCoefficient[1])
			otherShareY.Add(otherShareY, new(big.Int).Mul(shareY[2], LagrangeCoefficient[2]))
			otherShareY.Mod(otherShareY, D)

			allShareList[x][y] = new(big.Int).Add(ownShare, otherShareY)
			allShareList[x][y].Mod(allShareList[x][y], D)
			allShareList[y][x] = new(big.Int).Add(otherShare, ownShareY)
			allShareList[y][x].Mod(allShareList[y][x], D)
		}
	}
	result := make([]*big.Int, n)
	// sum own shares
	for z := 0; z < n; z++ {
		temp := big.NewInt(0)
		for y := 0; y < n; y++ {
			temp.Add(temp, allShareList[z][y])
		}
		result[z] = temp
		result[z].Mod(result[z], D)
	}
	return result
}

func generateAllMulShares(a, b, Mod *big.Int) []*big.Int {
	product := new(big.Int).Mul(a, b)
	product.Mod(product, Mod)
	degree := 1
	p, _ := polynomial.RandomPolynomial(Mod, uint32(degree))
	p.SetConstant(product)
	upBd := degree << 1
	shares := make([]*big.Int, upBd+1)
	for i := 1; i <= len(shares); i++ {
		shares[i-1] = p.Evaluate(big.NewInt(int64(i)))
	}
	return shares
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

func (m *BiPrimeManage) generateD(bitLength int, N *big.Int) *big.Int {
	dShares, _ := rand.Prime(rand.Reader, bitLength)
	return dShares
}

// lowBitLength -> 2N, upBitLength -> 4N
func generateRamdonP(bitLength, pmod4 int, D *big.Int, p, N *big.Int) (*big.Int, error) {
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

	// D, err := rand.Prime(rand.Reader, bitLength)
	// if err != nil {
	// 	return nil, nil, 0, err
	// }

	// D, err := utils.RandomCoprimeInt(N)
	// if err != nil {
	// 	return nil, nil, 0, err
	// }
	// sSquarep := big.NewInt(0)
	// for i := 0; i < len(sSquarepList); i++ {
	// 	sSquarep.Add(sSquarep, sSquarepList[i])
	// }
	// sSquarep.Mod(sSquarep, D)
	sign := -1
	if pmod4 == 3 && new(big.Int).Mod(D, big4).Cmp(big1) == 0 {
		sign = 1
	}

	if big.Jacobi(p, D) == sign {
		P, err := utils.RandomInt(N)
		if err != nil {
			return nil, err
		}
		Q := new(big.Int).Exp(P, big2, N)
		Q = Q.Sub(Q, D)
		if utils.Gcd(Q, N).Cmp(big1) == 0 {
			return P, nil
		}
	}
	return nil, ErrExceedMaxRetry
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
	u, v := big.NewInt(1), big.NewInt(0)
	if exp.Sign() > 0 {
		u, v = specialInverse(P, big.NewInt(-1), D, m.N)
		u, v = specialMul(P, big1, u, v, D, m.N)
	} else {
		u, v = specialInverse(P, big1, D, m.N)
		u, v = specialMul(P, big.NewInt(-1), u, v, D, m.N)
	}

	u, v = Exp(u, v, D, m.N, exp.Abs(exp))

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

func MPCMulShamir(pList, qList, LagrangeCoefficient []*big.Int, Mod *big.Int) []*big.Int {
	n := len(pList)
	degree := uint32(n - 1)
	allShares := make([]*big.Int, len(LagrangeCoefficient))
	polyP := make([]*polynomial.Polynomial, n)
	polyQ := make([]*polynomial.Polynomial, n)
	for i := 0; i < n; i++ {
		temp, _ := polynomial.RandomPolynomial(Mod, degree)
		temp.SetConstant(pList[i])
		polyP[i] = temp

		temp, _ = polynomial.RandomPolynomial(Mod, degree)
		temp.SetConstant(qList[i])
		polyQ[i] = temp
	}

	// Evaluate: each person random two polynomial
	for i := 0; i < len(allShares); i++ {
		tempSumP := big.NewInt(0)
		tempSumQ := big.NewInt(0)
		for j := 0; j < len(polyP); j++ {
			temp := polyP[j].Evaluate(big.NewInt(int64(i) + 1))
			tempSumP.Add(tempSumP, temp)

			temp = polyQ[j].Evaluate(big.NewInt(int64(i) + 1))
			tempSumQ.Add(tempSumQ, temp)
		}
		tempSumP.Mod(tempSumP, Mod)

		tempSumQ.Mod(tempSumQ, Mod)
		allShares[i] = new(big.Int).Mul(tempSumP, tempSumQ)
		allShares[i].Mod(allShares[i], Mod)
	}
	// fmt.Println("allShares:", allShares)

	// // TEst
	// test := big.NewInt(0)
	// for i:=0; i < 5; i++ {
	// 	test.Add(test, new(big.Int).Mul(allShares[i], LagrangeCoefficient[i]))

	// }
	// fmt.Println("test:", test.Mod(test, Mod))

	result := make([]*big.Int, n)
	upBd := n-1

	// Each participants has two shares; P_n has one share.
	for i := 0; i < upBd; i++ {
		index := 2 * i

		tempSum := new(big.Int).Mul(allShares[index], LagrangeCoefficient[index])
		tempSum.Mod(tempSum, Mod)
		tempSum.Add(tempSum, new(big.Int).Mul(allShares[index+1], LagrangeCoefficient[index+1]))
		tempSum.Mod(tempSum, Mod)
		result[i] = tempSum

	}
	result[upBd] = new(big.Int).Mul(allShares[len(allShares)-1], LagrangeCoefficient[len(allShares)-1])
	result[upBd].Mod(result[upBd], Mod)
	return result
}
