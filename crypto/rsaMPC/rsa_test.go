// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package mpcrsa

import (
	"fmt"
	"math/big"
	mathRandom "math/rand"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"

	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util test", func() {
	It("zero rank", func() {
		var p, q, N *big.Int
		numberOfPrime := 131
		n := 2
		// Chinese Recover (Now use extend)
		bjxj, product := chineseRecover(numberOfPrime)
		partyList := make([]*BiPrimeManage, n)
		tryTime := 50

		timeList := make([]string, tryTime)
		leakCountList := make([]int, tryTime)

		for m := 0; m < tryTime; m++ {
			start := time.Now()

			// Initial all parties
			for i := 0; i < n; i++ {
				partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
			}
			for j := 0; j < 10000; j++ {
				for i := 0; i < 4000; i++ {
					for l := 0; l < numberOfPrime; l++ {
						pi := partyList[0].pij[l]
						qi := partyList[0].qij[l]

						for z := 1; z < n; z++ {
							pi += partyList[z].pij[l]
							qi += partyList[z].qij[l]
						}

						Ni := (pi * qi) % primeList[l]
						if Ni != 0 {
							for z := 0; z < n; z++ {
								partyList[z].Nj[l] = Ni
							}

						} else {
							for z := 0; z < 1000; z++ {
								// Refresh divide part
								Refreshpij := make([]int64, n)
								Refreshqij := make([]int64, n)

								pi = 0
								qi = 0
								for z := 0; z < n; z++ {
									Refreshpij[z] = mathRandom.Int63n(primeList[l])
									Refreshqij[z] = mathRandom.Int63n(primeList[l])
									pi += Refreshpij[z]
									qi += Refreshqij[z]
								}
								Ni = (pi * qi) % primeList[l]
								if Ni != 0 {
									// Set New state
									for z := 0; z < n; z++ {
										partyList[z].Nj[l] = Ni
										partyList[z].pij[l] = Refreshpij[z]
										partyList[z].qij[l] = Refreshqij[z]
									}
									break
								}
							}
						}
					}
					partyPi := make([]*big.Int, n)
					partyQi := make([]*big.Int, n)

					for z := 0; z < n; z++ {
						partyPi[z] = big.NewInt(0)
						partyQi[z] = big.NewInt(0)
						for l := 0; l < numberOfPrime; l++ {
							pi := big.NewInt(partyList[z].pij[l])
							temp := new(big.Int).Mul(bjxj[l], pi)
							partyPi[z].Add(partyPi[z], temp)
							partyPi[z].Mod(partyPi[z], product)

							qi := big.NewInt(partyList[z].qij[l])
							temp = new(big.Int).Mul(bjxj[l], qi)
							partyQi[z].Add(partyQi[z], temp)
							partyQi[z].Mod(partyQi[z], product)
						}
					}

					p = big.NewInt(0)
					q = big.NewInt(0)
					for z := 0; z < n; z++ {
						p.Add(p, partyPi[z])
						q.Add(q, partyQi[z])
					}
					N = new(big.Int).Mul(p, q)

					if !checkDivisible(N, numberOfPrime) {
						for z := 0; z < n; z++ {
							partyList[z].N = new(big.Int).Set(N)
							partyList[z].pi = partyPi[z]
							partyList[z].qi = partyQi[z]
						}
						break
					} else {
						// Reset
						for i := 0; i < n; i++ {
							partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
						}
					}
				}

				epsilonP := big.NewInt(1)
				epsilonQ := big.NewInt(1)
				if new(big.Int).Mod(p, big4).Cmp(big1) == 0 {
					epsilonP.Neg(epsilonP)
				}
				if new(big.Int).Mod(q, big4).Cmp(big1) == 0 {
					epsilonQ.Neg(epsilonQ)
				}
				epsilonN := new(big.Int).Mul(epsilonP, epsilonQ)

				for z := 0; z < n; z++ {
					partyList[z].epsilonP = epsilonP
					partyList[z].epsilonQ = epsilonQ
					partyList[z].epsilonN = epsilonN
				}

				//
				count := 0
				leakCount := 0
				bigLowerLength := 20
				uList := make([]*big.Int, n)
				vList := make([]*big.Int, n)
				for k := 0; k < 80; k++ {
					P, D, temp, err := generateRamdonDandP(bigLowerLength, int(epsilonP.Int64()), p, N)

					for z := 0; z < n; z++ {
						u, v := partyList[z].computeLucasMatrice(D, P)
						uList[z] = u
						vList[z] = v
					}

					for z := 0; z < n; z++ {
						err = partyList[z].CheckLucasCongruence(uList, vList, D)
						if err != nil {
							break
						}
					}
					if err != nil {
						//fmt.Println("Failure:", j)
						break
					} else {
						//fmt.Println("MaybeOK", k)
						leakCount += temp
						count++
						continue
					}
				}
				if count > 79 {
					end := time.Since(start).String()
					if p.ProbablyPrime(10) && q.ProbablyPrime(10) {
						timeList[m] = end
						leakCountList[m] = leakCount
					} else {
						timeList[m] = "failure"
						leakCountList[m] = leakCount
					}
					fmt.Println("Complete", m)
					break
				} else {
					// Reset
					for i := 0; i < n; i++ {
						partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
					}
				}
			}
		}

		fmt.Println("timeList:", timeList)
		fmt.Println("leakCountList:", leakCountList)

	})

	// FIt("Exp", func() {
	// 	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	// 	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	// 	N := new(big.Int).Mul(P, Q)

	// 	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)
	// 	//N, _ := new(big.Int).SetString("80293587092502923522935802385092385205820802385023958230509358092580923850285025802358023592582058320988092385092385029850285", 10)
	// 	//exp1 := big.NewInt(76)
	// 	exp2, _ := new(big.Int).SetString("59879787979799869868969686969", 10)
	// 	//u, v := specialExp(P, D, N, exp1)

	// 	u2, v2 := specialExp(big.NewInt(2), big.NewInt(1), D, N, exp2)

	// 	u3, v3 := ExpSquareCubic(big.NewInt(2), big.NewInt(1), D, N, exp2)

	// 	//u3, v3 := Exp(big.NewInt(2), big.NewInt(1), D, N, exp2)
	// 	//u3, v3 := Exp(big.NewInt(2), big.NewInt(1), D, N, exp2)
	// 	fmt.Println(u2.Cmp(u3) == 0, v2.Cmp(v3) == 0)

	// })
})

func BenchmarkPrintInt2String01(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	//u2, v2 := specialExp(big.NewInt(2), big.NewInt(1), D, N, exp2)
	for i := 0; i < b.N; i++ {
		Exp(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func BenchmarkExpSquareCubic(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	for i := 0; i < b.N; i++ {
		ExpSquareCubic(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func BenchmarkSpecialExp(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	for i := 0; i < b.N; i++ {
		specialExp(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func BenchmarkRSA(b *testing.B) {
	var p, q, N *big.Int
	numberOfPrime := 132
	n := 4
	// Chinese Recover (Now use extend)
	bjxj, product := chineseRecover(numberOfPrime)
	partyList := make([]*BiPrimeManage, n)

	// Initial all parties
	for i := 0; i < n; i++ {
		partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
	}

	for i := 0; i < b.N; i++ {
		for j := 0; j < 10000; j++ {
			for i := 0; i < 4000; i++ {
				for l := 0; l < numberOfPrime; l++ {
					pi := partyList[0].pij[l]
					qi := partyList[0].qij[l]

					for z := 1; z < n; z++ {
						pi += partyList[z].pij[l]
						qi += partyList[z].qij[l]
					}

					Ni := (pi * qi) % primeList[l]
					if Ni != 0 {
						for z := 0; z < n; z++ {
							partyList[z].Nj[l] = Ni
						}

					} else {
						for z := 0; z < 1000; z++ {
							// Refresh divide part
							Refreshpij := make([]int64, n)
							Refreshqij := make([]int64, n)

							pi = 0
							qi = 0
							for z := 0; z < n; z++ {
								Refreshpij[z] = mathRandom.Int63n(primeList[l])
								Refreshqij[z] = mathRandom.Int63n(primeList[l])
								pi += Refreshpij[z]
								qi += Refreshqij[z]
							}
							Ni = (pi * qi) % primeList[l]
							if Ni != 0 {
								// Set New state
								for z := 0; z < n; z++ {
									partyList[z].Nj[l] = Ni
									partyList[z].pij[l] = Refreshpij[z]
									partyList[z].qij[l] = Refreshqij[z]
								}
								break
							}
						}
					}
				}
				partyPi := make([]*big.Int, n)
				partyQi := make([]*big.Int, n)

				for z := 0; z < n; z++ {
					partyPi[z] = big.NewInt(0)
					partyQi[z] = big.NewInt(0)
					for l := 0; l < numberOfPrime; l++ {
						pi := big.NewInt(partyList[z].pij[l])
						temp := new(big.Int).Mul(bjxj[l], pi)
						partyPi[z].Add(partyPi[z], temp)
						partyPi[z].Mod(partyPi[z], product)

						qi := big.NewInt(partyList[z].qij[l])
						temp = new(big.Int).Mul(bjxj[l], qi)
						partyQi[z].Add(partyQi[z], temp)
						partyQi[z].Mod(partyQi[z], product)
					}
				}

				p = big.NewInt(0)
				q = big.NewInt(0)
				for z := 0; z < n; z++ {
					p.Add(p, partyPi[z])
					q.Add(q, partyQi[z])
				}
				N = new(big.Int).Mul(p, q)

				if !checkDivisible(N, numberOfPrime) {
					for z := 0; z < n; z++ {
						partyList[z].N = new(big.Int).Set(N)
						partyList[z].pi = partyPi[z]
						partyList[z].qi = partyQi[z]
					}
					break
				} else {
					// Reset
					for i := 0; i < n; i++ {
						partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
					}
				}
			}

			epsilonP := big.NewInt(1)
			epsilonQ := big.NewInt(1)
			if new(big.Int).Mod(p, big4).Cmp(big1) == 0 {
				epsilonP.Neg(epsilonP)
			}
			if new(big.Int).Mod(q, big4).Cmp(big1) == 0 {
				epsilonQ.Neg(epsilonQ)
			}
			epsilonN := new(big.Int).Mul(epsilonP, epsilonQ)

			for z := 0; z < n; z++ {
				partyList[z].epsilonP = epsilonP
				partyList[z].epsilonQ = epsilonQ
				partyList[z].epsilonN = epsilonN
			}

			//
			count := 0
			leakCount := 0
			bigLowerLength := 20
			uList := make([]*big.Int, n)
			vList := make([]*big.Int, n)
			for k := 0; k < 80; k++ {
				P, D, temp, err := generateRamdonDandP(bigLowerLength, int(epsilonP.Int64()), p, N)

				for z := 0; z < n; z++ {
					u, v := partyList[z].computeLucasMatrice(D, P)
					uList[z] = u
					vList[z] = v
				}

				for z := 0; z < n; z++ {
					err = partyList[z].CheckLucasCongruence(uList, vList, D)
					if err != nil {
						break
					}
				}
				if err != nil {
					break
				} else {
					leakCount += temp
					count++
					continue
				}
			}
			if count > 79 {
				break
			} else {
				// Reset
				for i := 0; i < n; i++ {
					partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
				}
			}
		}
	}
}

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MpcRsa Test")
}
